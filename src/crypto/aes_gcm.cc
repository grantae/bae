#include "crypto/aes_gcm.h"
#include "crypto/random.h"
#include "util/make_unique.h"

using namespace Crypto;
using Util::Blob;
using Util::MutableBlob;
using std::unique_ptr;
using Util::make_unique;

U32 Crypto::AES_GCM_Keysize(AES_GCM_KEYSIZE _keysize)
{
  switch (_keysize) {
    case AES_GCM_KEYSIZE::K128:
      return 16;
    case AES_GCM_KEYSIZE::K192:
      return 24;
    case AES_GCM_KEYSIZE::K256:
      return 32;
    default:
      return 0;
  }
}

U32 Crypto::AES_GCM_Tagsize(AES_GCM_TAGSIZE _tagsize)
{
  switch (_tagsize) {
    case AES_GCM_TAGSIZE::T64:
      return 8;
    case AES_GCM_TAGSIZE::T96:
      return 12;
    case AES_GCM_TAGSIZE::T128:
      return 16;
    default:
      return 0;
  }
}

AES_GCM_Enc::AES_GCM_Enc(AES_GCM_Config _config)
  : cfg_(_config), ivc_(AES_GCM_BLOCKSIZE_BYTES), key_(), aad_(), ptxt_(), prng_(), enc_()
{
  updateIV(true);
}

const AES_GCM_Config &AES_GCM_Enc::config() const
{
  return cfg_;
}

AES_GCM_STATUS AES_GCM_Enc::keyIs(const Blob &_key)
{
  if (_key.size() == AES_GCM_Keysize(cfg_.keySize)) {
    key_ = _key;
    return AES_GCM_STATUS::VALID;
  }
  else {
    // Fail to an unknown key
    unique_ptr<Blob> randKey(Crypto::random(AES_GCM_Keysize(cfg_.keySize)));
    key_ = *randKey;
    return AES_GCM_STATUS::INVALID_SIZE;
  }
}

AES_GCM_STATUS AES_GCM_Enc::ivcIs(const Blob &_ivc)
{
  // GCM allows IV bitlengths between 1 and 2^64.
  if (cfg_.ivMode != AES_GCM_IV_MODE::RANDOM) {
    ivc_ = _ivc;
    return AES_GCM_STATUS::VALID;
  }
  else {
    return AES_GCM_STATUS::INVALID_MODE;
  }
}

void AES_GCM_Enc::aadIs(const Blob &_aad)
{
  aad_ = _aad;
}

void AES_GCM_Enc::plaintextIs(const Blob &_plaintext)
{
  ptxt_ = _plaintext;
}

const Blob &AES_GCM_Enc::ivc() const
{
  return ivc_;
}

unique_ptr<AES_GCM_Result> AES_GCM_Enc::ciphertext()
{
  try {
    enc_.SetKeyWithIV(key_.data(), key_.size(), ivc_.data(), ivc_.size());
    bool include_ivc = (cfg_.ivOutput != AES_GCM_IV_OUTPUT::NO);
    bool ivc_aad = (cfg_.ivOutput == AES_GCM_IV_OUTPUT::CTXT_PREPEND_AAD);

    // Determine the full output size
    U64 aadSize = aad_.size();
    U64 ivcSize = ((include_ivc) ? ivc_.size() : 0U);
    U32 tagSize = AES_GCM_Tagsize(cfg_.tagSize);
    U64 ctxtSize = aadSize + ivcSize + ptxt_.size() + tagSize;

    // Allocate space for the ciphertext and create the encryption filter
    MutableBlob mctxt(ctxtSize);
    U64 filter_offset = aadSize + ivcSize;
    Byte *filter_start = mctxt.data() + filter_offset;
    CryptoPP::AuthenticatedEncryptionFilter encf(enc_,
      new CryptoPP::ArraySink(filter_start, mctxt.size() - filter_offset),
      false, (S32)tagSize);

    // Insert the authenticated associated data
    encf.ChannelPut("AAD", aad_.data(), aadSize);
    if (ivc_aad) {
      encf.ChannelPut("AAD", ivc_.data(), ivcSize);
    }
    encf.ChannelMessageEnd("AAD");

    // Insert the plaintext as authenticated encrypted data
    encf.ChannelPut("", ptxt_.data(), ptxt_.size());
    encf.ChannelMessageEnd("");

    // Prepend the authenticated associated data to the ciphertext
    memcpy((void *)mctxt.data(), (const void *)aad_.data(), aadSize);
    if (include_ivc) {
      memcpy((void *)(mctxt.data() + aadSize), (void *)ivc_.data(), ivcSize);
    }

    // Create a new IV/Counter if not in manual mode
    updateIV(false);

    return make_unique<AES_GCM_Result>(mctxt, AES_GCM_STATUS::VALID);
  }
  catch (std::exception const &e) {
    return make_unique<AES_GCM_Result>(Blob(), AES_GCM_STATUS::ENC_ERROR);
  }
}

void AES_GCM_Enc::updateIV(bool _initialize)
{
  Byte *ivcNew = ivc_.data();

  if (cfg_.ivMode == AES_GCM_IV_MODE::RANDOM) {
    prng_.GenerateBlock(ivcNew, ivc_.size());
  }
  else if (cfg_.ivMode == AES_GCM_IV_MODE::COUNTER) {
    // Initialize at zero
    if (_initialize) {
      if (ivc_.size() != AES_GCM_BLOCKSIZE_BYTES) {
        ivc_ = MutableBlob(AES_GCM_BLOCKSIZE_BYTES);
        ivcNew = ivc_.data();
      }
      for (U64 i = 0; i < ivc_.size(); i++) {
        ivcNew[i] = 0x00;
      }
    }
    // Otherwise increment by one
    else {
      if (ivcNew[3] == 0xff) {
        if (ivcNew[2] == 0xff) {
          if (ivcNew[1] == 0xff) {
            ivcNew[0] += 1;
          }
          ivcNew[1] += 1;
        }
        ivcNew[2] += 1;
      }
      ivcNew[3] += 1;
    }
  }
}

/*** DECRYPTION ***/

AES_GCM_Dec::AES_GCM_Dec()
  : ctxt_(), iv_(), tag_(), aad_(), key_(), ptxt_(Blob(), AES_GCM_STATUS::DEC_ERROR),
  dec_(), needsDecrypt_(false), mutableMux_()
{
  // empty
}

void AES_GCM_Dec::ciphertextIs(const Blob &_ciphertext)
{
  if (ctxt_ != _ciphertext) {
    ctxt_ = _ciphertext;
    needsDecrypt_ = true;
  }
}

void AES_GCM_Dec::ivIs(const Blob &_iv)
{
  if (iv_ != _iv) {
    iv_ = _iv;
    needsDecrypt_ = true;
  }
}

void AES_GCM_Dec::tagIs(const Blob &_tag)
{
  if (tag_ != _tag) {
    tag_ = _tag;
    needsDecrypt_ = true;
  }
}

void AES_GCM_Dec::aadIs(const Blob &_aad)
{
  if (aad_ != _aad) {
    aad_ = _aad;
    needsDecrypt_ = true;
  }
}

AES_GCM_STATUS AES_GCM_Dec::keyIs(const Blob &_key)
{
  AES_GCM_STATUS status = AES_GCM_STATUS::VALID;

  U64 size = _key.size();
  if ((size != AES_GCM_KEYSIZE_256) && (size != AES_GCM_KEYSIZE_128) &&
    (size != AES_GCM_KEYSIZE_192)) {
    status = AES_GCM_STATUS::INVALID_SIZE;
  }
  else {
    key_ = _key;
    needsDecrypt_ = true;
  }
  return status;
}

const std::pair<Blob, AES_GCM_STATUS> &AES_GCM_Dec::plaintext() const
{
  mutableMux_.lock();
  if (needsDecrypt_ == true) {
    decrypt();
  }
  mutableMux_.unlock();
  return ptxt_;
}

void AES_GCM_Dec::decrypt() const
{
  if ((iv_.size() == 0) || (tag_.size() == 0) || (key_.size() == 0)) {
    ptxt_.second = AES_GCM_STATUS::INVALID_SIZE;
  }
  else {
    try {
      MutableBlob ptxt(ctxt_.size(), Blob::ScrubType::ZEROS);
      dec_.SetKeyWithIV(key_.data(), key_.size(), iv_.data(), iv_.size());
      CryptoPP::AuthenticatedDecryptionFilter decf(
        dec_,
        new CryptoPP::ArraySink(ptxt.data(), ptxt.size()),
        CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
        CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
        tag_.size());
      decf.ChannelPut("", tag_.data(), tag_.size());
      decf.ChannelPut("AAD", iv_.data(), iv_.size());
      decf.ChannelPut("", ctxt_.data(), ctxt_.size());
      decf.ChannelMessageEnd("AAD");
      decf.ChannelMessageEnd("");

      // Final verification
      if (decf.GetLastResult() == false) {
        ptxt_.first.dataIsNull();// = Blob();
        ptxt_.second = AES_GCM_STATUS::DEC_ERROR;
      }
      else {
        ptxt_.first = ptxt;
        ptxt_.second = AES_GCM_STATUS::VALID;
        needsDecrypt_ = false;
      }
    }
    catch (std::exception const &e) {
      //printf("Bad decrypt: %s\n", e.what());
      ptxt_.first.dataIsNull();
      ptxt_.second = AES_GCM_STATUS::DEC_ERROR;
    }
  }
}

