#include "aes_gcm_pbkd.h"
using namespace Crypto;
using Util::Blob;
using Util::MutableBlob;
using std::unique_ptr;

AES_GCM_PBKD_Config::AES_GCM_PBKD_Config()
  : keySize(AES_GCM_KEYSIZE_DEFAULT), tagSize(AES_GCM_TAGSIZE_DEFAULT),
  ivOutput(AES_GCM_IV_OUTPUT::CTXT_PREPEND_AAD), PBKDIters(PBKD_ITERS_DEFAULT)
{
  // empty
}

AES_GCM_PBKD_Enc::AES_GCM_PBKD_Enc(const AES_GCM_PBKD_Config _cfg)
  : cfg_(_cfg), password_(), enc_(
  AES_GCM_Config{_cfg.keySize, _cfg.tagSize, AES_GCM_IV_MODE::RANDOM, _cfg.ivOutput})
{
  // empty
}

const AES_GCM_PBKD_Config &AES_GCM_PBKD_Enc::config() const
{
  return cfg_;
}

void AES_GCM_PBKD_Enc::passwordIs(const Blob &_password)
{
  password_ = _password;
}

void AES_GCM_PBKD_Enc::plaintextIs(const Blob &_plaintext)
{
  enc_.plaintextIs(_plaintext);
}


unique_ptr<AES_GCM_Result> AES_GCM_PBKD_Enc::ciphertext()
{
  // The random IV mode ensures that the key is never reused with the
  // same IV. The IV is also used as the the PBKDF2 salt for key derivation.
  // The advantage of combining the salt and IV is that the message can
  // be smaller and is stateless, requiring no additional data on either end.
  // The disadvantage is that decryption always requires PBKDF2 first which is
  // expensive. In a future configuration the salt could be persistent on the
  // encryption and decryption sides and passed (if needed) with the message.


  unique_ptr<Blob> key = PBKDF2_SHA256(AES_GCM_Keysize(cfg_.keySize), password_,
    enc_.ivc(), cfg_.PBKDIters);

  unique_ptr<AES_GCM_Result> result(new AES_GCM_Result());
  result->second = enc_.keyIs(*key);
  if (result->second != AES_GCM_STATUS::VALID) {
    return result;
  }
  return enc_.ciphertext();
}


// Decryption

AES_GCM_PBKD_Dec::AES_GCM_PBKD_Dec(const AES_GCM_PBKD_Config _config)
  : cfg_(_config), password_(), key_(), ciphertext_(), plaintext_(), dec_(),
  havePassword_(false), haveCiphertext_(false)
{
  // empty
}

void AES_GCM_PBKD_Dec::passwordIs(const Blob &_password)
{
  if (password_.compare(_password, Blob::CompareType::CONST) ==
      Blob::Comparison::NE) {
    password_ = _password;
    havePassword_ = true;
    if (haveCiphertext_) {
      decrypt();
    }
  }
}

void AES_GCM_PBKD_Dec::ciphertextIs(const Blob &_ciphertext)
{
  if (ciphertext_ != _ciphertext) {
    ciphertext_ = _ciphertext;
    haveCiphertext_ = true;
    if (havePassword_) {
      decrypt();
    }
  }
}

const AES_GCM_Result &AES_GCM_PBKD_Dec::plaintext() const
{
  return plaintext_;
}


void AES_GCM_PBKD_Dec::decrypt()
{
  // Sizes of components (under/overflow okay)
  U32 ivSize = AES_GCM_BLOCKSIZE_BYTES;
  U32 tagSize = AES_GCM_Tagsize(cfg_.tagSize);
  U64 ctxtSize = ciphertext_.size() - ivSize - tagSize;

  // Actual components (auto-truncated)
  Blob iv(ciphertext_, ivSize, 0);
  Blob ctxt(ciphertext_, ctxtSize, ivSize);
  Blob tag(ciphertext_, tagSize, ivSize + ctxtSize);

  // Recover the key
  key_ = PBKDF2_SHA256(AES_GCM_Keysize(cfg_.keySize), password_, iv, cfg_.PBKDIters);

  // Decrypt
  dec_.ciphertextIs(ctxt);
  dec_.ivIs(iv);
  dec_.tagIs(tag);
  dec_.aadIs(iv);
  dec_.keyIs(*key_);
  plaintext_ = dec_.plaintext();
}

