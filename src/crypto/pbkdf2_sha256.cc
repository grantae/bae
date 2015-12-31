#include "crypto/pbkdf2_sha256.h"
#include "util/make_unique.h"
#include "cryptopp/sha.h"
#include "cryptopp/pwdbased.h"

using namespace Crypto;
using Util::Blob;
using Util::MutableBlob;
using std::unique_ptr;
using Util::make_unique;

unique_ptr<Blob> Crypto::PBKDF2_SHA256(U64 _keySize, const Blob &_password,
  const Blob &_salt, U64 _iterations)
{
  MutableBlob mkey(_keySize, Blob::ScrubType::ZEROS, Blob::CompareType::CONST);
  CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
  pbkdf.DeriveKey(mkey.data(), mkey.size(), 0, _password.data(), _password.size(),
    _salt.data(), _salt.size(), _iterations);
  return make_unique<Blob>(mkey); // XXX make sure size is not zero
}

