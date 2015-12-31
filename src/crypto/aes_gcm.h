#ifndef CRYPTO_AES_GCM_H
#define CRYPTO_AES_GCM_H

#include "util/blob.h"
#include "cryptopp/osrng.h"
#include "cryptopp/aes.h"
#include "cryptopp/gcm.h"
#include "util/fixed_types.h"
#include <mutex>
#include <utility>

namespace Crypto {

static const U32 AES_GCM_BLOCKSIZE_BYTES = 16;
static const U32 AES_GCM_KEYSIZE_128 = 16;
static const U32 AES_GCM_KEYSIZE_192 = 24;
static const U32 AES_GCM_KEYSIZE_256 = 32;

// Key sizes for AES
enum class AES_GCM_KEYSIZE
{
  K128, K192, K256
};

static const AES_GCM_KEYSIZE AES_GCM_KEYSIZE_DEFAULT = AES_GCM_KEYSIZE::K256;
U32 AES_GCM_Keysize(AES_GCM_KEYSIZE keysize);


// Tag sizes for AES/GCM
enum class AES_GCM_TAGSIZE
{
  T64, T96, T128
};

static const AES_GCM_TAGSIZE AES_GCM_TAGSIZE_DEFAULT = AES_GCM_TAGSIZE::T128;
U32 AES_GCM_Tagsize(AES_GCM_TAGSIZE tagsize);


// The IV can be handled automatically or manually
enum class AES_GCM_IV_MODE
{
  RANDOM, COUNTER, MANUAL
};

static const AES_GCM_IV_MODE AES_GCM_IV_MODE_DEFAULT = AES_GCM_IV_MODE::RANDOM;


// The IV can be prepended as Additional Authenticated Data (AAD), prepended,
// or not included in the ciphertext (retrieve using AES_GCM_Enc::ivc() prior
// to encryption).
enum class AES_GCM_IV_OUTPUT
{
  NO, CTXT_PREPEND, CTXT_PREPEND_AAD
};

static const AES_GCM_IV_OUTPUT AES_GCM_IV_OUTPUT_DEFAULT = AES_GCM_IV_OUTPUT::CTXT_PREPEND_AAD;

// A collection of configuration options for the encryptor
struct AES_GCM_Config
{
  AES_GCM_KEYSIZE     keySize;
  AES_GCM_TAGSIZE     tagSize;
  AES_GCM_IV_MODE     ivMode;
  AES_GCM_IV_OUTPUT   ivOutput;
};

enum class AES_GCM_STATUS
{
  VALID, INVALID_SIZE, INVALID_MODE, ENC_ERROR, DEC_ERROR
};

typedef std::pair<Util::Blob, AES_GCM_STATUS> AES_GCM_Result;

class AES_GCM_Enc
{
 public:
  AES_GCM_Enc(const AES_GCM_Config config);
  AES_GCM_Enc(const AES_GCM_Enc &) = delete;
  AES_GCM_Enc &operator=(const AES_GCM_Enc &) = delete;
  AES_GCM_Enc &operator=(AES_GCM_Enc &&) = default;
  const AES_GCM_Config &config() const;
  AES_GCM_STATUS keyIs(const Util::Blob &key);
  AES_GCM_STATUS ivcIs(const Util::Blob &ivc);
  void aadIs(const Util::Blob &aad);
  void plaintextIs(const Util::Blob &plaintext);
  const Util::Blob &ivc() const;
  std::unique_ptr<AES_GCM_Result> ciphertext();

 private:
  void updateIV(bool initialize);
  AES_GCM_Config cfg_;
  Util::MutableBlob ivc_;
  Util::Blob key_;
  Util::Blob aad_;
  Util::Blob ptxt_;
  CryptoPP::AutoSeededRandomPool prng_;
  CryptoPP::GCM<CryptoPP::AES>::Encryption enc_;
};

class AES_GCM_Dec
{
 public:
  AES_GCM_Dec();
  AES_GCM_Dec(const AES_GCM_Dec &) = delete;
  AES_GCM_Dec &operator=(const AES_GCM_Dec &) = delete;
  AES_GCM_Dec &operator=(AES_GCM_Dec &&) = default;
  void ciphertextIs(const Util::Blob &ciphertext);
  void ivIs(const Util::Blob &iv);
  void tagIs(const Util::Blob &tag);
  void aadIs(const Util::Blob &aad);
  AES_GCM_STATUS keyIs(const Util::Blob &key);
  const AES_GCM_Result &plaintext() const;

 private:
  void decrypt() const;
  Util::Blob ctxt_;
  Util::Blob iv_;
  Util::Blob tag_;
  Util::Blob aad_;
  Util::Blob key_;
  mutable AES_GCM_Result ptxt_;
  mutable CryptoPP::GCM<CryptoPP::AES>::Decryption dec_;
  mutable bool needsDecrypt_;
  mutable std::mutex mutableMux_;
};

} // namespace Crypto

#endif // CRYPTO_AES_GCM_H

