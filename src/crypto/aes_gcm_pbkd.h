#ifndef CRYPTO_AES_GCM_PBKD_H
#define CRYPTO_AES_GCM_PBKD_H

#include "crypto/pbkdf2_sha256.h"
#include "crypto/aes_gcm.h"
#include "util/blob.h"
#include "util/fixed_types.h"
#include <mutex>
#include <memory>

namespace Crypto {

struct AES_GCM_PBKD_Config
{
  AES_GCM_PBKD_Config();

  AES_GCM_KEYSIZE   keySize;      // 128, 192, 256
  AES_GCM_TAGSIZE   tagSize;      // 64, 96, 128
  AES_GCM_IV_OUTPUT ivOutput;     // no, prepend, prepend+aad
  PBKD_Iters        PBKDIters;
};

class AES_GCM_PBKD_Enc
{
 public:
  AES_GCM_PBKD_Enc(const AES_GCM_PBKD_Config config);
  AES_GCM_PBKD_Enc(const AES_GCM_PBKD_Enc &) = delete;
  AES_GCM_PBKD_Enc &operator=(const AES_GCM_PBKD_Enc &) = delete;
  AES_GCM_PBKD_Enc &operator=(AES_GCM_PBKD_Enc &&) = default;
  const AES_GCM_PBKD_Config &config() const;
  void passwordIs(const Util::Blob &password);
  void plaintextIs(const Util::Blob &plaintext);
  std::unique_ptr<AES_GCM_Result> ciphertext();

 private:
  AES_GCM_PBKD_Config cfg_;
  Util::Blob password_;
  AES_GCM_Enc enc_;
};

class AES_GCM_PBKD_Dec
{
 public:
  AES_GCM_PBKD_Dec(const AES_GCM_PBKD_Config config);
  AES_GCM_PBKD_Dec(const AES_GCM_PBKD_Dec &) = delete;
  AES_GCM_PBKD_Dec &operator=(const AES_GCM_PBKD_Dec &) = delete;
  AES_GCM_PBKD_Dec &operator=(AES_GCM_PBKD_Dec &&) = default;
  void passwordIs(const Util::Blob &password);
  void ciphertextIs(const Util::Blob &ciphertext);
  const AES_GCM_Result &plaintext() const;

 private:
  void decrypt();
  AES_GCM_PBKD_Config cfg_;
  Util::Blob password_;
  std::unique_ptr<Util::Blob> key_;
  Util::Blob ciphertext_;
  AES_GCM_Result plaintext_;
  AES_GCM_Dec dec_;
  bool havePassword_;
  bool haveCiphertext_;
};

} // namespace Crypto

#endif // CRYPTO_AES_GCM_PBKD_H

