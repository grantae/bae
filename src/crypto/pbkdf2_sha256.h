#ifndef CRYPTO_PBKDF2_SHA256_H
#define CRYPTO_PBKDF2_SHA256_H

#include "util/blob.h"
#include <string>
#include <memory>

namespace Crypto {

typedef U32 PBKD_Iters;
static const PBKD_Iters PBKD_ITERS_DEFAULT = 100000;

std::unique_ptr<Util::Blob> PBKDF2_SHA256(U64 keySize, const Util::Blob &password,
  const Util::Blob &salt, U64 iterations);

// TODO: Futures

} // namespace Crypto

#endif // CRYPTO_PBKDF2_SHA256_H

