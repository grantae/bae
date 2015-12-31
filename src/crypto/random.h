#ifndef CRYPTO_RANDOM_H
#define CRYPTO_RANDOM_H

#include "util/blob.h"
#include "util/fixed_types.h"
#include <memory>

namespace Crypto {

// Create a new Blob with crypto-strength random data of the specified size
std::unique_ptr<Util::Blob> random(U64 size);

// Fill an existing MutableBlob with crypto-strenght random data
void randomize(Util::MutableBlob &blob);

} // namespace Crypto

#endif // CRYPTO_RANDOM_H

