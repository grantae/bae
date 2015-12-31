#include "crypto/random.h"
#include "util/make_unique.h"
#include "cryptopp/osrng.h"

std::unique_ptr<Util::Blob> Crypto::random(U64 _size)
{
  Util::MutableBlob m(_size);
  CryptoPP::AutoSeededRandomPool prng;
  prng.GenerateBlock(m.data(), m.size());

  return Util::make_unique<Util::Blob>(m);
}

void Crypto::randomize(Util::MutableBlob &_blob)
{
  CryptoPP::AutoSeededRandomPool prng;
  prng.GenerateBlock(_blob.data(), _blob.size());
}
