#include "gtest/gtest.h"
#include "crypto/aes_gcm_pbkd.h"

using namespace Crypto;
using Util::Blob;
using std::unique_ptr;

static AES_GCM_PBKD_Config cfg;

static Blob pt("Plaintext", 9);
static Blob pw("password", 8);

TEST(AES_GCM_PBKD_Test, Sanity) {
  // Encryption is reversible
  cfg.keySize = AES_GCM_KEYSIZE::K256;
  cfg.tagSize = AES_GCM_TAGSIZE::T128;
  cfg.ivOutput = AES_GCM_IV_OUTPUT::CTXT_PREPEND_AAD;
  cfg.PBKDIters = 1234;

  AES_GCM_PBKD_Enc e(cfg);
  e.passwordIs(pw);
  e.plaintextIs(pt);
  unique_ptr<AES_GCM_Result> eres = e.ciphertext();
  EXPECT_EQ(eres->second, AES_GCM_STATUS::VALID);

  AES_GCM_PBKD_Dec d(cfg);
  d.passwordIs(pw);
  d.ciphertextIs(eres->first);
  AES_GCM_Result dres = d.plaintext();
  EXPECT_EQ(dres.second, AES_GCM_STATUS::VALID);
  EXPECT_EQ(dres.first, pt);

  // Key/IV are different for each encryption
  unique_ptr<AES_GCM_Result> eres2 = e.ciphertext();
  EXPECT_EQ(eres2->second, AES_GCM_STATUS::VALID);
  EXPECT_NE(eres2->first, eres->first);
}

