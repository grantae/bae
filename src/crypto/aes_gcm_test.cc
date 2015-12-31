#include "gtest/gtest.h"
#include "crypto/aes_gcm.h"

using namespace Crypto;
using Util::Blob;
using Util::MutableBlob;
using std::unique_ptr;


// The following 18 test vectors are from McGrew and Viega's paper,
// "The Galois/Counter Mode of Operation (GCM)"


// Keys
static const Blob kz32("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 32);
static const Blob kz24(kz32, 24, 0);
static const Blob kz16(kz32, 16, 0);
static const Blob kr32("\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"
                       "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08", 32);
static const Blob kr24(kr32, 24, 0);
static const Blob kr16(kr32, 16, 0);

// Plaintexts
static const Blob pr64("\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
                       "\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
                       "\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
                       "\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf\xd2\x55", 64);
static const Blob pr60(pr64, 60, 0);
static const Blob pz16(kz16);

// IVs
static const Blob iz12("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12);
static const Blob ir60("\x93\x13\x22\x5d\xf8\x84\x06\xe5\x55\x90\x9c\x5a\xff\x52\x69\xaa"
                       "\x6a\x7a\x95\x38\x53\x4f\x7d\xa1\xe4\xc3\x03\xd2\xa3\x18\xa7\x28"
                       "\xc3\xc0\xc9\x51\x56\x80\x95\x39\xfc\xf0\xe2\x42\x9a\x6b\x52\x54"
                       "\x16\xae\xdb\xf5\xa0\xde\x6a\x57\xa6\x37\xb3\x9b", 60);
static const Blob ir12("\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88", 12);
static const Blob ir8(ir12, 8, 0);

// Additional Authenticated Data
static const Blob ar20("\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef"
                       "\xab\xad\xda\xd2", 20);

// Encryptor
static AES_GCM_Config cfg = {AES_GCM_KEYSIZE::K128, AES_GCM_TAGSIZE::T128,
  AES_GCM_IV_MODE::MANUAL, AES_GCM_IV_OUTPUT::NO};


TEST(AES_GCMTest, Vector1) {
  Blob t("\x58\xe2\xfc\xce\xfa\x7e\x30\x61\x36\x7f\x1d\x57\xa4\xe7\x45\x5a", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kz16);
  e.ivcIs(iz12);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  EXPECT_TRUE(pkg == t);
}

TEST(AES_GCMTest, Vector2) {
  Blob c("\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78", 16);
  Blob t("\xab\x6e\x47\xd4\x2c\xec\x13\xbd\xf5\x3a\x67\xb2\x12\x57\xbd\xdf", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kz16);
  e.ivcIs(iz12);
  e.plaintextIs(pz16);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob ctxt(pkg, 16, 0);
  Blob tag(pkg, 16, 16);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

TEST(AES_GCMTest, Vector3) {
  Blob c("\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c"
         "\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e"
         "\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05"
         "\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91\x47\x3f\x59\x85", 64);
  Blob t("\x4d\x5c\x2a\xf3\x27\xcd\x64\xa6\x2c\xf3\x5a\xbd\x2b\xa6\xfa\xb4", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kr16);
  e.ivcIs(ir12);
  e.plaintextIs(pr64);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob ctxt(pkg, 64, 0);
  Blob tag(pkg, 16, 64);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

TEST(AES_GCMTest, Vector4) {
  Blob c("\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c"
         "\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e"
         "\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05"
         "\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91", 60);
  Blob t("\x5b\xc9\x4f\xbc\x32\x21\xa5\xdb\x94\xfa\xe9\x5a\xe7\x12\x1a\x47", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kr16);
  e.ivcIs(ir12);
  e.aadIs(ar20);
  e.plaintextIs(pr60);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob aad(pkg, 20, 0);
  Blob ctxt(pkg, 60, 20);
  Blob tag(pkg, 16, 80);
  EXPECT_TRUE(aad == ar20);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

TEST(AES_GCMTest, Vector5) {
  Blob c("\x61\x35\x3b\x4c\x28\x06\x93\x4a\x77\x7f\xf5\x1f\xa2\x2a\x47\x55"
         "\x69\x9b\x2a\x71\x4f\xcd\xc6\xf8\x37\x66\xe5\xf9\x7b\x6c\x74\x23"
         "\x73\x80\x69\x00\xe4\x9f\x24\xb2\x2b\x09\x75\x44\xd4\x89\x6b\x42"
         "\x49\x89\xb5\xe1\xeb\xac\x0f\x07\xc2\x3f\x45\x98", 60);
  Blob t("\x36\x12\xd2\xe7\x9e\x3b\x07\x85\x56\x1b\xe1\x4a\xac\xa2\xfc\xcb", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kr16);
  e.ivcIs(ir8);
  e.aadIs(ar20);
  e.plaintextIs(pr60);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob aad(pkg, 20, 0);
  Blob ctxt(pkg, 60, 20);
  Blob tag(pkg, 16, 80);
  EXPECT_TRUE(aad == ar20);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

TEST(AES_GCMTest, Vector6) {
  Blob c("\x8c\xe2\x49\x98\x62\x56\x15\xb6\x03\xa0\x33\xac\xa1\x3f\xb8\x94"
         "\xbe\x91\x12\xa5\xc3\xa2\x11\xa8\xba\x26\x2a\x3c\xca\x7e\x2c\xa7"
         "\x01\xe4\xa9\xa4\xfb\xa4\x3c\x90\xcc\xdc\xb2\x81\xd4\x8c\x7c\x6f"
         "\xd6\x28\x75\xd2\xac\xa4\x17\x03\x4c\x34\xae\xe5", 60);
  Blob t("\x61\x9c\xc5\xae\xff\xfe\x0b\xfa\x46\x2a\xf4\x3c\x16\x99\xd0\x50", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kr16);
  e.ivcIs(ir60);
  e.aadIs(ar20);
  e.plaintextIs(pr60);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob aad(pkg, 20, 0);
  Blob ctxt(pkg, 60, 20);
  Blob tag(pkg, 16, 80);
  EXPECT_TRUE(aad == ar20);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

TEST(AES_GCMTest, Vector7) {
  Blob t("\xcd\x33\xb2\x8a\xc7\x73\xf7\x4b\xa0\x0e\xd1\xf3\x12\x57\x24\x35", 16);

  cfg.keySize = AES_GCM_KEYSIZE::K192;
  AES_GCM_Enc e(cfg);
  e.aadIs(Blob());
  e.keyIs(kz24);
  e.ivcIs(iz12);
  e.plaintextIs(Blob());
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  EXPECT_TRUE(pkg == t);
}

TEST(AES_GCMTest, Vector8) {
  Blob c("\x98\xe7\x24\x7c\x07\xf0\xfe\x41\x1c\x26\x7e\x43\x84\xb0\xf6\x00", 16);
  Blob t("\x2f\xf5\x8d\x80\x03\x39\x27\xab\x8e\xf4\xd4\x58\x75\x14\xf0\xfb", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kz24);
  e.ivcIs(iz12);
  e.plaintextIs(pz16);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob ctxt(pkg, 16, 0);
  Blob tag(pkg, 16, 16);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

TEST(AES_GCMTest, Vector9) {
  Blob c("\x39\x80\xca\x0b\x3c\x00\xe8\x41\xeb\x06\xfa\xc4\x87\x2a\x27\x57"
         "\x85\x9e\x1c\xea\xa6\xef\xd9\x84\x62\x85\x93\xb4\x0c\xa1\xe1\x9c"
         "\x7d\x77\x3d\x00\xc1\x44\xc5\x25\xac\x61\x9d\x18\xc8\x4a\x3f\x47"
         "\x18\xe2\x44\x8b\x2f\xe3\x24\xd9\xcc\xda\x27\x10\xac\xad\xe2\x56", 64);
  Blob t("\x99\x24\xa7\xc8\x58\x73\x36\xbf\xb1\x18\x02\x4d\xb8\x67\x4a\x14", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kr24);
  e.ivcIs(ir12);
  e.plaintextIs(pr64);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob ctxt(pkg, 64, 0);
  Blob tag(pkg, 16, 64);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

TEST(AES_GCMTest, Vector10) {
  Blob c("\x39\x80\xca\x0b\x3c\x00\xe8\x41\xeb\x06\xfa\xc4\x87\x2a\x27\x57"
         "\x85\x9e\x1c\xea\xa6\xef\xd9\x84\x62\x85\x93\xb4\x0c\xa1\xe1\x9c"
         "\x7d\x77\x3d\x00\xc1\x44\xc5\x25\xac\x61\x9d\x18\xc8\x4a\x3f\x47"
         "\x18\xe2\x44\x8b\x2f\xe3\x24\xd9\xcc\xda\x27\x10", 60);
  Blob t("\x25\x19\x49\x8e\x80\xf1\x47\x8f\x37\xba\x55\xbd\x6d\x27\x61\x8c", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kr24);
  e.ivcIs(ir12);
  e.aadIs(ar20);
  e.plaintextIs(pr60);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob aad(pkg, 20, 0);
  Blob ctxt(pkg, 60, 20);
  Blob tag(pkg, 16, 80);
  EXPECT_TRUE(aad == ar20);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

TEST(AES_GCMTest, Vector11) {
  Blob c("\x0f\x10\xf5\x99\xae\x14\xa1\x54\xed\x24\xb3\x6e\x25\x32\x4d\xb8"
         "\xc5\x66\x63\x2e\xf2\xbb\xb3\x4f\x83\x47\x28\x0f\xc4\x50\x70\x57"
         "\xfd\xdc\x29\xdf\x9a\x47\x1f\x75\xc6\x65\x41\xd4\xd4\xda\xd1\xc9"
         "\xe9\x3a\x19\xa5\x8e\x8b\x47\x3f\xa0\xf0\x62\xf7", 60);
  Blob t("\x65\xdc\xc5\x7f\xcf\x62\x3a\x24\x09\x4f\xcc\xa4\x0d\x35\x33\xf8", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kr24);
  e.ivcIs(ir8);
  e.aadIs(ar20);
  e.plaintextIs(pr60);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob aad(pkg, 20, 0);
  Blob ctxt(pkg, 60, 20);
  Blob tag(pkg, 16, 80);
  EXPECT_TRUE(aad == ar20);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

TEST(AES_GCMTest, Vector12) {
  Blob c("\xd2\x7e\x88\x68\x1c\xe3\x24\x3c\x48\x30\x16\x5a\x8f\xdc\xf9\xff"
         "\x1d\xe9\xa1\xd8\xe6\xb4\x47\xef\x6e\xf7\xb7\x98\x28\x66\x6e\x45"
         "\x81\xe7\x90\x12\xaf\x34\xdd\xd9\xe2\xf0\x37\x58\x9b\x29\x2d\xb3"
         "\xe6\x7c\x03\x67\x45\xfa\x22\xe7\xe9\xb7\x37\x3b", 60);
  Blob t("\xdc\xf5\x66\xff\x29\x1c\x25\xbb\xb8\x56\x8f\xc3\xd3\x76\xa6\xd9", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kr24);
  e.ivcIs(ir60);
  e.aadIs(ar20);
  e.plaintextIs(pr60);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob aad(pkg, 20, 0);
  Blob ctxt(pkg, 60, 20);
  Blob tag(pkg, 16, 80);
  EXPECT_TRUE(aad == ar20);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

TEST(AES_GCMTest, Vector13) {
  Blob t("\x53\x0f\x8a\xfb\xc7\x45\x36\xb9\xa9\x63\xb4\xf1\xc4\xcb\x73\x8b", 16);

  cfg.keySize = AES_GCM_KEYSIZE::K256;
  AES_GCM_Enc e(cfg);
  e.aadIs(Blob());
  e.keyIs(kz32);
  e.ivcIs(iz12);
  e.plaintextIs(Blob());
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  EXPECT_TRUE(pkg == t);
}

TEST(AES_GCMTest, Vector14) {
  Blob c("\xce\xa7\x40\x3d\x4d\x60\x6b\x6e\x07\x4e\xc5\xd3\xba\xf3\x9d\x18", 16);
  Blob t("\xd0\xd1\xc8\xa7\x99\x99\x6b\xf0\x26\x5b\x98\xb5\xd4\x8a\xb9\x19", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kz32);
  e.ivcIs(iz12);
  e.plaintextIs(pz16);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob ctxt(pkg, 16, 0);
  Blob tag(pkg, 16, 16);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

TEST(AES_GCMTest, Vector15) {
  Blob c("\x52\x2d\xc1\xf0\x99\x56\x7d\x07\xf4\x7f\x37\xa3\x2a\x84\x42\x7d"
         "\x64\x3a\x8c\xdc\xbf\xe5\xc0\xc9\x75\x98\xa2\xbd\x25\x55\xd1\xaa"
         "\x8c\xb0\x8e\x48\x59\x0d\xbb\x3d\xa7\xb0\x8b\x10\x56\x82\x88\x38"
         "\xc5\xf6\x1e\x63\x93\xba\x7a\x0a\xbc\xc9\xf6\x62\x89\x80\x15\xad", 64);
  Blob t("\xb0\x94\xda\xc5\xd9\x34\x71\xbd\xec\x1a\x50\x22\x70\xe3\xcc\x6c", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kr32);
  e.ivcIs(ir12);
  e.plaintextIs(pr64);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob ctxt(pkg, 64, 0);
  Blob tag(pkg, 16, 64);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

TEST(AES_GCMTest, Vector16) {
  Blob c("\x52\x2d\xc1\xf0\x99\x56\x7d\x07\xf4\x7f\x37\xa3\x2a\x84\x42\x7d"
         "\x64\x3a\x8c\xdc\xbf\xe5\xc0\xc9\x75\x98\xa2\xbd\x25\x55\xd1\xaa"
         "\x8c\xb0\x8e\x48\x59\x0d\xbb\x3d\xa7\xb0\x8b\x10\x56\x82\x88\x38"
         "\xc5\xf6\x1e\x63\x93\xba\x7a\x0a\xbc\xc9\xf6\x62", 60);
  Blob t("\x76\xfc\x6e\xce\x0f\x4e\x17\x68\xcd\xdf\x88\x53\xbb\x2d\x55\x1b", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kr32);
  e.ivcIs(ir12);
  e.aadIs(ar20);
  e.plaintextIs(pr60);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob aad(pkg, 20, 0);
  Blob ctxt(pkg, 60, 20);
  Blob tag(pkg, 16, 80);
  EXPECT_TRUE(aad == ar20);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

TEST(AES_GCMTest, Vector17) {
  Blob c("\xc3\x76\x2d\xf1\xca\x78\x7d\x32\xae\x47\xc1\x3b\xf1\x98\x44\xcb"
         "\xaf\x1a\xe1\x4d\x0b\x97\x6a\xfa\xc5\x2f\xf7\xd7\x9b\xba\x9d\xe0"
         "\xfe\xb5\x82\xd3\x39\x34\xa4\xf0\x95\x4c\xc2\x36\x3b\xc7\x3f\x78"
         "\x62\xac\x43\x0e\x64\xab\xe4\x99\xf4\x7c\x9b\x1f", 60);
  Blob t("\x3a\x33\x7d\xbf\x46\xa7\x92\xc4\x5e\x45\x49\x13\xfe\x2e\xa8\xf2", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kr32);
  e.ivcIs(ir8);
  e.aadIs(ar20);
  e.plaintextIs(pr60);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob aad(pkg, 20, 0);
  Blob ctxt(pkg, 60, 20);
  Blob tag(pkg, 16, 80);
  EXPECT_TRUE(aad == ar20);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

TEST(AES_GCMTest, Vector18) {
  Blob c("\x5a\x8d\xef\x2f\x0c\x9e\x53\xf1\xf7\x5d\x78\x53\x65\x9e\x2a\x20"
         "\xee\xb2\xb2\x2a\xaf\xde\x64\x19\xa0\x58\xab\x4f\x6f\x74\x6b\xf4"
         "\x0f\xc0\xc3\xb7\x80\xf2\x44\x45\x2d\xa3\xeb\xf1\xc5\xd8\x2c\xde"
         "\xa2\x41\x89\x97\x20\x0e\xf8\x2e\x44\xae\x7e\x3f", 60);
  Blob t("\xa4\x4a\x82\x66\xee\x1c\x8e\xb0\xc8\xb5\xd4\xcf\x5a\xe9\xf1\x9a", 16);

  AES_GCM_Enc e(cfg);
  e.keyIs(kr32);
  e.ivcIs(ir60);
  e.aadIs(ar20);
  e.plaintextIs(pr60);
  unique_ptr<AES_GCM_Result> res = e.ciphertext();
  EXPECT_TRUE(res->second == AES_GCM_STATUS::VALID);
  const Blob &pkg = res->first;
  Blob aad(pkg, 20, 0);
  Blob ctxt(pkg, 60, 20);
  Blob tag(pkg, 16, 80);
  EXPECT_TRUE(aad == ar20);
  EXPECT_TRUE(ctxt == c);
  EXPECT_TRUE(tag == t);
}

