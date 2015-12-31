#include "gtest/gtest.h"
#include "crypto/pbkdf2_sha256.h"
#include <future>

using namespace Crypto;
using Util::Blob;
using std::future;
using std::async;
using std::launch;
using std::unique_ptr;

// Salts
static Blob s1("\x9d\x68\x61\x4c\x08\xa4\x62\x8a", 8);
static Blob s2("\xf0\x84\x4a\x0a\xc2\xf3\xa9\x6d\x4c\xa0\x04\xc3\x7f\xf7\x66\x02", 16);

// Passphrases
static Blob p1("pqpqpq", 6);
static Blob p2("Suspendisse sed purus in metus tempus mattis.", 45);
static Blob p3("\x0a\xbf\x24\x25\x25\x05\xc7\x6d\x4d\xd9\x0d\x15\x4c", 13);

// Keys for all salt/passphrase combinations and 1k, 10k, 100k iterations
static Blob k_s1_p1_1k  ("\x75\xea\x0f\xc1\x2c\xcb\x0c\x2d\x51\xc3\xc0\xdb\x1f\x87\x7c\x2b"
                         "\x69\x9b\xf1\x3d\xed\xdd\x31\x2b\x22\x3d\xfc\xb5\xa8\x16\x75\x8e", 32);
static Blob k_s1_p1_10k ("\x79\x06\x65\xb3\x25\x3d\x2c\x3a\xec\x24\x36\xb4\xfd\x9a\xfc\x3d"
                         "\xde\x9b\x46\xe1\x6a\x74\x9b\xcb\x06\x94\x61\xed\xbb\x7a\x75\x45", 32);
static Blob k_s1_p1_100k("\x5e\xad\xc9\xdc\x00\xd5\xdd\xc8\x02\x11\x2d\x47\x07\x27\xf2\xbb"
                         "\x88\xde\x0b\xb6\xfb\xe1\x9d\x99\xd3\xe1\xbc\x68\x63\x2c\x02\xe7", 32);
static Blob k_s1_p2_1k  ("\x13\x7a\x46\x0a\x8c\x31\x6a\xc2\x90\xa3\x58\xfa\x16\x2a\x07\xc8"
                         "\x3d\x58\x4e\xaf\x0e\xa3\xb7\x65\x29\x12\xad\x04\xf2\xf7\x9b\x8a", 32);
static Blob k_s1_p2_10k ("\x6b\x9b\xae\x1e\x92\xc1\xd4\x87\xac\x7e\xc2\x93\x39\xa6\xd5\x16"
                         "\x8c\x91\x49\x8b\xbd\x36\xd2\x2f\xb3\x18\xec\xfb\xbe\xb4\xda\x4e", 32);
static Blob k_s1_p2_100k("\x0a\xd5\xee\x95\xf4\x54\xeb\xde\x96\xdc\xdd\x39\x6e\x4c\x1e\x56"
                         "\xd7\x0b\x3e\x2c\xab\xec\xb4\x5c\x13\xdc\xf9\x3f\x19\xec\x4a\x7f", 32);
static Blob k_s1_p3_1k  ("\x15\x64\x86\x95\x7d\xa3\x51\xea\x77\x0c\xc9\x1a\x21\x8a\x28\x00"
                         "\xf6\xcf\xdc\xd2\x31\x0a\xc3\xa2\xce\x82\x1f\x0d\xae\x7e\x9f\x96", 32);
static Blob k_s1_p3_10k ("\x21\xd0\x57\xb5\x66\xa0\x2d\x66\xf6\x69\x1f\x25\x3c\x44\xbf\x74"
                         "\xbb\x34\xbf\x17\xba\x8b\x61\x39\xf6\x0f\x3b\x90\x65\x63\x4d\x28", 32);
static Blob k_s1_p3_100k("\xc6\x9d\xcb\xf8\x09\x30\x58\x91\x02\x5e\x76\x19\xeb\xd3\x55\xa2"
                         "\xf3\xb1\xc1\x59\x7c\x5b\x97\xdb\x78\x54\x5d\xaf\x03\x5c\x11\xb7", 32);
static Blob k_s2_p1_1k  ("\x9b\x68\x1f\x2e\xe8\x18\x34\x15\x44\x16\x92\x48\xd8\x02\x83\x43"
                         "\xad\x67\x07\x75\xbd\x41\x48\x57\xa5\x6a\xfc\x3a\x6d\xcf\xa9\xc7", 32);
static Blob k_s2_p1_10k ("\x9e\x37\x68\x08\xb6\xa4\x48\x0f\xc6\x6f\xea\x52\xb3\x22\xe6\x64"
                         "\xd0\x06\x59\xc1\xe9\x87\xcf\xdb\x91\xac\x3d\x13\xb6\xcf\x44\x4f", 32);
static Blob k_s2_p1_100k("\x39\x07\x71\x39\xb8\xa0\x6f\x9d\x4a\xe0\x6b\x76\x2d\x50\x11\xe2"
                         "\xe8\x4a\x29\x3a\x09\xf3\x8d\x34\x65\xe7\x80\xb6\x32\x67\xde\xda", 32);
static Blob k_s2_p2_1k  ("\x57\x0e\x4d\x76\x6f\x46\x8a\xca\xf7\xa4\xbc\x1a\x43\xc2\xfd\x18"
                         "\xc4\xc4\xa4\xeb\x11\xcc\xd4\x04\xa6\xd1\x4f\x29\x40\xe8\x27\xd2", 32);
static Blob k_s2_p2_10k ("\x86\xd8\x49\x41\x5d\xb7\x41\x85\xee\xa6\x31\xff\x7e\x3e\x04\x4b"
                         "\x55\x90\x64\xfe\xa5\x9f\xc9\x1c\x9c\x8a\x42\x05\x9a\x87\xa6\x4d", 32);
static Blob k_s2_p2_100k("\xd8\x80\x50\xe5\x59\x55\x6e\xe7\x76\x72\x9b\x21\xea\x18\x15\x40"
                         "\x16\x67\x3a\x4c\xb8\xa1\x89\xdc\x47\xc1\x29\xfb\x03\xc9\x6c\x2a", 32);
static Blob k_s2_p3_1k  ("\x12\xef\xeb\xa1\x26\x5d\x8a\x41\xe9\x3b\x81\x47\x60\xe5\xe0\xfb"
                         "\x4e\x67\x26\xaf\x0f\x5a\x1b\xa8\x92\x51\x2b\x73\x49\x11\xd6\xb1", 32);
static Blob k_s2_p3_10k ("\x22\xd9\xb2\xfe\x5b\x6c\x36\xeb\xc7\xb8\x40\xcf\xac\x99\x66\x07"
                         "\xba\x75\xd3\x21\x55\x3a\x94\xfa\xf2\x7d\x41\x6d\x25\x07\xea\xec", 32);
static Blob k_s2_p3_100k("\x18\x47\x54\x30\xdf\xf0\x36\xb7\xbd\xd0\xfa\xa5\x37\x09\xff\x74"
                         "\x3a\x87\x3d\xbc\x6f\x64\x21\xb4\x93\xf3\xc5\x1c\x13\xba\x22\x07", 32);

TEST(Pbkdf2Sha256Test, TestVectors) {
  // Run the expensive tests asynchronously, let the system decide for the rest
  future<unique_ptr<Blob>> f1  = async(PBKDF2_SHA256, 32, p1, s1, 1000);
  future<unique_ptr<Blob>> f2  = async(launch::async, PBKDF2_SHA256, 32, p1, s1, 10000);
  future<unique_ptr<Blob>> f3  = async(launch::async, PBKDF2_SHA256, 32, p1, s1, 100000);
  future<unique_ptr<Blob>> f4  = async(PBKDF2_SHA256, 32, p2, s1, 1000);
  future<unique_ptr<Blob>> f5  = async(launch::async, PBKDF2_SHA256, 32, p2, s1, 10000);
  future<unique_ptr<Blob>> f6  = async(launch::async, PBKDF2_SHA256, 32, p2, s1, 100000);
  future<unique_ptr<Blob>> f7  = async(PBKDF2_SHA256, 32, p3, s1, 1000);
  future<unique_ptr<Blob>> f8  = async(launch::async, PBKDF2_SHA256, 32, p3, s1, 10000);
  future<unique_ptr<Blob>> f9  = async(launch::async, PBKDF2_SHA256, 32, p3, s1, 100000);
  future<unique_ptr<Blob>> f10 = async(PBKDF2_SHA256, 32, p1, s2, 1000);
  future<unique_ptr<Blob>> f11 = async(launch::async, PBKDF2_SHA256, 32, p1, s2, 10000);
  future<unique_ptr<Blob>> f12 = async(launch::async, PBKDF2_SHA256, 32, p1, s2, 100000);
  future<unique_ptr<Blob>> f13 = async(PBKDF2_SHA256, 32, p2, s2, 1000);
  future<unique_ptr<Blob>> f14 = async(launch::async, PBKDF2_SHA256, 32, p2, s2, 10000);
  future<unique_ptr<Blob>> f15 = async(launch::async, PBKDF2_SHA256, 32, p2, s2, 100000);
  future<unique_ptr<Blob>> f16 = async(PBKDF2_SHA256, 32, p3, s2, 1000);
  future<unique_ptr<Blob>> f17 = async(launch::async, PBKDF2_SHA256, 32, p3, s2, 10000);
  future<unique_ptr<Blob>> f18 = async(launch::async, PBKDF2_SHA256, 32, p3, s2, 100000);

  EXPECT_EQ(*(f1.get()),  k_s1_p1_1k);
  EXPECT_EQ(*(f2.get()),  k_s1_p1_10k);
  EXPECT_EQ(*(f3.get()),  k_s1_p1_100k);
  EXPECT_EQ(*(f4.get()),  k_s1_p2_1k);
  EXPECT_EQ(*(f5.get()),  k_s1_p2_10k);
  EXPECT_EQ(*(f6.get()),  k_s1_p2_100k);
  EXPECT_EQ(*(f7.get()),  k_s1_p3_1k);
  EXPECT_EQ(*(f8.get()),  k_s1_p3_10k);
  EXPECT_EQ(*(f9.get()),  k_s1_p3_100k);
  EXPECT_EQ(*(f10.get()), k_s2_p1_1k);
  EXPECT_EQ(*(f11.get()), k_s2_p1_10k);
  EXPECT_EQ(*(f12.get()), k_s2_p1_100k);
  EXPECT_EQ(*(f13.get()), k_s2_p2_1k);
  EXPECT_EQ(*(f14.get()), k_s2_p2_10k);
  EXPECT_EQ(*(f15.get()), k_s2_p2_100k);
  EXPECT_EQ(*(f16.get()), k_s2_p3_1k);
  EXPECT_EQ(*(f17.get()), k_s2_p3_10k);
  EXPECT_EQ(*(f18.get()), k_s2_p3_100k);
}

