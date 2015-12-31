#include "crypto/aes_gcm_pbkd.h"
#include "crypto/random.h"
#include "util/byte_encoders.h"
#include <unistd.h>
#include <cstring>
#include <iostream>
using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::unique_ptr;
using Util::Blob;
using Util::MutableBlob;
using Util::encode_hex;
using Util::encode_base58;
using Util::encode_base64;
using Util::encode_string;

static void usage()
{
  const char *msg =
    "\nUsage: <program> [options]\n"
    "    -d <demo>  Choose demo 1 (default) or 2\n"
    "    -h         Print this help message\n"
    "\n";
    cerr << msg;
    exit(1);
}

static void blockPrint(const string &msg, U32 offset, U32 cols)
{
  for (U64 i = 0; i < msg.size(); i++) {
    if ((i % (cols - offset)) == 0) {
      if (i != 0) {
        cout << endl;
      }
      for (U64 j = 0; j < offset; j++) {
        cout << " ";
      }
    }
    cout << msg[i];
  }
  cout << endl;
}

/* Example 1: Simplified AES/PBKDF2 encryption/decryption
 *
 * Uses the AES_GCM_PBKD interface for simpler encryption
 * and decryption when the key should be password-based.
 * Otherwise it is the same as the next example and encrypts
 * and decrypts with 256-bit authenticated encryption (AES/GCM).
 */
static Blob ex1_encrypt(const string &_msg, const string &_pw)
{
  // Configuration
  Crypto::AES_GCM_PBKD_Config cfg;
  cfg.keySize = Crypto::AES_GCM_KEYSIZE::K256;
  cfg.tagSize = Crypto::AES_GCM_TAGSIZE::T128;
  cfg.ivOutput = Crypto::AES_GCM_IV_OUTPUT::CTXT_PREPEND_AAD;
  cfg.PBKDIters = 100000;

  // Encrypt the message
  Crypto::AES_GCM_PBKD_Enc enc(cfg);
  enc.passwordIs(Blob(_pw));
  enc.plaintextIs(Blob(_msg));
  std::unique_ptr<Crypto::AES_GCM_Result> encRes = enc.ciphertext();
  if (encRes->second != Crypto::AES_GCM_STATUS::VALID) {
    cout << "Error: Encryption failed" << endl;
    exit(1);
  }
  Blob &ctxt = encRes->first;
  cout << "Encrypted message:" << endl;
  blockPrint(*ctxt.data(encode_hex), 4, 80);

  return Blob(ctxt);
}

static void ex1_decrypt(const Blob &_ctxt, const string &_pw)
{
  // Specify the configuration
  Crypto::AES_GCM_PBKD_Config cfg;
  cfg.keySize = Crypto::AES_GCM_KEYSIZE::K256;
  cfg.tagSize = Crypto::AES_GCM_TAGSIZE::T128;
  cfg.ivOutput = Crypto::AES_GCM_IV_OUTPUT::CTXT_PREPEND_AAD;
  cfg.PBKDIters = 100000;

  // Decrypt the message
  Crypto::AES_GCM_PBKD_Dec dec(cfg);
  dec.passwordIs(Blob(_pw));
  dec.ciphertextIs(_ctxt);
  const Crypto::AES_GCM_Result &decRes = dec.plaintext();
  if (decRes.second != Crypto::AES_GCM_STATUS::VALID) {
    cout << "Error: Decryption failed" << endl;
    exit(1);
  }
  const Blob &ptxt = decRes.first;
  cout << "Decrypted message:" << endl;
  blockPrint(*ptxt.data(encode_string), 4, 80);
}

/* Example 2: Manual key derivation and encryption/decryption
 *
 * Generates a key with PBKDF2 and then encrypts and decrypts
 * the message with 256-bit authenticated encryption (AES/GCM).
 */
static Blob ex2_encrypt(const string &_msg, const string &_pw)
{
  // Initialization vector / salt is needed for key derivation
  MutableBlob ivc(Crypto::AES_GCM_BLOCKSIZE_BYTES, Blob::ScrubType::ZEROS,
    Blob::CompareType::CONST);
  Crypto::randomize(ivc);

  // Create a key from the password and salt with 100k iterations
  cout << "Password:\n    " << _pw << endl;
  unique_ptr<Blob> key = Crypto::PBKDF2_SHA256(Crypto::AES_GCM_KEYSIZE_256,
    _pw, ivc, 100000);
  cout << "Key:" << endl;
  blockPrint(*(key->data(encode_hex)), 4, 80);

  // Encrypt the data
  Crypto::AES_GCM_Config cfg;
  cfg.keySize = Crypto::AES_GCM_KEYSIZE::K256;
  cfg.tagSize = Crypto::AES_GCM_TAGSIZE::T128;
  cfg.ivMode = Crypto::AES_GCM_IV_MODE::MANUAL;
  cfg.ivOutput = Crypto::AES_GCM_IV_OUTPUT::CTXT_PREPEND_AAD;
  Crypto::AES_GCM_Enc enc(cfg);
  Crypto::AES_GCM_STATUS encStatus;
  encStatus = enc.keyIs(*key);
  if (encStatus != Crypto::AES_GCM_STATUS::VALID) {
    cout << "Error setting encryption key" << endl;
    exit(1);
  }
  encStatus = enc.ivcIs(ivc);
  if (encStatus != Crypto::AES_GCM_STATUS::VALID) {
    cout << "Error setting encryption IV/counter" << endl;
    exit(1);
  }
  enc.plaintextIs(Blob(_msg));
  unique_ptr<Crypto::AES_GCM_Result> encRes = enc.ciphertext();
  if (encRes->second != Crypto::AES_GCM_STATUS::VALID) {
    cout << "Error: Encryption failed" << endl;
    exit(1);
  }
  Blob &ctxt = encRes->first;
  cout << "Encrypted message:" << endl;
  blockPrint(*ctxt.data(encode_hex), 4, 80);

  return Blob(ctxt);
}

static void ex2_decrypt(const Blob &_ctxt, const string &_pw)
{
  // Extract ciphertext components
  U32 ivSize = Crypto::AES_GCM_BLOCKSIZE_BYTES;
  U32 tagSize = Crypto::AES_GCM_Tagsize(Crypto::AES_GCM_TAGSIZE::T128);
  U64 ctxtSize = _ctxt.size() - ivSize - tagSize;
  Blob ivc(_ctxt, ivSize, 0);
  Blob ctxt(_ctxt, ctxtSize, ivSize);
  Blob tag(_ctxt, tagSize, ivSize + ctxtSize);

  // Recover the key
  unique_ptr<Blob> key = Crypto::PBKDF2_SHA256(Crypto::AES_GCM_KEYSIZE_256,
    _pw, ivc, 100000);

  // Decrypt
  Crypto::AES_GCM_Dec dec;
  dec.ciphertextIs(ctxt);
  dec.ivIs(ivc);
  dec.tagIs(tag);
  if (dec.keyIs(*key) != Crypto::AES_GCM_STATUS::VALID) {
    cout << "Error setting decryption key" << endl;
    exit(1);
  }
  const Crypto::AES_GCM_Result &resDec = dec.plaintext();
  if (resDec.second != Crypto::AES_GCM_STATUS::VALID) {
    cout << "Error: Decryption failed" << endl;
    exit(1);
  }
  const Blob &ptxt = resDec.first;
  cout << "Decrypted message:" << endl;
  blockPrint(*ptxt.data(encode_string), 4, 80);
}

int main(int argc, char *argv[])
{
  int demo = 1;

  // Parse command line options
  int ch;
  while ((ch = getopt(argc, argv, "d:h")) != -1) {
    switch (ch) {
      case 'd':
        demo = std::stoi(optarg);
        break;
      case 'h':
      default:
        usage();
        break;
    }
  }
  argc -= optind;
  argv += optind;

  string msg = "This is a plaintext message";
  string pw = "7j(xf";

  switch (demo) {
    case 1:
      ex1_decrypt(ex1_encrypt(msg, pw), pw);
      break;
    case 2:
      ex2_decrypt(ex1_encrypt(msg, pw), pw);
      break;
    default:
      cerr << "Error: Invalid demo '" << demo << "'" << endl;
      exit(1);
  }
  return 0;
}

