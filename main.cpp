#include "packet_crypter.h"

#include <iostream>

#include <random>

using random_bytes_engine = std::independent_bits_engine<
    std::default_random_engine, CHAR_BIT, unsigned char>;

int main(void) {
  random_bytes_engine rbe;
  PacketCrypter::State state{};
  std::generate(std::begin(state.key), std::end(state.key), std::ref(rbe));
  state.nextLiteNonce_ = 0;
  auto crypter = PacketCrypter(state);

  size_t plaintextSize = 100;
  std::vector<uint8_t> plaintext(plaintextSize);
  std::generate(std::begin(plaintext), std::end(plaintext), std::ref(rbe));
  auto bufferCapcity = crypter.SpaceRequiredToEncrypt(plaintextSize);
  std::vector<uint8_t> ciphertext(bufferCapcity);
  memcpy(ciphertext.data(), plaintext.data(), plaintextSize);
  auto ciphertextSize{plaintextSize};

  auto res = crypter.Encrypt(ciphertext.data(), ciphertextSize, bufferCapcity);
  assert(res);

  auto decryptedSize = ciphertextSize;
  res = crypter.Decrypt(ciphertext.data(), decryptedSize);
  assert(res);

  assert(plaintextSize == decryptedSize);

  assert(!memcmp(plaintext.data(), ciphertext.data(), plaintextSize));
}
