#pragma once

#include <array>

#include <sodium.h>

class PacketCrypter {
public:

  using Nonce = std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES>;

  struct State {
    uint8_t key[crypto_secretbox_KEYBYTES]{0};
      uint32_t nextLiteNonce_{};
  };

  PacketCrypter(State state);

  size_t SpaceRequiredToEncrypt(size_t cleartextSize);

  bool Decrypt(uint8_t* src, size_t& length);
  bool Encrypt(uint8_t* src, size_t& length, size_t bufferCapacity);

private:
    State state_{};
};
