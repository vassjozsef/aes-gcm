#include "packet_crypter.h"

size_t constexpr kLiteBytes{4};

PacketCrypter::PacketCrypter(State state) : state_(state)
{
  int res = sodium_init();
  if (res == -1) {
    assert(!"Sodium init failed");
  }
}

size_t PacketCrypter::SpaceRequiredToEncrypt(size_t cleartextSize)
{
  return cleartextSize + crypto_aead_aes256gcm_ABYTES + kLiteBytes;
}

bool PacketCrypter::Decrypt(uint8_t* src, size_t& length)
{
  size_t packetLength = length;
  Nonce nonce{};
  size_t nonceOffset{0};
  size_t nonceLength{0};

  nonceOffset = packetLength - kLiteBytes;
  nonceLength = kLiteBytes;
  packetLength -= kLiteBytes;
  if (length <  crypto_aead_aes256gcm_ABYTES + kLiteBytes) {
    return false;
  }

  std::copy(src + nonceOffset, src + nonceOffset + nonceLength, nonce.begin());
  uint8_t* cryptoBuffer = src;

  int res = crypto_aead_aes256gcm_decrypt(cryptoBuffer,
                                          nullptr,
                                          nullptr,
                                          cryptoBuffer,
                                          (unsigned long long)(packetLength),
                                          src,
                                          0,
                                          &nonce[0],
                                          state_.key);

  length = packetLength - crypto_aead_aes256gcm_ABYTES;

  if (res != 0) {
    return false;
  }

  return true;
}

bool PacketCrypter::Encrypt(uint8_t* src, size_t& length, size_t bufferCapacity)
{
  auto oldSize = length;
  auto newSize = SpaceRequiredToEncrypt(length);

  if (bufferCapacity < newSize) {
    return false;
  }

  Nonce nonce{};
  size_t bytesToAppend = 0;

  auto start = reinterpret_cast<uint8_t const*>(&state_.nextLiteNonce_);
  std::copy(start, start + sizeof(state_.nextLiteNonce_), nonce.begin());
  ++state_.nextLiteNonce_;
  bytesToAppend = kLiteBytes;

  uint8_t* encryptedData = src;
  unsigned long long encryptedLen = 0;

  int res = crypto_aead_aes256gcm_encrypt(encryptedData,
                                            &encryptedLen,
                                            encryptedData,
                                            oldSize,
                                            src,
                                            0,
                                            NULL,
                                            &nonce[0],
                                            state_.key);

  newSize = static_cast<size_t>(encryptedLen + kLiteBytes);

  if (res != 0) {
    return 0;
  }

  if (bytesToAppend > 0) {
    auto checkedSrc = src;
    auto dest = checkedSrc + newSize - bytesToAppend;
    std::copy(nonce.begin(), nonce.begin() + bytesToAppend, dest);
  }

 length = newSize;

  return true;
}



