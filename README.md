AES GCM Encryption Test
=======================

Testing out AES GCM from `libsodium` on different architectures.

Install
-------

Download the latest stable `libsodium` source from https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz. Build and install:

    ./configure
    make
    make install

`libsodium` release does not support AES GCM for ARM.  For M2, please clone https://github.com/jedisct1/libsodium.git master branch. Make sure you have `autoconf`, `libtool` and `automake` installed. Build and install:

    ./autogen.sh -s
    ./configure 
    make
    make install

Build and run the sample:

    make
    ./aes_gcm 
