CC = clang
CXX = clang++
CXXFLAGS=-std=c++17 -I/usr/local/include
LDFLAGS=-L/usr/local/ -lsodium

aes_gcm: packet_crypter.o main.o
	$(CXX) $(LDFLAGS) packet_crypter.o main.o -o aes_gcm

packet_crypter.o: packet_crypter.cpp packet_crypter.h
	$(CXX) $(CXXFLAGS) packet_crypter.cpp -c -o packet_crypter.o

main.o: main.cpp 
	$(CXX) $(CXXFLAGS) main.cpp -c -o main.o

clean:
	rm -rf *.o aes_gcm
