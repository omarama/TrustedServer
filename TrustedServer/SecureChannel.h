#pragma once
#include "Ethernet.h"
#include "botan/auto_rng.h"
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/cipher_mode.h>
#include "AAA.h"


const std::vector<uint8_t> privateEccTsR = Botan::hex_decode("4C0085C17342FF475C1F65F732A35135B5F31A1CA34F154894AC8C3A82A04844");
const std::vector<uint8_t> publicEccTsX = Botan::hex_decode("4A929384B9A1B7F0C9FF7A4DCFB2901D2BD73EC0D2478E07A882627A7F074BED");
const std::vector<uint8_t> publicEccTsY = Botan::hex_decode("940CF170C9E97132C4D4B67BB1BBC0E8A8D54727533D0C27D2BB742B7476B90F");

//const std::vector<uint8_t> Client1Pub = Botan::hex_decode("041df3f8fdd2036ee2554fa3bc0d5bd5560a4d01b5f0ac94f9aae9b1f798fa259e09b359d32d89a7888dbc4560e4f29687c800f9a1c69a34d4e9a2f1b970e8c592");
const std::vector<uint8_t> privateEccCR = Botan::hex_decode("81fd790f1a00f8c38b92cf51ebc250d39a5f0e9930ec0496082df4624650ef21");

//static const uint8_t publicEccClient [64]= 
//{
//	0x1d, 0xf3, 0xf8, 0xfd, 0xd2, 0x03, 0x6e, 0xe2, 
//	0x55, 0x4f, 0xa3, 0xbc, 0x0d, 0x5b, 0xd5, 0x56,
//	0x0a, 0x4d, 0x01, 0xb5, 0xf0, 0xac, 0x94, 0xf9,
//	0xaa, 0xe9, 0xb1, 0xf7, 0x98, 0xfa, 0x25, 0x9e, 
//
//	0x09, 0xb3, 0x59, 0xd3, 0x2d, 0x89, 0xa7, 0x88,
//	0x8d, 0xbc, 0x45, 0x60, 0xe4, 0xf2, 0x96, 0x87,
//	0xc8, 0x00, 0xf9, 0xa1, 0xc6, 0x9a, 0x34, 0xd4, 
//	0xe9, 0xa2, 0xf1, 0xb9, 0x70, 0xe8, 0xc5, 0x92
//};
#define AESMACSIZE 16
#define AESIVSIZE 12
#define AESKEYSIZE 16
class SecureChannel
{
private:
	//int myTempSecretUsed = 0;
	Botan::AutoSeeded_RNG rng;
	Botan::EC_Group domain;
	int generateTempSecret(Ethernet &sock);
	Botan::secure_vector<uint8_t> myChannelKey;
	Ethernet &myClient;
	bool clientAuthenticated = false; 
	int clientID; 
public:
	SecureChannel(Ethernet &sock);
	int sendSecure(const std::vector<uint8_t> &data);
	int sendSecure(const std::string &plainDataSend);
	int receiveSecure(std::vector<uint8_t> &plainDataRec, const int length);
	int receiveSecure(std::string &plainDataRec, const int length);
	bool getClientAuthenticated() const;
	int getClientID() { return this->clientID; }
};