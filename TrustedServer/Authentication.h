#pragma once
#include "Ethernet.h"
#include <string>
#include <botan/auto_rng.h>
#include <botan/ecdh.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <botan/bigint.h>
#include <botan/numthry.h>
#include <botan/mac.h>
#include <botan/ecdsa.h>
#include <botan/ec_group.h>
#include <botan/pubkey.h>
typedef uint8_t epid_group_id[4];
typedef struct ec_pub
{
	uint8_t gx[32];
	uint8_t gy[32];
} ec_pub;
typedef struct ra_msg0
{
	uint32_t	epid;
} ra_msg0;
typedef struct ra_msg1
{
	ec_pub             g_a;        // the Endian-ness of Ga is
											// Little-Endian
	epid_group_id      gid;        // the Endian-ness of GID is
											// Little-Endian
} ra_msg1;
typedef struct ec_sign256
{
	uint8_t x[32];
	uint8_t y[32];
} ec_sign256;
typedef struct ra_msg2
{
	ec_pub	        g_b;								// the Endian-ness of Gb is
														// Little-Endian
	uint8_t         spid[16];							// In little endian
	uint16_t        quote_type;							/* unlinkable Quote(0) or linkable Quote(0) in little endian*/
	uint16_t        kdf_id;					 			/* key derivation function id in little endian.
															0x0001 for AES-CMAC Entropy Extraction and Key Derivation */
	ec_sign256      sign_gb_ga;							// In little endian
	uint8_t         mac[16];							// mac_smk(g_b||spid||quote_type||
														//         sign_gb_ga)
	uint32_t        sig_rl_size;
	uint8_t         sig_rl[4];						//TODO Nochmal checken sig_rl hat keine größe ist dynamisch
} ra_msg2;
typedef struct ec_private
{
	uint8_t r[32];
} ec256_private;
int ra_proc1();

class ClientDatabase
{
private: 
	std::vector <ec_pub> clientDatabase;
public: 
	ec_pub getPublicKey(int ID) { return this->clientDatabase.at(ID); };
	int addClient(ec_pub publicKey);
	int removeClient(int ID);
	int storeDatabase();
};