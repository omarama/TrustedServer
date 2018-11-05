#include "stdafx.h"
#include "Authentication.h"

// This is the private EC key of SP, the corresponding public EC key is
// hard coded in isv_enclave. It is based on NIST P-256 curve.
static const ec_private tsPrivKey = {
	{
		//0x01,0x8c,0x03,0xd1, 0x53,0x34,0x57,0xad,0xea, 0xae,
		//0xb6, 0x65,0x3b,0x6a,0x86,0x1f,0xec,0x87,0x9c,
		//0x43,0x11,0xde,0x66,0x3b, 0xce,0xa1, 0x52,0x2d,
		//0xbb,0x6c,0xe7,0x90
		0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
		0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
		0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
		0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
	}
};
// This is the public EC key of SP, this key is hard coded in isv_enclave.
// It is based on NIST P-256 curve. Not used in the SP code.
static const ec_pub tsPubKey = {
	{
		0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
		0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
		0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
		0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
	},
	{
		0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
		0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
		0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
		0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
	}
};
int ra_proc1()
{
	auto& sock = Ethernet::getInstance();
	int result = 0;
	ra_msg0 ra_msg0;
	ra_msg1 ra_msg1;
	ra_msg2 ra_msg2;
	std::string msg;
	int msg1Length = sizeof(ra_msg1);
	msg.reserve(msg1Length);
	if (sock.getSockInitialzied())
	{
		result = sock.receiveIn(msg, sizeof(ra_msg0.epid));
		if (result == sizeof(ra_msg0.epid))
		{
			for (int i = 0; i < result; i++)
			{
				ra_msg0.epid = 0;
			}
		}
		else
		{
			return -1;
		}
		result = sock.receiveIn(msg, sizeof(ra_msg1.g_a.gx));
		if (result == sizeof(ra_msg1.g_a.gx))
		{
			for (int i = 0; i < result; i++)
			{
				ra_msg1.g_a.gx[31-i] = msg.at(i);
			}
		}
		else
		{
			return -1;
		}
		std::cout << "There are " << result << " bytes received!" << std::endl;
		result = sock.receiveIn(msg, sizeof(ra_msg1.g_a.gy));
		if (result == sizeof(ra_msg1.g_a.gy))
		{
			for (int i = 0; i < result; i++)
			{
				ra_msg1.g_a.gy[31-i] = msg.at(i);
			}
		}
		else
		{
			return -1;
		}
		std::cout << "There are " << result << " bytes received!" << std::endl;
		result = sock.receiveIn(msg, sizeof(ra_msg1.gid));
		if (result == sizeof(ra_msg1.gid))
		{
			for (int i = 0; i < result; i++)
			{
				ra_msg1.gid[4-i] = msg.at(i);
			}
		}
		else
		{
			return -1;
		}
		std::cout << "There are " << result << " bytes received!" << std::endl;
		/*Message 1 is received from the client*/
		/*Generate Message 2*/
		/////////////////////////////////////1/////////////////////////////////////////////////////////////
		Botan::AutoSeeded_RNG rng;
		// ec domain and
		Botan::EC_Group domain("secp256r1");
		std::string kdf = "KDF1(AES-128/CMAC)";
		//private and public key TS
		Botan::PointGFp tsPubPoint(domain.get_curve(), Botan::BigInt(tsPubKey.gx, 32), Botan::BigInt(tsPubKey.gy, 32));
		Botan::ECDSA_PrivateKey privKeyTS(rng,domain,Botan::BigInt(tsPrivKey.r,32));
		Botan::ECDSA_PublicKey pubKeyTS(domain, tsPubPoint);
		//generate ECDH keys
		Botan::PointGFp clientPubPoint(domain.get_curve(), Botan::BigInt(ra_msg1.g_a.gx,32), Botan::BigInt(ra_msg1.g_a.gy,32));
		Botan::ECDH_PrivateKey channelPrivKeyTS(rng, domain);
		Botan::PointGFp tsChannelPoint(channelPrivKeyTS.public_point());
		Botan::ECDH_PublicKey channelPubKeyC(domain,clientPubPoint);
		if (channelPubKeyC.check_key(rng, 1))
		{
			std::cout << "Key is valid" << std::endl;
		}

		/////////////////////////////////////2//////////////////////////////////////////////////
		// Construct key agreements
		Botan::PK_Key_Agreement ecdhTS(channelPrivKeyTS, rng, "Raw");
		// Agree on shared secret and derive symmetric key of 256 bit length
		Botan::secure_vector<uint8_t> Gab_secret = ecdhTS.derive_key(16, channelPubKeyC.public_value()).bits_of();
		const std::vector<uint8_t> key = Botan::hex_decode("00000000000000000000000000000000");
		std::vector<uint8_t> invertedGab;// = Botan::hex_decode("6BC1BEE22E409F96E93D7E117393172A");
		for (int i = 15; i <= 0 ;i--)
		{
			invertedGab.push_back(Gab_secret.at(i));
		}
		std::unique_ptr<Botan::MessageAuthenticationCode> mac(Botan::MessageAuthenticationCode::create("CMAC(AES-128)"));
		if (!mac)
			return 1;
		mac->set_key(key);
		mac->update(invertedGab);
		Botan::secure_vector<uint8_t> kdk = mac->final();
		mac->clear();
		
		///////////////////////////3/////////////////////////////////////
		mac->set_key(kdk);
		uint8_t derivation_buffer[7];
		derivation_buffer[0] = 0x01;
		memcpy_s(&derivation_buffer[1], sizeof(derivation_buffer)-1, "SMK", 3);
		uint8_t *additional = (uint8_t *)(&(derivation_buffer[7 - 3]));
		*additional = 0x00;
		uint16_t *key_len = (uint16_t *)(&(derivation_buffer[7 - 2]));
		*key_len = 0x0080;
		mac->update(derivation_buffer,7);
		Botan::secure_vector<uint8_t> SMK = mac->final();

		///////////////////////////////4(1)/////////////////////////////////////////
		ra_msg2.quote_type = 0x0001;
		memset(ra_msg2.spid, 0, sizeof(ra_msg2.spid));
		///////////////////////////////5(2)////////////////////////////////////////////
		ra_msg2.kdf_id = 0x0001;
		///////////////////////////////6(3)////////////////////////////////////////
		Botan::PK_Signer signer(privKeyTS, rng, "EMSA1(SHA-256)");
		Botan::BigInt buf(tsChannelPoint.get_x());
		uint8_t temp[32];
		memcpy(temp, buf.data(), sizeof(temp));
		for (int i = 0; i < 32; i++)
		{
			memcpy(&ra_msg2.g_b.gx[i], &temp[31-i], 1);
		}
		buf.operator<<=(32 * 8);
		buf.operator+= (tsChannelPoint.get_y());
		memcpy(temp, buf.data(), sizeof(temp));
		for (int i = 0; i < 32; i++)
		{
			memcpy(&ra_msg2.g_b.gy[i], &temp[31 - i], 1);
		}
		buf.operator<<=(32 * 8);
		buf.operator+= (clientPubPoint.get_x());
		buf.operator<<=(32 * 8);
		buf.operator+= (clientPubPoint.get_y());

		uint8_t Gba[128];
		memcpy(Gba, buf.data(), sizeof(Gba));			//eventuell falsch kopiert ?? schau nochmal nach der reihenfolge
		signer.update(Gba, sizeof(Gba));
		std::vector<uint8_t> signature = signer.signature(rng);
		// verify signature
		Botan::PK_Verifier verifier(pubKeyTS, "EMSA1(SHA-256)");
		verifier.update(Gba,sizeof(Gba));
		std::cout << std::endl << "is " << (verifier.check_signature(signature) ? "valid" : "invalid");
		for (int i = 0; i < 32; i++)
		{
			memcpy(&ra_msg2.sign_gb_ga.x[i], &signature.at(31-i), 1);
			memcpy(&ra_msg2.sign_gb_ga.y[i], &signature.at(63-i), 1);
		}
		mac->clear();

		/////////////////////////////////////7(4)///////////////////////////////////////////////////////////
		mac->set_key(SMK);
		mac->update(ra_msg2.g_b.gx, sizeof(ra_msg2.g_b.gx));
		mac->update(ra_msg2.g_b.gy, sizeof(ra_msg2.g_b.gy));
		mac->update(ra_msg2.spid, sizeof(ra_msg2.spid));
		mac->update(static_cast<uint8_t>(ra_msg2.quote_type));
		mac->update(static_cast<uint8_t>(ra_msg2.quote_type+1));
		mac->update(static_cast<int8_t>(ra_msg2.kdf_id));
		mac->update(static_cast<int8_t>(ra_msg2.kdf_id+1));
		mac->update(ra_msg2.sign_gb_ga.x,  sizeof(ra_msg2.sign_gb_ga.x));
		mac->update(ra_msg2.sign_gb_ga.y, sizeof(ra_msg2.sign_gb_ga.y));
		Botan::secure_vector<uint8_t> AMac = mac->final();
		memcpy(ra_msg2.mac, AMac.data(), sizeof(ra_msg2.mac));
		memset(&ra_msg2.sig_rl_size, 0, sizeof(ra_msg2.sig_rl_size));
		memset(&ra_msg2.sig_rl, 0, 4);
		char msg2[168];
		memcpy(msg2, &ra_msg2, 168);
		result = sock.sendOut(std::string(msg2, 168));
}
	else
	{
		return -1; 
	}
	getchar(); 
	return 1; 
}
int ClientDatabase::addClient(const ec_pub pubKey)
{
	std::cout << "There is a new client. Should the key add to the database?\nThe public key is: [Y]" << std::endl; 
	std::cout << "x Point:\n"; 
	for (int i = 0; i < 32; i++)
	{
		std::cout << pubKey.gx[i] << "\t";
	}
	std::cout << "\ny Point:\n";
	for (int i = 0; i < 32; i++)
	{
		std::cout << pubKey.gy[i] << "\t";
	}
	int temp = getchar(); 
	if (temp == 'Y')
	{
		int clientID = clientDatabase.size();
		this->clientDatabase.push_back(pubKey);
		return clientID;
	}
	else
	{
		return -1;
	}

}
int ClientDatabase::removeClient(const int ID)
{
	if (this->clientDatabase.size() > ID)
	{
		std::cout << "Do you want to delete client ID?\nThe public key is: [Y]" << std::endl;
		std::cout << "x Point:\n";
		for (int i = 0; i < 32; i++)
		{
			std::cout << this->clientDatabase.at(ID).gx[i] << "\t";
		}
		std::cout << "\ny Point:\n";
		for (int i = 0; i < 32; i++)
		{
			std::cout << this->clientDatabase.at(ID).gy[i] << "\t";
		}
		int temp = getchar();
		if (temp == 'Y')
		{
			auto ret = this->clientDatabase.erase(clientDatabase.begin()+ID);
			return ID;
		}
		else
		{
			return -1;
		}
	}
	else
	{
		std::cout << "This client ID is invalid!" << std::endl; 
		return -1; 
	}

}
int ClientDatabase::storeDatabase()
{
	std::ofstream bigFile;
	bigFile.open("../ClientDatabase.txt", std::ios::app);
	if (bigFile.is_open() &&(this->clientDatabase.size() !=0))
	{
		for (int i = 0; i < clientDatabase.size(); i++)
		{
			bigFile.write(reinterpret_cast<char*>(clientDatabase.data()), 64);
		}
		bigFile.close(); 
		return 1;

	}
	else
	{
		printf("Cannot write file!\n");
		return 0;
	}
}