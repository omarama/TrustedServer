#include "SecureChannel.h"
#include "stdafx.h"

SecureChannel::SecureChannel(Ethernet &sock) : domain("secp256r1"), myClient(sock)
{
	generateTempSecret(this->myClient);
}

int SecureChannel::generateTempSecret(Ethernet &sock)
{
	uint8_t clientRand[32];
	std::string buf;
	Botan::secure_vector<uint8_t> tsRand;
	Botan::ECDSA_PrivateKey tsPrivKey(this->rng, domain, Botan::BigInt(privateEccTsR.data(), privateEccTsR.size()));
	std::vector<uint8_t> signature;
	std::vector<uint8_t> message;
	/* Channel Key Exchange */

	/* 1. Receive Rand Number from Client */
	sock.receiveIn(buf, 96);
	memcpy(clientRand, buf.c_str(), 32);
	for (int i = 0; i < 64; i++)
	{
		signature.push_back(buf.at(32+i));
	}	
	for (int i = 0; i <32; i++)
	{
		message.push_back(buf.at(i));
	}
	int id1 = authenticationCheck(message, signature, tsPrivKey.algorithm_identifier());
	if (id1 == -1)
	{
		return -1; 
	}
	buf.clear();

	/* 2. Send Random Number to the Client */
	Botan::PK_Signer signerTs(tsPrivKey,this->rng, "EMSA1(SHA-256)");
	tsRand = this->rng.random_vec(32);
	std::vector<uint8_t> signatureTsRand = signerTs.sign_message(tsRand.data(), tsRand.size(), this->rng); 

	for (int i = 0; i < 32; i++) 
	{
		buf.push_back(tsRand.at(i));
	}
	for (int i = 0; i < 64; i++)
	{
		buf.push_back(signatureTsRand.at(i));
	}
	sock.sendOut(buf);
	buf.clear(); 

	/* 3. Receive Public Channel Key from Client */
	sock.receiveIn(buf, 128); 	
	uint8_t clientX[32];
	for (int i = 0; i < 32; i++)
	{
		memcpy(&clientX[i], buf.c_str()+(31-i), 1);
	}
	uint8_t clientY[32];
	for (int i = 0; i < 32; i++)
	{
		memcpy(&clientY[i], buf.c_str() + (63 - i), 1);
	}
	/*Check Signature*/
	signature.clear();
	for (int i = 0; i < 64; i++)
	{
		signature.push_back(buf.at(64 + i));
	}
	int id2 = authenticationCheck(std::vector<uint8_t>(buf.data(),buf.data()+64), signature, tsPrivKey.algorithm_identifier());
	if (id2 == -1)
	{
		std::cout << "Channel key cannot generated! Signature Failure!";
		return -1;
	}
	else if (id2 != id1)
	{
		std::cout << "Failure in channel key generation" << std::endl; 
		return -1; 
	}
	Botan::PointGFp clientPubPoint(this->domain.get_curve(), Botan::BigInt(clientX,32), Botan::BigInt(clientY, 32));
	Botan::ECDH_PublicKey Ga(this->domain, clientPubPoint);
	if (!Ga.check_key(this->rng, 0))
	{
		std::cout << "The public channel key of the client is invalid!" << std::endl; 
		return -1; 
	}
	buf.clear(); 

	/* 4. Send Public Channel Key to the Client */
	Botan::ECDH_PrivateKey Gb(this->rng, this->domain);
	Botan::BigInt tempX = Gb.public_point().get_affine_x();
	Botan::BigInt tempY = Gb.public_point().get_affine_y();
	char temp[64];
	memcpy(&temp[0], tempX.data(), 32);
	memcpy(&temp[32], tempY.data(), 32);
	std::string packet(temp, 64);
	std::vector<uint8_t> signatureTsGb = signerTs.sign_message(reinterpret_cast<const uint8_t*>(packet.data()), 64, this->rng);

	for (int i = 0; i < 64; i++)
	{
		packet.push_back(signatureTsGb.at(i));
	}
	sock.sendOut(packet);

	/* 5. Generate preshared secret */
	Botan::PK_Key_Agreement ecdhTS(Gb, this->rng, "Raw");
	// Agree on shared secret and derive symmetric key of 256 bit length
	Botan::secure_vector<uint8_t> Gab_secret = ecdhTS.derive_key(32, Ga.public_value()).bits_of();

	std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create("SHA-256"));
	hash->update(Gab_secret);
	hash->update(clientRand,32);
	hash->update(tsRand);
	this->myChannelKey = hash->final();

	buf.clear();
	int status = receiveSecure(buf, 11);
	if ( (buf.substr(0,11) == "HelloServer"))
	{
		std::cout << "Erfolgreich" << std::endl;
		status = sendSecure("HelloClient");
		this->clientAuthenticated = true; 
	}
	this->clientID = id1;
	return 1; 
}
bool SecureChannel::getClientAuthenticated() const 
{
	return this->clientAuthenticated; 
}
int SecureChannel::sendSecure(const std::string &plainDataSend)
{
	int result; 
	std::vector<uint8_t> sendWrapper(plainDataSend.data(), plainDataSend.data() + plainDataSend.size());
	result = sendSecure(sendWrapper);
	return result; 
}
int SecureChannel::sendSecure(const std::vector<uint8_t> &plainDataSend)
{
	int sent = 0; 
	std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-128/GCM", Botan::ENCRYPTION);
	enc->set_key(this->myChannelKey.data(), AESKEYSIZE);
	Botan::secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());
	enc->start(iv);
	Botan::secure_vector<uint8_t> pt(plainDataSend.data(), plainDataSend.data() + plainDataSend.size());
	enc->finish(pt);
	std::vector< uint8_t> securePacket;
	securePacket.insert(securePacket.begin(), iv.data(), iv.data()+iv.size());
	securePacket.insert(securePacket.end(),pt.data(), pt.data()+pt.size());
	sent = this->myClient.sendOut(std::string(reinterpret_cast<char*>(securePacket.data()), securePacket.size()));
	if (sent == securePacket.size())
		return 1;
	else if (sent == SOCKET_ERROR)
		return -1;
	else
		return 0; 
}
int SecureChannel::receiveSecure(std::string &plainDataRec, const int length)
{
	int result;
	std::vector<uint8_t> receiveWrapper;
	receiveWrapper.resize(length); 
	result = receiveSecure(receiveWrapper, length);
	if (result <= 0)
	{
		return result; 
	}
	plainDataRec.resize(length);
	plainDataRec.insert(plainDataRec.begin(), receiveWrapper.data(), receiveWrapper.data() + receiveWrapper.size());
	return plainDataRec.size(); 
}
int SecureChannel::receiveSecure(std::vector<uint8_t> &plainDataRec,const int length)
{
	int received = 0; 
	std::string receive; 
	std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("AES-128/GCM", Botan::DECRYPTION);
	dec->set_key(this->myChannelKey.data() , AESMACSIZE);
	received = this->myClient.receiveIn(receive, (length + AESIVSIZE + AESMACSIZE));
	if (received !=  (length+ AESIVSIZE + AESMACSIZE))
	{
		return received; 
	}
	else if (received == SOCKET_ERROR)
	{
		return -1;
	}
	else
	{
		dec->start(std::vector<uint8_t>(receive.data(), receive.data()+ AESIVSIZE));
		Botan::secure_vector<uint8_t> pt(receive.data() + AESIVSIZE, receive.data() + AESMACSIZE + AESIVSIZE + length);
		dec->finish(pt);
		plainDataRec.insert(plainDataRec.begin(), pt.data(), pt.data() + pt.size());
		return plainDataRec.size();
	}
 
}
