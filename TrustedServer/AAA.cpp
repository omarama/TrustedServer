#include "stdafx.h"
#include "AAA.h"
std::vector<uint8_t> Client1Pub;//= Botan::hex_decode("041df3f8fdd2036ee2554fa3bc0d5bd5560a4d01b5f0ac94f9aae9b1f798fa259e09b359d32d89a7888dbc4560e4f29687c800f9a1c69a34d4e9a2f1b970e8c592");
bool authorizationCheck(const std::string &userID, const std::string &log, std::string &response )
{
	if (userID.at(0) == '2')
	{
		std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create("SHA-256"));
		hash->update(log);
		Botan::secure_vector<uint8_t> resp = hash->final();
		response.insert(response.begin(), resp.data(), resp.data() + resp.size());
		return true; 
	}
	else
	{
		return false;
	}
}
bool authorizationCheck(const int &userID, const std::string &TDK)
{
	if (TDK == "TDK" && userID == 2)
	{
		return true;
	}
	else
	{
		return false;
	}
}

int authenticationCheck(const std::vector<uint8_t> &message, const std::vector<uint8_t> &signature, Botan::AlgorithmIdentifier algo)
{
	Botan::AutoSeeded_RNG rng;
	Botan::ECDSA_PublicKey client1(algo , Client1Pub);
	Botan::PK_Verifier verify( client1, "EMSA1(SHA-256)");
	bool key = client1.check_key(rng,1);

	verify.update(message);
	bool sigCheck = verify.check_signature(signature);
	if (sigCheck == true)
	{
		/*Return ID*/
		return 2; 
	}
	else
	{
		return -1; 
	}
}
bool accountingAppend(std::string userID, const std::string &log)
{
	std::ofstream bigFile;
	std::string Path = "../LogStorageID";
	Path.append(userID.data(),1);
	Path.append(".txt");
	bigFile.open(Path, std::ios::app);
	if (bigFile.is_open())
	{
		std::string temp(log, 10, 10);
		int time = atoi(temp.c_str());
		time_t t = time;
		struct tm *buf;
		char str[26];
		buf = gmtime(&t);
		buf->tm_hour += 1;   //German time
		asctime_s(str, sizeof str, buf);

		//printf("local: %s", str);
		bigFile.write(str, 26);
		bigFile.write(log.c_str(), 100);
		bigFile.write("\n", 1);
		bigFile.close();
		return true;
	}
	else
	{
		printf("Cannot write file!\n");
		return false;
	}
}
bool setPublicClientKeys(int ID,const std::vector<char> &pub)
{

	for (int i = 0; i < 65; i++)
	{
		Client1Pub.push_back(pub.at(i));
	}
	return true; 
}