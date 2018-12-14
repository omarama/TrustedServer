// TrustedServer.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "time.h"

#include "TDK.h"

struct trustedServerManagement
{
	bool AUTHENTICATED = false;
	bool AUTHORIZED = false;
};

int main()
{
	std::cout << "Start the Trusted Server" << std::endl; 
	std::vector<char> publicKey;
	int publicKeyLength = 64;
	readTxtFile(publicKey,publicKeyLength, "../publicID.txt");
	publicKey.insert(publicKey.begin(), '\x4');
	setPublicClientKeys(2, publicKey);
	auto& sock = Ethernet::getInstance();
	trustedServerManagement unit;
	int result = 0;
	std::cout << "Socket is established\nWaiting for Clients." << std::endl; 
	while (1)
	{
		/*Wait for Client*/
		unit.AUTHENTICATED = false;
		sock.acceptClient();
		std::cout << "\nClient accepted!" << std::endl;
		/*Generate Secure Channel to the client*/
		SecureChannel secureClientChannel(sock);
		std::cout << "Channel Key is generated.\n";
		if (secureClientChannel.getClientID() > 0)
		{
			unit.AUTHENTICATED = true; 
			do
			{
				std::string message;
				unit.AUTHENTICATED = secureClientChannel.getClientAuthenticated();
				/*Receive message from socket*/
				result = secureClientChannel.receiveSecure(message, 1);
				if (result <= 0)
				{
					message.clear();
					result = 0;
					break;
				}
				else if (message.at(0) == 'G')
				{

				}
				/*TDK Distribution*/
				else if (message.at(0) == 'K')
				{
					std::cout << "\nKey requested from Client!" << std::endl;
					unit.AUTHORIZED = authorizationCheck(secureClientChannel.getClientID(), "TDK");
					if (unit.AUTHENTICATED == true && unit.AUTHORIZED == true)
					{
						distributionTDK(secureClientChannel);
					}
					unit.AUTHORIZED = false; 
				}
				else if (message.at(0) == 'L')
				{

					std::cout << "\nLogging received from Client!" << std::endl;
					if (unit.AUTHENTICATED == true)
					{
						loggingServer(message, secureClientChannel);
					}
					else
					{//Send Invalid Flag0
						secureClientChannel.sendSecure("0");
					}
				}
				else
				{
					message.clear();
					result = 0;
					break;
				}

			} while (result > 0);
		}
			sock.removeClient();
		//getchar();
	}
    return 0;
}
bool readTxtFile(std::vector < char> &fileText, int &length, const std::string &fileName)
{
	std::ifstream bigFile(fileName.c_str(), std::ifstream::binary);
	fileText.reserve(MAX_SIZE);

	bigFile.seekg(0, bigFile.end);
	length = bigFile.tellg();
	bigFile.seekg(0, bigFile.beg);
	if (length < MAX_SIZE && length > 0)
	{
		fileText.resize(length);
		bigFile.read(fileText.data(), length);
	}
	else
	{
		length = MAX_SIZE;
		fileText.resize(length);
		bigFile.read(fileText.data(), MAX_SIZE);
	}
	if (bigFile.gcount() == length)
	{
		//std::cout << "The reading size is " << length / 1000 << " kB" << std::endl;
		bigFile.close();
		return true;
	}
	else if (bigFile.gcount() == 0)
	{
		std::cout << "Error: File "<< fileName << " not found!\nPlease check the file.\nPerhaps the ReadMe.txt could help you."<<std::endl;
		bigFile.close();
		return false;
	}
	else
	{
		std::cout << "Error: only " << bigFile.gcount() << " could be read";
		bigFile.close();
		return false;
	}
}