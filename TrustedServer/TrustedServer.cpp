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
	auto& sock = Ethernet::getInstance();
	trustedServerManagement unit;
	/*Remote Attestation and Channel Key Exchange*/ 
	//Das muss noch fertig gemacht werden 
	//	ra_proc1();
	std::string message;
	int result = 0;
	std::cout << "Socket is established" << std::endl; 
	while (1)
	{
		trustedServerManagement unit;
		//	ra_proc1();
		std::string message;
		result = 0;
		/*Wait for Client*/
		sock.acceptClient();
		std::cout << "Client accepted!" << std::endl; 
		do
		{
			/*Receive message from socket*/
			result = sock.receiveIn(message, 101);
			/*Check Authenticated*/
			//Das wird vermutlich schon in der Remote attestation gemacht. Sobald die implementiert ist muss ich hierrüber nochmal nachdenken. 
			unit.AUTHENTICATED = true;
			/*Chek Authorization*/
			//Hier soll sowas wie darf der User Lesen, schreiben etc. 
			unit.AUTHORIZED = true;
			/*Add a new client*/
			//Momentan nur 1 Client, daher nur als Dummy für ein größeres System.
			if (message.at(0) == 'A')
			{

			}
			/*TDK Distribution*/
			else if (message.at(0) == 'K')
			{
				std::cout << "\nKey requested!" << std::endl; 
				if (unit.AUTHENTICATED == true && unit.AUTHORIZED == true)
				{
					distributionTDK();
				}
			}
			else if (message.at(0) == 'L')
			{
				std::cout << "\nLogging Record received!" << std::endl;
				/*Store Logging Record*/
				if (unit.AUTHENTICATED == true && unit.AUTHORIZED == true)
				{
					loggingServer(message);
				}
				else
				{//Send Invalid Flag
					sock.sendOut("0");
				}
			}
		} while (result > 0);
		sock.removeClient();
		//getchar();
	}
    return 0;
}

