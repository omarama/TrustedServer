#pragma once 
#include "stdafx.h"
#include "TDK.h"

std::vector <uint8_t> mySymmetricKey = { 160,244,87,95,127,6,231,169,133,90,180,107,139,1,232,194 } ;

/*Distribution Block 
distribute the trusted domain keys for the clients
*/
//Kann noch erweitert werden mit verschiedenen symmetrischen Schlüssel für unterschiedliche Level
void distributionTDK()
{
	auto& sock = Ethernet::getInstance();
	char* key = reinterpret_cast<char*>(mySymmetricKey.data());
	sock.sendOut(std::string(key,mySymmetricKey.size()));
}