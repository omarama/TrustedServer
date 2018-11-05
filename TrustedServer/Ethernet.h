#pragma comment(lib, "Ws2_32.lib")
#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS 
//#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsock.h>
#include <iostream>
#include <vector>
class Ethernet
{
private:
	const int myPort = 9090;
	const std::string myServer = "127.0.0.1";
	SOCKET myListenSock = INVALID_SOCKET;
	SOCKET myClientSock=INVALID_SOCKET;
	bool sockInitialized = false;
	bool client = false; 
	Ethernet();
	~Ethernet();
public:
	// singleton
	int acceptClient();
	int removeClient();
	static Ethernet& getInstance();
	int initializeSocket();
	int closeSocket();
	int sendOut(const std::string &buf);
	int receiveIn(std::string &buf, int length);
	/*Getter*/
	bool getSockInitialzied() { return this->sockInitialized; }
};