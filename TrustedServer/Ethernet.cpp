#include "stdafx.h"
#include "Ethernet.h"
#define DEFAULT_PORT "9090"
#define DEFAULT_BUFLEN 512
Ethernet::Ethernet()
{
	int res = 0;
	res = initializeSocket();
	if (res)
	{
		this->sockInitialized = true;
	}
}
Ethernet& Ethernet::getInstance()
{
	static Ethernet instance;
	return instance;
}
int Ethernet::initializeSocket()
{
	WSADATA wsaData;
	int iResult;

	struct addrinfo *result = NULL;
	struct addrinfo hints;

	int iSendResult;
	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen = DEFAULT_BUFLEN;


	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}
	// Create a SOCKET for connecting to server
	myListenSock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (myListenSock == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket
	iResult = bind(myListenSock, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(myListenSock);
		WSACleanup();
		return 1;
	}

//	freeaddrinfo(result);

	iResult = listen(myListenSock, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(myListenSock);
		WSACleanup();
		return 1;
	}
	// Accept a client socket
	//this->myClientSock= accept(myListenSock, NULL, NULL);
	//if (this->myClientSock == INVALID_SOCKET) {
	//	printf("accept failed with error: %d\n", WSAGetLastError());
	//	closesocket(myListenSock);
	//	WSACleanup();
	//	return 1;
	//}
	return 1;
}
int Ethernet::acceptClient()
{
	// Accept a client socket
	this->myClientSock = accept(myListenSock, NULL, NULL);
	if (this->myClientSock == INVALID_SOCKET) {
		printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(myListenSock);
		WSACleanup();
		return 1;
	}
	return 1; 
}
int Ethernet::removeClient()
{
	int iResult;
	// shutdown the connection since we're done
	iResult = shutdown(this->myClientSock, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(this->myClientSock);
		WSACleanup();
		return 1;
	}
	//// cleanup
	closesocket(this->myClientSock);
	this->myClientSock = 0;
	//WSACleanup();
	return 1; 
}
int Ethernet::sendOut(const std::string &buf)
{
	int socketResult = 0;
	socketResult = send(this->myClientSock, buf.c_str(), buf.size(), 0);
	if (socketResult == SOCKET_ERROR)
	{
		printf("send failed: %d\n", WSAGetLastError());
		return 0;
	}
	printf("Bytes send: %d\n", socketResult);
	return socketResult;
}
int Ethernet::receiveIn(std::string &buf, int length)
{
	char* buffer;
	buffer = new char[length];
	int socketResult = 0;
	socketResult = recv(this->myClientSock, buffer, length, 0);
	if (socketResult > 0)
	{
		printf("Bytes received: %d\n", socketResult);
		buf = std::string(buffer, socketResult);
	}
	else if (socketResult == SOCKET_ERROR)
	{
		printf("Received failed : %d\n", WSAGetLastError());
		delete[] buffer;
		return -1;
	}
	delete[] buffer;
	return socketResult;
}
int Ethernet::closeSocket()
{
	if (closesocket(this->myClientSock) != 0)
	{
		printf("Client: Cannot close \"this->mySocket\" socket. Error code: %ld\n", WSAGetLastError());
		return 0;
	}
	else
	{
		printf("Client: Closing \"this->mySocket\" socket...\n");
	}
	// When your application is finished handling the connection, call WSACleanup.
	if (WSACleanup() != 0)
	{
		printf("Client: WSACleanup() failed!...\n");
		return 0;
	}
	else
	{
		printf("Client: WSACleanup() is OK...\n");
		return 1;
	}
}
Ethernet::~Ethernet()
{
	int res = 0;
	res = closeSocket();
	if (res)
	{
		this->sockInitialized = false;
	}
}