#pragma once
#define MAX_SIZE 100000
#include <fstream>
#include <vector>
#include "botan\sha2_32.h"
#include "Ethernet.h"
/*	The action type defines if a read or write access is executed.*/
void loggingServer(std::string logRecord);
class LoggingStorage
{
private:
	const std::string Path = "../LogStorage.txt";
public:
	bool writeLogRecord(const std::string &log);
};
class LoggingRecord
{
private:
	std::string timeStamp;									//Unix time
	std::string hostID;								//cpu id 
	std::string fileName;							//file name
	std::string versionNumber;							//file version
	std::string documentSize;									//file size
	std::string action;									//Read or write access
	bool valid = false; 
	bool logSaved = false;
public:
	LoggingRecord(std::string logRecord);
	int createResponse(std::string &response);
	std::string getLogRecord();
	void setLogSaved(bool saved) { this->logSaved = saved; }
};