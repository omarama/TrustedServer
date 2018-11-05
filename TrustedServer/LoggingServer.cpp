#include "stdafx.h"
#include "LoggingServer.h"
/*Logging Block*/
void loggingServer(std::string logRecord)
{
	auto& sock= Ethernet::getInstance();
	bool ret = false; 
	std::string response;
	LoggingRecord logRec(logRecord);
	LoggingStorage logStore;
	ret = logStore.writeLogRecord(logRec.getLogRecord());
	if (ret)
	{
		logRec.setLogSaved(true);
	}
	else
	{
		logRec.setLogSaved(false);
	}
	ret = logRec.createResponse(response);
	sock.sendOut(response);
}
/*Logging Storage Class*/
bool LoggingStorage::writeLogRecord(const std::string &log)
{
	std::ofstream bigFile;
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
		
		printf("local: %s", str);
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
/*Logging Record Class*/
LoggingRecord::LoggingRecord(std::string logRecord) : 
	fileName(logRecord.substr(73,18)) , 
	versionNumber(logRecord.substr(59,10)) , 
	documentSize(logRecord.substr(45,10)), 
	hostID(logRecord.substr(31,10)), 
	action (logRecord.substr(28,1)),
	timeStamp(logRecord.substr(11,10))
{

}
/*Create Response Message*/
//Ist nat�rlich ausreichen, da der Inhalt sp�ter �ber den trusted Channel gesichert ist. Soll allerdings trotzdem noch mehr in die response ? 
int LoggingRecord::createResponse(std::string &resp)
{
	if (this->logSaved)
	{
		resp.replace(0, 1, "1");
		return 1; 
	}
	else
	{
		resp.replace(0, 1, "0");
		return 0; 
	}
}
/*Logging record structure
0 - 6						"LOGREC"
7 -	10						"TIME"
11 - 20						Unixtime
21 - 25						"ACTION"
26 - 26						act
27 - 28						"ID"
29 - 38						id
39 - 42						"SIZE"
43 - 52						filesize
53 - 56						"VERS"
57 - 66						verion
67 - 70						"NAME"
71 - 90						name
*/
std::string LoggingRecord::getLogRecord()
{
	std::string templ = "";
	std::string loggingRec(100, ' ');
	loggingRec.replace(0, 6, "LOGREC");
	loggingRec.replace(6, 4, "TIME");
	loggingRec.replace(10, this->timeStamp.size(), this->timeStamp);
	loggingRec.replace(21, 6, "ACTION");
	loggingRec.replace(27, 1, this->action);
	loggingRec.replace(28, 2, "ID");
	loggingRec.replace(30, this->hostID.size(), this->hostID);
	loggingRec.replace(40, 4, "SIZE");
	loggingRec.replace(44, this->documentSize.size(), this->documentSize);
	loggingRec.replace(54, 4, "VERS");
	loggingRec.replace(58, this->versionNumber.size(), this->versionNumber);
	loggingRec.replace(68, 4, "NAME");
	loggingRec.replace(72, this->fileName.size(), this->fileName);
	for (int i = loggingRec.size(); i < 100; i++)
	{
		loggingRec.replace(i, 1, " ");
	}
	return loggingRec;
}