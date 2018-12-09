#pragma once
#include "botan/auto_rng.h"
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/cipher_mode.h>

bool authorizationCheck(const std::string &userID, const std::string &log, std::string &response);
int authenticationCheck(const std::vector<uint8_t> &message, const std::vector<uint8_t> &signatureTsGb, Botan::AlgorithmIdentifier algo);
bool accountingAppend(std::string userID, const std::string &log);
bool authorizationCheck(const int &userID,const  std::string &TDK);
bool setPublicClientKeys(int ID,const std::vector<char> &pub);