// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//
#pragma once
#define NOMINMAX					//prevent errors in botan lib
#include "targetver.h"
#include <stdio.h>
#include <tchar.h>
#include "Ethernet.h"
#include "Authentication.h"
#include "LoggingServer.h"
#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <chrono>
#include <ctime>
#include "SecureChannel.h"
// TODO: reference additional headers your program requires here
