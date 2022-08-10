#pragma once

extern "C"
{
	#include "socketsetup/ksock.h"
	#include "socketsetup/sock.h"
}

typedef int SOCKET;

#define INVALID_SOCKET  (SOCKET)(-1)
#define SOCKET_ERROR            (-1)