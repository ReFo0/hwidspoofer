#pragma once
#include <WinSock2.h>
#include <cstdint>

#define socket_connected 1
#define socket_failed ~0
#define socket_error -1

namespace driver
{
	void	init();
	void	deinit();

	SOCKET	connect();
	void	disconnect(SOCKET connection);

	uintptr_t clean_cachetable(SOCKET connection);
	uintptr_t clean_unloaddrivers(SOCKET connection);
	uintptr_t spoof_computer(SOCKET connection);
}

