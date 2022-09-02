#include "driver.h"
#include "shared.h"

#pragma comment(lib, "Ws2_32")

static bool send_packet(const SOCKET	connection,const Packet& packet,uint64_t& out_result)
{
	Packet completion_packet{ };

	if (send(connection, (const char*)&packet, sizeof(Packet), 0) == socket_error)
		return false;

	const auto result = recv(connection, (char*)&completion_packet, sizeof(Packet), 0);
	if (result < sizeof(PacketHeader) || completion_packet.header.magic != packet_magic || completion_packet.header.type != PacketType::socket_completed)
		return false;

	out_result = completion_packet.data.completed.result;
	return true;
}


void driver::init()
{
	WSADATA wsa_data;
	WSAStartup(MAKEWORD(2, 2), &wsa_data);
}

void driver::deinit()
{
	WSACleanup();
}

SOCKET driver::connect()
{
	SOCKADDR_IN address{ };

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(server_ip);
	address.sin_port = htons(server_port);

	const auto connection = socket(AF_INET, SOCK_STREAM, 0);
	if (connection == INVALID_SOCKET)
		return INVALID_SOCKET;

	if (connect(connection, (SOCKADDR*)&address, sizeof(address)) == SOCKET_ERROR)
	{
		closesocket(connection);
		return INVALID_SOCKET;
	}

	return connection;
}

void driver::disconnect(const SOCKET connection)
{
	closesocket(connection);
}


uintptr_t driver::clean_cachetable(const SOCKET connection)
{
	Packet packet{ };

	packet.header.magic = packet_magic;
	packet.header.type = PacketType::socket_clean_piddbcachetable;

	auto& data = packet.data.clean_piddbcachetable;

	uint64_t result = 0;
	if (send_packet(connection, packet, result))
		return 1;

	return 0;
}

uintptr_t driver::clean_unloaddrivers(const SOCKET connection)
{
	Packet packet{ };

	packet.header.magic = packet_magic;
	packet.header.type = PacketType::socket_clean_mmunloadeddrivers;

	auto& data = packet.data.clean_mmunloadeddrivers;

	uint64_t result = 0;
	if (send_packet(connection, packet, result))
		return 1;

	return 0;
}

uintptr_t driver::spoof_computer(const SOCKET connection)
{
	Packet packet{ };

	packet.header.magic = packet_magic;
	packet.header.type = PacketType::socket_completed;

	auto& data = packet.data.spoof_drives;

	uint64_t result = 0;
	if (send_packet(connection, packet, result))
		return 1;

	return 0;
}


