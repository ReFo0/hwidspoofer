#include "../shared/shared.h"
#include "../sockets.h"
#include "../misc/log.h"
#include "../misc/spoofs.h"
#include "../socketsetup/sock.h"

extern uint64_t handle_incoming_packet(const Packet& packet);
extern bool		complete_request(SOCKET client_connection, uint64_t result);

static SOCKET create_listen_socket()
{
	SPOOF_FUNC;
	SOCKADDR_IN address{ };

	address.sin_family	= AF_INET;
	address.sin_port	= htons(server_port);

	const auto listen_socket = socket_listen(AF_INET, SOCK_STREAM, 0);
	if (listen_socket == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	if (bind(listen_socket, (SOCKADDR*)&address, sizeof(address)) == SOCKET_ERROR)
	{

		closesocket(listen_socket);
		return INVALID_SOCKET;
	}

	if (listen(listen_socket, 10) == SOCKET_ERROR)
	{

		closesocket(listen_socket);
		return INVALID_SOCKET;
	}

	return listen_socket;
}

static void NTAPI connection_thread(void* connection_socket)
{
	SPOOF_FUNC;
	const auto client_connection = SOCKET(ULONG_PTR(connection_socket));

	Packet packet{ };
	while (true)
	{
		const auto result = recv(client_connection, (void*)&packet, sizeof(packet), 0);
		if (result <= 0)
			break;

		if (result < sizeof(PacketHeader))
			continue;

		if (packet.header.magic != packet_magic)
			continue;

		const auto packet_result = handle_incoming_packet(packet);
		if (!complete_request(client_connection, packet_result))
			break;
	}

	closesocket(client_connection);
}

void NTAPI server_thread(void*)
{
	SPOOF_FUNC;
	auto status = KsInitialize();
	if (!NT_SUCCESS(status))
	{
		return;
	}

	const auto listen_socket = create_listen_socket();
	if (listen_socket == INVALID_SOCKET)
	{

		KsDestroy();
		return;
	}


	while (true)
	{
		sockaddr  socket_addr{ };
		socklen_t socket_length{ };

		const auto client_connection = accept(listen_socket, &socket_addr, &socket_length);
		if (client_connection == INVALID_SOCKET)
		{
			break;
		}

		HANDLE thread_handle = nullptr;
		status = PsCreateSystemThread(&thread_handle,GENERIC_ALL,nullptr,nullptr,nullptr,connection_thread,(void*)client_connection);

		if (!NT_SUCCESS(status))
		{

			closesocket(client_connection);
			break;
		}

		ZwClose(thread_handle);
	}

	closesocket(listen_socket);

}