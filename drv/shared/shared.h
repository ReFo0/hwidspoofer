#pragma once
#include "stdint.h"

constexpr auto packet_magic = 0x82345523;
constexpr auto server_ip = 0x7F000001; // 127.0.0.1 converted hex
constexpr auto server_port = 28221; // Socket Port 

enum class PacketType
{
	socket_clean_piddbcachetable,
	socket_clean_mmunloadeddrivers,
	socket_spoof_drives,
	socket_completed
};




struct PacketCleanPiDDBCacheTable {
};

struct PacketCleanMMUnloadedDrivers {
};

struct PacketSpoofDrives {
};

struct PackedCompleted
{
	uint64_t result;
};

struct PacketHeader
{
	uint32_t   magic;
	PacketType type;
};

struct Packet
{
	PacketHeader header;
	union
	{
		PacketCleanPiDDBCacheTable clean_piddbcachetable;
		PacketCleanMMUnloadedDrivers clean_mmunloadeddrivers;
		PacketSpoofDrives	 spoof_drives;
		PackedCompleted		 completed;
	} data;
};
