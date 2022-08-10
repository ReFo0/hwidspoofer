#include <ntifs.h>
#include "shared/shared.h"
#include "sockets.h"
#include "misc/windows_import.h"
#include "misc/log.h"
#include <ntimage.h>
#include "mem/utils.h"
#include "cacheclean/cacheclean.h"
#include "misc/spoofs.h"



bool complete_request(const SOCKET client_connection, const uint64_t result)
{
	SPOOF_FUNC;
	Packet packet{ };
	packet.header.magic = packet_magic;
	packet.header.type = PacketType::socket_completed;
	packet.data.completed.result = result;

	return send(client_connection, &packet, sizeof(packet), 0) != SOCKET_ERROR;
}






void DisableSmartBit(PRAID_UNIT_EXTENSION extension)
{
	extension->_Smart.Telemetry.SmartMask = 0;
}


PDEVICE_OBJECT GetRaidDevice(const wchar_t* deviceName)
{
	SPOOF_FUNC;
	UNICODE_STRING raidPort;
	RtlInitUnicodeString(&raidPort, deviceName);

	PFILE_OBJECT fileObject = nullptr;
	PDEVICE_OBJECT deviceObject = nullptr;
	auto status = IoGetDeviceObjectPointer(&raidPort, FILE_READ_DATA, &fileObject, &deviceObject);
	if (!NT_SUCCESS(status))
	{
		return nullptr;
	}

	return deviceObject->DriverObject->DeviceObject; 
}


NTSTATUS LoopDisk(PDEVICE_OBJECT deviceArray, RaidUnitRegisterInterfaces registerInterfaces)
{
	SPOOF_FUNC;
	auto status = STATUS_NOT_FOUND;

	while (deviceArray->NextDevice)
	{
		if (deviceArray->DeviceType == FILE_DEVICE_DISK)
		{
			auto* extension = static_cast<PRAID_UNIT_EXTENSION>(deviceArray->DeviceExtension);
			if (!extension)
				continue;

			const auto length = extension->_Identity.Identity.SerialNumber.Length;
			if (!length)
				continue;

			char original[256];
			memcpy(original, extension->_Identity.Identity.SerialNumber.Buffer, length);
			original[length] = '\0';

			auto* buffer = static_cast<char*>(ExAllocatePoolWithTag(NonPagedPool, length, 0));
			buffer[length] = '\0';

			Utils::RandomText(buffer, length);
			RtlInitString(&extension->_Identity.Identity.SerialNumber, buffer);


			status = STATUS_SUCCESS;
			ExFreePool(buffer);

			DisableSmartBit(extension);

			registerInterfaces(extension);
		}

		deviceArray = deviceArray->NextDevice;
	}

	return status;
}





NTSTATUS ChangeDiskSerials()
{
	SPOOF_FUNC;
	auto* base = Utils::GetModuleBase("storport.sys");
	if (!base)
	{
		return STATUS_UNSUCCESSFUL;
	}

	const auto registerInterfaces = static_cast<RaidUnitRegisterInterfaces>(Utils::FindPatternImage(base, "\x48\x89\x5C\x24\x00\x55\x56\x57\x48\x83\xEC\x50", "xxxx?xxxxxxx")); 
	if (!registerInterfaces)
	{
		return STATUS_UNSUCCESSFUL;
	}

	

	auto status = STATUS_NOT_FOUND;
	for (auto i = 0; i < 2; i++)
	{
		const auto* raidFormat = L"\\Device\\RaidPort%d";
		wchar_t raidBuffer[18];
		RtlStringCbPrintfW(raidBuffer, 18 * sizeof(wchar_t), raidFormat, i);

		auto* device = GetRaidDevice(raidBuffer);
		if (!device)
			continue;

		const auto loopStatus = LoopDisk(device, registerInterfaces);
		if (NT_SUCCESS(loopStatus))
			status = loopStatus;
	}

	return status;
}

extern "C" POBJECT_TYPE * IoDriverObjectType;


NTSTATUS DisableSmart()
{
	SPOOF_FUNC;
	auto* base = Utils::GetModuleBase("disk.sys");
	if (!base)
	{
		return STATUS_UNSUCCESSFUL;
	}

	const auto disableFailurePrediction = static_cast<DiskEnableDisableFailurePrediction>(Utils::FindPatternImage(base, "\x4C\x8B\xDC\x49\x89\x5B\x10\x49\x89\x7B\x18\x55\x49\x8D\x6B\xA1\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x33\xC4\x48\x89\x45\x4F", "xxxxxxxxxxxxxxxxxxx????xxx????xxxxxxx"));
	if (!disableFailurePrediction)
	{
		return STATUS_UNSUCCESSFUL;
	}

	UNICODE_STRING driverDisk;
	RtlInitUnicodeString(&driverDisk, L"\\Driver\\Disk");

	PDRIVER_OBJECT driverObject = nullptr;
	auto status = ObReferenceObjectByName(&driverDisk, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, reinterpret_cast<PVOID*>(&driverObject));
	if (!NT_SUCCESS(status))
	{
	
		return STATUS_UNSUCCESSFUL;
	}

	PDEVICE_OBJECT deviceObjectList[64];
	RtlZeroMemory(deviceObjectList, sizeof(deviceObjectList));

	ULONG numberOfDeviceObjects = 0;
	status = IoEnumerateDeviceObjectList(driverObject, deviceObjectList, sizeof(deviceObjectList), &numberOfDeviceObjects);
	if (!NT_SUCCESS(status))
	{
		
		return STATUS_UNSUCCESSFUL;
	}

	for (ULONG i = 0; i < numberOfDeviceObjects; ++i)
	{
		auto* deviceObject = deviceObjectList[i];
		disableFailurePrediction(deviceObject->DeviceExtension, false);
		ObDereferenceObject(deviceObject);
	}

	ObDereferenceObject(driverObject);
	return STATUS_SUCCESS;
}









static uintptr_t ready_spoof()
{
	SPOOF_FUNC;
	DisableSmart();
	ChangeDiskSerials();
	log("spoofed pc refo <3");
	return 1;
}



uintptr_t handle_incoming_packet(const Packet& packet)
{
	switch (packet.header.type)
	{
	case PacketType::socket_clean_piddbcachetable:
		return clean_piddb_cache();

	case PacketType::socket_clean_mmunloadeddrivers:
		return clean_unloaded_drivers();

	case PacketType::socket_spoof_drives:
		return ready_spoof();

	default:
		break;
	}

	return uint64_t(STATUS_NOT_IMPLEMENTED);
}
