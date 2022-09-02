#include <ntifs.h>
#include "shared/shared.h"
#include "sockets.h"
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





NTSTATUS DiskSerials()
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






NTSTATUS ProcessTable(SMBIOS_HEADER* header)
{
	SPOOF_FUNC;
	if (!header->Length)
		return STATUS_UNSUCCESSFUL;

	if (header->Type == 0)
	{
		auto* type0 = reinterpret_cast<SMBIOS_TYPE0*>(header);

		auto* vendor = Utils::GetString(header, type0->Vendor);
		Utils::RandomizeString(vendor);
	}

	if (header->Type == 1)
	{
		auto* type1 = reinterpret_cast<SMBIOS_TYPE1*>(header);

		auto* manufacturer = Utils::GetString(header, type1->Manufacturer);
		Utils::RandomizeString(manufacturer);

		auto* productName = Utils::GetString(header, type1->ProductName);
		Utils::RandomizeString(productName);

		auto* serialNumber = Utils::GetString(header, type1->SerialNumber);
		Utils::RandomizeString(serialNumber);
	}

	if (header->Type == 2)
	{
		auto* type2 = reinterpret_cast<SMBIOS_TYPE2*>(header);

		auto* manufacturer = Utils::GetString(header, type2->Manufacturer);
		Utils::RandomizeString(manufacturer);

		auto* productName = Utils::GetString(header, type2->ProductName);
		Utils::RandomizeString(productName);

		auto* serialNumber = Utils::GetString(header, type2->SerialNumber);
		Utils::RandomizeString(serialNumber);
	}

	if (header->Type == 3)
	{
		auto* type3 = reinterpret_cast<SMBIOS_TYPE3*>(header);

		auto* manufacturer = Utils::GetString(header, type3->Manufacturer);
		Utils::RandomizeString(manufacturer);

		auto* serialNumber = Utils::GetString(header, type3->SerialNumber);
		Utils::RandomizeString(serialNumber);
	}

	return STATUS_SUCCESS;
}


NTSTATUS LoopTables(void* mapped, ULONG size)
{
	auto* endAddress = static_cast<char*>(mapped) + size;
	while (true)
	{
		auto* header = static_cast<SMBIOS_HEADER*>(mapped);
		if (header->Type == 127 && header->Length == 4)
			break;

		ProcessTable(header);
		auto* end = static_cast<char*>(mapped) + header->Length;
		while (0 != (*end | *(end + 1))) end++;
		end += 2;
		if (end >= endAddress)
			break;

		mapped = end;
	}

	return STATUS_SUCCESS;
}

NTSTATUS SmbiosSerials()
{
	SPOOF_FUNC;
	auto* base = Utils::GetModuleBase("ntoskrnl.exe");
	if (!base)
	{
		return STATUS_UNSUCCESSFUL;
	}

	auto* physicalAddress = static_cast<PPHYSICAL_ADDRESS>(Utils::FindPatternImage(base, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15", "xxx????xxxx?xx")); // WmipFindSMBiosStructure -> WmipSMBiosTablePhysicalAddress
	if (!physicalAddress)
	{
		return STATUS_UNSUCCESSFUL;
	}

	physicalAddress = reinterpret_cast<PPHYSICAL_ADDRESS>(reinterpret_cast<char*>(physicalAddress) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(physicalAddress) + 3));
	if (!physicalAddress)
	{
		return STATUS_UNSUCCESSFUL;
	}

	auto* sizeScan = Utils::FindPatternImage(base, "\x8B\x1D\x00\x00\x00\x00\x48\x8B\xD0\x44\x8B\xC3\x48\x8B\xCD\xE8\x00\x00\x00\x00\x8B\xD3\x48\x8B", "xx????xxxxxxxxxx????xxxx");  // WmipFindSMBiosStructure -> WmipSMBiosTableLength
	if (!sizeScan)
	{
		return STATUS_UNSUCCESSFUL;
	}

	const auto size = *reinterpret_cast<ULONG*>(static_cast<char*>(sizeScan) + 6 + *reinterpret_cast<int*>(static_cast<char*>(sizeScan) + 2));
	if (!size)
	{
		return STATUS_UNSUCCESSFUL;
	}

	auto* mapped = MmMapIoSpace(*physicalAddress, size, MmNonCached);
	if (!mapped)
	{
		return STATUS_UNSUCCESSFUL;
	}

	LoopTables(mapped, size);

	MmUnmapIoSpace(mapped, size);

	return STATUS_SUCCESS;
}



static uintptr_t ready_spoof()
{
	SPOOF_FUNC;
	DisableSmart();
	DiskSerials();
	SmbiosSerials();
	log("spoofed pc refo <3");
	return 1;
}



uintptr_t handle_incoming_packet(const Packet& packet)
{
	SPOOF_FUNC;
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
