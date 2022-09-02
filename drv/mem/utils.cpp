#include <ntifs.h>
#include <windef.h>
#include <ntimage.h>
#include "utils.h"


PVOID Utils::GetModuleBase(const char* moduleName)
{
	PVOID address = nullptr;
	ULONG size = 0;
	
	auto status = ZwQuerySystemInformation(SystemModuleInformation, &size, 0, &size);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return nullptr;

	auto* moduleList = static_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePoolWithTag(NonPagedPool, size, 0));
	if (!moduleList)
		return nullptr;

	status = ZwQuerySystemInformation(SystemModuleInformation, moduleList, size, nullptr);
	if (!NT_SUCCESS(status))
		goto end;

	for (auto i = 0; i < moduleList->ulModuleCount; i++)
	{
		auto module = moduleList->Modules[i];
		if (strstr(module.ImageName, moduleName))
		{
			address = module.Base;
			break;
		}
	}
	
end:
	ExFreePool(moduleList);
	return address;
}



bool Utils::CheckMask(const char* base, const char* pattern, const char* mask)
{
	for (; *mask; ++base, ++pattern, ++mask) 
	{
		if ('x' == *mask && *base != *pattern) 
		{
			return false;
		}
	}

	return true;
}


PVOID Utils::FindPattern(PVOID base, int length, const char* pattern, const char* mask)
{
	length -= static_cast<int>(strlen(mask));
	for (auto i = 0; i <= length; ++i) 
	{
		const auto* data = static_cast<char*>(base);
		const auto* address = &data[i];
		if (CheckMask(address, pattern, mask))
			return PVOID(address);
	}

	return nullptr;
}


PVOID Utils::FindPatternImage(PVOID base, const char* pattern, const char* mask)
{
	PVOID match = nullptr;

	auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<char*>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
	auto* sections = IMAGE_FIRST_SECTION(headers);
	
	for (auto i = 0; i < headers->FileHeader.NumberOfSections; ++i) 
	{
		auto* section = &sections[i];
		if ('EGAP' == *reinterpret_cast<PINT>(section->Name) || memcmp(section->Name, ".text", 5) == 0) 
		{
			match = FindPattern(static_cast<char*>(base) + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (match) 
				break;
		}
	}

	return match;
}


void Utils::RandomText(char* text, const int length)
{
	if (!text)
		return;

	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	auto seed = KeQueryTimeIncrement();

	for (auto n = 0; n <= length; n++)
	{
		auto key = RtlRandomEx(&seed) % static_cast<int>(sizeof(alphanum) - 1);
		text[n] = alphanum[key];
	}
}




char* Utils::GetString(SMBIOS_HEADER* header, SMBIOS_STRING string)
{
	const auto* start = reinterpret_cast<const char*>(header) + header->Length;

	if (!string || *start == 0)
		return nullptr;

	while (--string)
	{
		start += strlen(start) + 1;
	}

	return const_cast<char*>(start);
}


void Utils::RandomizeString(char* string)
{
	const auto length = static_cast<int>(strlen(string));

	auto* buffer = static_cast<char*>(ExAllocatePoolWithTag(NonPagedPool, length, 'ref0'));
	Utils::RandomText(buffer, length);
	buffer[length] = '\0';

	memcpy(string, buffer, length);

	ExFreePool(buffer);
}
