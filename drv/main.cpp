#include "misc/log.h"
#include "misc/spoofs.h"

extern void NTAPI server_thread(void*);

extern "C" NTSTATUS DriverEntry() {
	SPOOF_FUNC;
	HANDLE handle_a = nullptr;

	const auto status = PsCreateSystemThread(&handle_a,GENERIC_ALL,nullptr,nullptr,nullptr,server_thread,nullptr);

	if (!NT_SUCCESS(status))
	{
		return STATUS_UNSUCCESSFUL;
	}

	ZwClose(handle_a);
	return STATUS_SUCCESS;
}