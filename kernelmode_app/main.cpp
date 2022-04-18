#include "hook.h"

extern "C" NTSTATUS EntryPoint(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) 
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);

	DbgPrintEx(0, 0, "unk4hook driver loaded\n");


	if (unk4hook::call_kernel_function(&unk4hook::hook_handler)) {
		DbgPrintEx(0,0,"Kernel function success hooked\n");
	}
	else {
		DbgPrintEx(0, 0, "Kernel function failed hooked\n");
	}



	return STATUS_SUCCESS;

}