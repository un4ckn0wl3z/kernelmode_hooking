#include "hook.h"

bool unk4hook::call_kernel_function(void* kernel_function_address) 
{
	DbgPrintEx(0, 0, "call_kernel_function called\n");

	if (!kernel_function_address) return false;

	PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys",
		"NtQueryCompositionSurfaceStatistics"));

	if (!function) return false;

	BYTE orig[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	BYTE shell_code[] = 
	{
		0x48, 0xB8 // mov rax, <byte>
	};

	BYTE shell_code_end[] =
	{
		0xFF, 0xE0 // jmp rax
	};

	RtlSecureZeroMemory(&orig, sizeof(orig));
	memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));
	uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address);
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));

	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*) ), &shell_code_end, sizeof(shell_code_end));

	write_to_read_only_memory(function, &orig, sizeof(orig));

	DbgPrintEx(0, 0, "call_kernel_function end\n");


	return true;

}

NTSTATUS unk4hook::hook_handler(PVOID called_param) 
{
	DbgPrintEx(0, 0, "hook_handler called\n");

	UNK4_MEMORY* instructions = (UNK4_MEMORY*)called_param;

	if (instructions->req_base == TRUE) {

		DbgPrintEx(0, 0, "instructions->req_base processing\n");

		ANSI_STRING AS;
		UNICODE_STRING ModuleName;

		RtlInitAnsiString(&AS, instructions->module_name);
		RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);

		PEPROCESS process;
		PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
		ULONG64 base_address64 = NULL;

		base_address64 = get_module_base_x64(process, ModuleName);
		instructions->base_address = base_address64;
		RtlFreeUnicodeString(&ModuleName);

		DbgPrintEx(0, 0, "instructions->req_base finished\n");

		
	}
	else if (instructions->write == TRUE) 
	{
		DbgPrintEx(0, 0, "instructions->write processing\n");

		if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0) 
		{
			PVOID kernelBuff = ExAllocatePool(NonPagedPool, instructions->size);
			if (!kernelBuff) 
			{
				return STATUS_UNSUCCESSFUL;
			}

			if (!memcpy(kernelBuff, instructions->buffer_address, instructions->size))
			{
				return STATUS_UNSUCCESSFUL;
			}
			PEPROCESS process;
			PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
			write_kernel_memory((HANDLE)instructions->pid, instructions->address, kernelBuff, instructions->size);
			ExFreePool(kernelBuff);
		}


		DbgPrintEx(0, 0, "instructions->write finished\n");

	}
	else if (instructions->read == TRUE)
	{
		DbgPrintEx(0, 0, "instructions->read processing\n");

		if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0)
		{
			read_kernel_memory((HANDLE)instructions->pid, instructions->address, instructions->output, instructions->size);
		}

		DbgPrintEx(0, 0, "instructions->read finished\n");

	}

	return STATUS_SUCCESS;
}

