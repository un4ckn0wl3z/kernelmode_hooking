#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <memory>
#include <string_view>
#include <cstdint>
#include <vector>

typedef struct _UNK4_MEMORY
{
	void* buffer_address;
	UINT_PTR address;
	ULONGLONG size;
	ULONG pid;
	BOOLEAN write;
	BOOLEAN read;
	BOOLEAN req_base;
	void* output;
	const char* module_name;
	ULONG64 base_address;
} UNK4_MEMORY;

uintptr_t base_address = 0;
std::uint32_t process_id = 0;

template<typename ... Arg>
uint64_t call_hook(const Arg ... args) 
{
	void* hooked_func = GetProcAddress(LoadLibrary("win32u.dll"), "NtQueryCompositionSurfaceStatistics");
	auto func = static_cast<uint64_t(_stdcall*)(Arg...)>(hooked_func);

	return func(args ...);
}

struct HandleDisposer 
{
	using pointer = HANDLE;
	void operator()(HANDLE handle) const 
	{
		if (handle != NULL || handle != INVALID_HANDLE_VALUE) {
			CloseHandle(handle);
		}
	}

};

using unique_handle = std::unique_ptr<HANDLE, HandleDisposer>;

static std::uint32_t get_process_id(std::string_view process_name)
{
	PROCESSENTRY32 process_entry;
	const unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL));

	if (snapshot_handle.get() == INVALID_HANDLE_VALUE) return NULL;

	process_entry.dwSize = sizeof(MODULEENTRY32);

	while (Process32Next(snapshot_handle.get(), &process_entry) == TRUE) {
		if (process_name.compare(process_entry.szExeFile) == NULL) {
			return process_entry.th32ProcessID;
		}
	}
	return NULL;
}

static ULONG64 get_module_base_address(const char* module_name) 
{
	UNK4_MEMORY instructions = { 0 };
	instructions.pid = process_id;
	instructions.req_base = TRUE;
	instructions.read = FALSE;
	instructions.write = FALSE;
	instructions.module_name = module_name;
	call_hook(&instructions);

	ULONG64 base = NULL;
	base = instructions.base_address;
	return base;
}

template<class T>
T read(UINT_PTR read_address)
{
	T response{};
	UNK4_MEMORY instructions;
	instructions.pid = process_id;
	instructions.size = sizeof(T);
	instructions.address = read_address;
	instructions.read = TRUE;
	instructions.write = FALSE;
	instructions.req_base = FALSE;
	instructions.output& response;

	call_hook(&instructions);

	return response;
}

bool write_memory(UINT_PTR write_address, UINT_PTR source_address, SIZE_T write_size)
{
	UNK4_MEMORY instructions;
	instructions.address = write_address;
	instructions.pid = process_id;
	instructions.write = TRUE;
	instructions.read = FALSE;
	instructions.req_base = FALSE;
	instructions.buffer_address = (void*)source_address;
	instructions.size = write_size;

	call_hook(&instructions);

	return true;

}

template<typename S>
bool write(UINT_PTR write_address, S& value) 
{
	return write_memory(write_address, (UINT_PTR)&value, sizeof(S));
}

int main() 
{

	process_id = get_process_id("notepad.exe");
	base_address = get_module_base_address("notepad.exe");

	if (!base_address) 
	{
		printf("NAH");
	}
	else {
		printf("GOODA");
	}

	Sleep(5000);
	return 0;

}