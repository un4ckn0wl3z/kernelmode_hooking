#pragma once
#include "memory.h"

namespace unk4hook 
{
	bool call_kernel_function(void* kernel_function_address);
	NTSTATUS hook_handler(PVOID called_param);

}