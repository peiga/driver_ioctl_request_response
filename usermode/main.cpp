/**********************************************
					INCLUDES
**********************************************/
#include <Windows.h>
#include <ntstatus.h>
#include <iostream>

/**********************************************
					DEFINES
**********************************************/
#define DebugPrint( content, ... ) DbgPrintEx( 0, 0, "[>] " content, __VA_ARGS__ )
#define IO_MODULE_BASE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_COPY_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0702, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

/**********************************************
					STRUCTS
**********************************************/
typedef struct _KERNEL_MODULE_BASE_REQUEST
{
	ULONG ProcessId;
	PVOID Address;
	size_t Size;
	wchar_t Module[64];
} KERNEL_MODULE_BASE_REQUEST, * PKERNEL_MODULE_BASE_REQUEST;

typedef struct _KERNEL_MODULE_BASE_RESPONSE
{
	NTSTATUS Status;
	PVOID Address;
} KERNEL_MODULE_BASE_RESPONSE, * PKERNEL_MODULE_BASE_RESPONSE;

typedef struct _KERNEL_COPY_REQUEST
{
	ULONG ProcessId;
	PVOID Address;
	PVOID Buffer;
	size_t Size;
} KERNEL_COPY_REQUEST, * PKERNEL_COPY_REQUEST;

typedef struct _KERNEL_COPY_RESPONSE
{
	NTSTATUS Status;
} KERNEL_COPY_RESPONSE, * PKERNEL_COPY_RESPONSE;

/**********************************************
					CLASSES
**********************************************/

class Driver
{
public:
	// Handle to driver
	HANDLE hDriver;

	// Initializer
	Driver(LPCSTR RegistryPath)
	{
		hDriver = CreateFileA(RegistryPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
		if (!hDriver) {
			printf("CreateFileA failed with code: %d\n", GetLastError());
		}
	}

	// ModuleBase
	KERNEL_MODULE_BASE_RESPONSE moduleBase(ULONG ProcessId, const wchar_t* module_name)
	{
		KERNEL_MODULE_BASE_RESPONSE ModuleBaseResponse = {};

		if (!hDriver) {
			printf("hDriver invalid handle!\n");
			ModuleBaseResponse.Status = STATUS_UNSUCCESSFUL;

			return ModuleBaseResponse;
		}

		DWORD Return, Bytes;
		KERNEL_MODULE_BASE_REQUEST ModuleBaseRequest;

		ModuleBaseRequest.ProcessId = ProcessId;
		ModuleBaseRequest.Address = (PVOID)0x1337;
		ModuleBaseRequest.Size = sizeof(PVOID);
		std::wstring w_string = module_name;
		memset(&ModuleBaseRequest.Module[0], 0, 64 * sizeof(wchar_t));
		memcpy(&ModuleBaseRequest.Module[0], const_cast<wchar_t*>(w_string.data()), (std::wcslen(w_string.data()) + 1) * sizeof(wchar_t));

		// send code to our driver with the arguments
		if (DeviceIoControl(hDriver, IO_MODULE_BASE_REQUEST, &ModuleBaseRequest, sizeof(ModuleBaseRequest), &ModuleBaseResponse, sizeof(ModuleBaseResponse), 0, 0)) {

			return ModuleBaseResponse;
		}

		printf("DeviceIoControl failed!\n");

		return ModuleBaseResponse;
	}

	// copy
	KERNEL_COPY_RESPONSE copy(ULONG ProcessId, PVOID ReadAddress, PVOID BufferAddress, SIZE_T Size)
	{
		KERNEL_COPY_RESPONSE response = {};

		if (!hDriver) {
			printf("hDriver invalid handle!\n");
			response.Status = STATUS_UNSUCCESSFUL;

			return response;
		}

		DWORD Return, Bytes = 0;
		KERNEL_COPY_REQUEST request = {};

		request.ProcessId = ProcessId;
		request.Address = ReadAddress;
		request.Buffer = BufferAddress;
		request.Size = Size;

		// send code to our driver with the arguments
		if (DeviceIoControl(hDriver, IO_COPY_REQUEST, &request, sizeof(request), &response, sizeof(response), 0, 0)) {

			return response;
		}

		printf("DeviceIoControl failed!\n");

		return response;
	}

};

/**********************************************
					MAIN
**********************************************/

int main()
{
	// instantiate class
	Driver* driver = new Driver("\\\\.\\drivername");

	// module request
	int pid = 1234;
	std::wstring module_name = L"GameAssembly.dll";
	KERNEL_MODULE_BASE_RESPONSE module_response = driver->moduleBase(pid, module_name.c_str());
	if (module_response.Status != STATUS_SUCCESS) {
		printf("error moduleBase! Status: 0x%p - %d, Address: 0x%p", module_response.Status, module_response.Status, module_response.Address);
		return 0;
	}
	printf("result: 0x%p\n", module_response.Address);

	// copy request
	char buf[64] = { 0 };
	KERNEL_COPY_RESPONSE result_copy = driver->copy(pid, (PVOID)module_response.Address, &buf, sizeof(buf));
	if (result_copy.Status != STATUS_SUCCESS) {
		printf("error copy! Status: 0x%p - %d", result_copy.Status, result_copy.Status);
		return 0;
	}
	printf("result: Status: 0x%p - %d | Buffer: %s\n", result_copy.Status, result_copy.Status, buf);

	return 0;
}