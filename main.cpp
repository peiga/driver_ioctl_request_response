/**********************************************
                    INCLUDES
**********************************************/
#include <ntddk.h>

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
                    GLOBAL VARS
**********************************************/
PDEVICE_OBJECT pDeviceObject; // our driver object
UNICODE_STRING dev, dos; // Driver registry paths

/**********************************************
                    FUNCTIONS
**********************************************/

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    IoDeleteDevice(pDeviceObject);
    IoDeleteSymbolicLink(&dos);
    IoDeleteSymbolicLink(&dev);
}

NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG BytesIO = 0;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    // Code received from user space
    ULONG ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    // ioctl handlers
    if (ControlCode == IO_MODULE_BASE_REQUEST)
    {
        // logging
        DebugPrint("Received IOCTL: 0x%p - %d", IO_MODULE_BASE_REQUEST, IO_MODULE_BASE_REQUEST);

        // Get the input buffer & format it to our struct
        PKERNEL_MODULE_BASE_REQUEST request = (PKERNEL_MODULE_BASE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        PKERNEL_MODULE_BASE_RESPONSE response = (PKERNEL_MODULE_BASE_RESPONSE)Irp->AssociatedIrp.SystemBuffer;;

        // read request
        int requestProcessId = request->ProcessId;
        PVOID requestAddress = request->Address;
        size_t requestSize = request->Size;
        UNICODE_STRING requestModuleName;
        RtlInitUnicodeString(&requestModuleName, request->Module);

        // create response
        response->Status = STATUS_SUCCESS;
        response->Address = (PVOID)0x7ff6acd60000;

        // logging
        DebugPrint("[i] Request | requestProcessId: %d | requestAddress: 0x%p | requestSize: %d | requestModuleName: %wZ", requestProcessId, requestAddress, requestSize, requestModuleName);
        DebugPrint("[i] Response | response->Address: 0x%p | response->Status: 0x%p - %d", response->Address, response->Status, response->Status);

        // set io info
        Status = response->Status;
        BytesIO = sizeof(KERNEL_MODULE_BASE_RESPONSE);
    }
    else if (ControlCode == IO_COPY_REQUEST)
    {
        // logging
        DebugPrint("Received IOCTL: 0x%p - %d", IO_COPY_REQUEST, IO_COPY_REQUEST);

        // Get the input buffer & format it to our struct
        PKERNEL_COPY_REQUEST request = (PKERNEL_COPY_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        PKERNEL_COPY_RESPONSE response = (PKERNEL_COPY_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

        // read request
        int requestProcessId = request->ProcessId;
        PVOID requestAddress = request->Address;
        PVOID requestBuffer = request->Buffer;
        size_t requestSize = request->Size;

        // create response
        response->Status = STATUS_SUCCESS;

        // logging
        DebugPrint("[i] Request | requestProcessId: %d | requestAddress: 0x%p | requestBuffer: 0x%p | requestSize: %d", requestProcessId, requestAddress, requestBuffer, requestSize);
        DebugPrint("[i] Response | response->Status: 0x%p - %d", response->Status, response->Status);

        // set io info
        Status = response->Status;
        BytesIO = sizeof(KERNEL_MODULE_BASE_RESPONSE);
    }
    else
    {
        // logging
        DebugPrint("Received unknown IOCTL: 0x%p - %d", IO_COPY_REQUEST, IO_COPY_REQUEST);

        // set io info
        Status = STATUS_INVALID_PARAMETER;
        BytesIO = 0;
    }

    // Complete the request
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = BytesIO;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

/**********************************************
                    DRIVERENTRY
**********************************************/

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DebugPrint("Driver Loaded");

    // init unicode strings
    RtlInitUnicodeString(&dev, L"\\Device\\drivername");
    RtlInitUnicodeString(&dos, L"\\DosDevices\\drivername");

    // specify MajorFunction
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCall;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;

    // specify unload function
    DriverObject->DriverUnload = DriverUnload;

    // create device and symlink
    NTSTATUS result = IoCreateDevice(DriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
    IoCreateSymbolicLink(&dos, &dev);

    // check if driver is initialized
    if (result != STATUS_SUCCESS) {
        DebugPrint("IoCreateDevice Status: 0x%p - %d ", result, result);

        return STATUS_UNSUCCESSFUL;
    }

    // specify flags
    if (pDeviceObject) {
        pDeviceObject->Flags |= DO_DIRECT_IO;
        pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    }

    return STATUS_SUCCESS;
}
