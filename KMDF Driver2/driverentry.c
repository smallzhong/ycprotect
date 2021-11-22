#include<ntifs.h> 
#include <ntddk.h>
#include <ntstrsafe.h>
#include "结构.h"

// 设备名称
#define DEVICE_NAME L"\\Device\\smallzhong"
#define SYM_NAME L"\\??\\smallzhong"
#define DEVICE_EXTEND_SIZE 0

// 请求号，自定义请求号从0x800开始
#define CODE_句柄降权 0x800

// 请求
#define CTL_句柄降权 CTL_CODE(FILE_DEVICE_UNKNOWN, CODE_句柄降权, METHOD_BUFFERED, FILE_ANY_ACCESS)

// TODO:完善为更稳定方法
// 结束之前设为FALSE让线程自动退出
BOOLEAN isThreadWork = TRUE;

VOID DRIVERUNLOAD(_In_ struct _DRIVER_OBJECT* DriverObject)
{
	// 删除符号链接
	UNICODE_STRING symName = { 0 };
	RtlInitUnicodeString(&symName, SYM_NAME);
	IoDeleteSymbolicLink(&symName);

	// 删除设备
	IoDeleteDevice(DriverObject->DeviceObject);

	// TODO:稳定
	isThreadWork = FALSE;
	LARGE_INTEGER tin = { 0 };
	tin.QuadPart = -10000 * 15000;
	KeDelayExecutionThread(KernelMode, FALSE, &tin);

	KdPrintEx((77, 0, "driver unload\r\n"));
}

// 设备对象是跟谁通信就是谁，打开谁的句柄就是谁
NTSTATUS default_dispatch(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT); // 往下传递请求
	KdPrintEx((77, 0, "default dispatch\r\n"));

	return STATUS_SUCCESS;
}

ULONG 获取偏移_ObjectTable()
{
	// TODO:兼容
	return 0xf4;
}

ULONG 获取偏移_ActiveProcessLinks()
{
	// TODO:兼容
	return 0xb8;
}

ULONG 获取偏移_ImageFileName()
{
	return 0x16c;
}

BOOLEAN NTAPI 回调_句柄降权(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
)
{
	if (HandleTableEntry)
	{

		PUCHAR x = (HandleTableEntry->Value & ~7);
		ULONG_PTR object = (HandleTableEntry->Value & ~7) + 0x18; //0xfffffff8
		UCHAR tindex = *(x + 0xc);
		KdPrintEx((77, 0, "[db]:index = %x EnumParameter=%x,object=%x\r\n", tindex, EnumParameter, object));
		if (tindex == 0x7)
		{
			//DbgBreakPoint();

			if (object == (ULONG_PTR)EnumParameter)
			{
				HandleTableEntry->GrantedAccess &= ~(PROCESS_VM_READ | PROCESS_VM_WRITE);
			}
		}
	}

	return FALSE;
}

VOID 线程_句柄降权(PEPROCESS ep)
{
	//DbgBreakPoint();
	HANDLE pid = PsGetProcessId(ep);
	while (isThreadWork)
	{
		PEPROCESS pOld = NULL;
		pOld = PsGetCurrentProcess();
		PEPROCESS pCur = pOld;

		do
		{
			pCur = (PEPROCESS)((PUCHAR)(*(PULONG)((PUCHAR)pCur + 获取偏移_ActiveProcessLinks())) - 获取偏移_ActiveProcessLinks());
			KdPrintEx((77, 0, "当前进程%s\r\n", (PUCHAR)pCur + 获取偏移_ImageFileName()));

			if (PsGetProcessExitStatus(pCur) == STATUS_PENDING)
			{
				ExEnumHandleTable(*(PULONG)((PUCHAR)pCur + 获取偏移_ObjectTable()), 回调_句柄降权, ep, NULL);
			}
		} while (pCur != pOld);

		//PEPROCESS Process = NULL;
		//for (ULONG i = 8; i < 0x1000000; i += 4)
		//{
		//	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)i, &Process);
		//	if (!NT_SUCCESS(status))
		//	{
		//		continue;
		//	}

		//	// TODO:这里有一个硬编码(objecttable)
		//	if (PsGetProcessExitStatus(Process) == STATUS_PENDING)
		//	{
		//		ExEnumHandleTable(*(PULONG)((PUCHAR)Process + 获取偏移_ObjectTable()), 回调_句柄降权, ep, NULL);

		//		if (PsGetProcessExitStatus(Process) == STATUS_PENDING)
		//			ObDereferenceObject(Process);
		//	}
		//}

		LARGE_INTEGER tin = { 0 };
		tin.QuadPart = -10000 * 1000;
		KeDelayExecutionThread(KernelMode, FALSE, &tin);
	}
}

BOOLEAN 句柄降权_pid(ULONG pid)
{
	PEPROCESS pEprocess = NULL;

	NTSTATUS status = PsLookupProcessByProcessId(pid, &pEprocess);

	if (!NT_SUCCESS(status))
	{
		KdPrintEx((77, 0, "获取eprocess失败 line = %d\r\n", __LINE__));
		return FALSE;
	}

	HANDLE hThread = NULL;
	PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, 线程_句柄降权, pEprocess);
	if (hThread) NtClose(hThread);

	return TRUE; // 执行成功
}

NTSTATUS dispatch_func(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);

	// 大部分时候没必要判断，为了严谨可以判断一下。反正通过不正确的调用号调用
	if (ioStack->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		// 获取三环传过来的参数的长度
		ULONG size = ioStack->Parameters.DeviceIoControl.InputBufferLength;
		// 通信的时候使用的控制码，从3环传过来
		ULONG IoControlCode = ioStack->Parameters.DeviceIoControl.IoControlCode;

		// 向外传数据的缓冲区
		ULONG OutputBufferLength = ioStack->Parameters.DeviceIoControl.OutputBufferLength;
		KdPrintEx((77, 0, "outputbufferlength = %d\r\n", OutputBufferLength));

		// 判断控制码，进行不同的操作。
		switch (IoControlCode)
		{
		case CTL_句柄降权:
		{
			// 传进来的数据的缓冲区地址
			PLONG p = (PLONG)Irp->AssociatedIrp.SystemBuffer;

			ULONG pid = 0;
			RtlMoveMemory(&pid, p, sizeof(ULONG));
			KdPrintEx((77, 0, "pid = %u\r\n", pid));

			BOOLEAN status = 句柄降权_pid(pid);

			// TODO: 返回三环状态

			break;
		}
		}
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	KdPrintEx((77, 0, "entry\r\n"));
	// 设备名称
	UNICODE_STRING unName = { 0 };
	RtlInitUnicodeString(&unName, DEVICE_NAME);

	// 符号链接（三环通过符号链接找到0环设备）
	UNICODE_STRING symName = { 0 };
	RtlInitUnicodeString(&symName, SYM_NAME);

	PDEVICE_OBJECT pDevice = NULL;
	NTSTATUS status = IoCreateDevice(pDriver, DEVICE_EXTEND_SIZE, &unName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDevice);

	if (!NT_SUCCESS(status))
	{
		KdPrintEx((77, 0, "创建设备失败 status = %d\r\n", status));
		return status;
	}

	// 初始化extend区域
	RtlZeroMemory(pDevice->DeviceExtension, DEVICE_EXTEND_SIZE);

	// 创建符号链接
	status = IoCreateSymbolicLink(&symName, &unName);
	// 如果创建失败
	if (!NT_SUCCESS(status))
	{
		// 删除设备
		IoDeleteDevice(pDevice);
		KdPrintEx((77, 0, "创建符号链接失败status = %d\r\n", status));
		return status;
	}

	// 干掉这一位(为了兼容，win7以上没有这个问题)
	pDevice->Flags &= ~DO_DEVICE_INITIALIZING;

	// 设置通讯方式
	pDevice->Flags |= DO_BUFFERED_IO;

	pDriver->MajorFunction[IRP_MJ_CREATE] = default_dispatch; // 如果想要通信，必须填充，否则三环返回错误
	pDriver->MajorFunction[IRP_MJ_CLOSE] = default_dispatch; // 如果想要通信，必须填充，否则三环返回错误
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_func;

	pDriver->DriverUnload = DRIVERUNLOAD;
	return STATUS_SUCCESS;
}