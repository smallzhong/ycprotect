#include<ntifs.h> 
#include <ntddk.h>
#include <ntstrsafe.h>
#include "�ṹ.h"

// �豸����
#define DEVICE_NAME L"\\Device\\smallzhong"
#define SYM_NAME L"\\??\\smallzhong"
#define DEVICE_EXTEND_SIZE 0

// ����ţ��Զ�������Ŵ�0x800��ʼ
#define CODE_�����Ȩ 0x800

// ����
#define CTL_�����Ȩ CTL_CODE(FILE_DEVICE_UNKNOWN, CODE_�����Ȩ, METHOD_BUFFERED, FILE_ANY_ACCESS)

// TODO:����Ϊ���ȶ�����
// ����֮ǰ��ΪFALSE���߳��Զ��˳�
BOOLEAN isThreadWork = TRUE;

VOID DRIVERUNLOAD(_In_ struct _DRIVER_OBJECT* DriverObject)
{
	// ɾ����������
	UNICODE_STRING symName = { 0 };
	RtlInitUnicodeString(&symName, SYM_NAME);
	IoDeleteSymbolicLink(&symName);

	// ɾ���豸
	IoDeleteDevice(DriverObject->DeviceObject);

	// TODO:�ȶ�
	isThreadWork = FALSE;
	LARGE_INTEGER tin = { 0 };
	tin.QuadPart = -10000 * 15000;
	KeDelayExecutionThread(KernelMode, FALSE, &tin);

	KdPrintEx((77, 0, "driver unload\r\n"));
}

// �豸�����Ǹ�˭ͨ�ž���˭����˭�ľ������˭
NTSTATUS default_dispatch(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT); // ���´�������
	KdPrintEx((77, 0, "default dispatch\r\n"));

	return STATUS_SUCCESS;
}

ULONG ��ȡƫ��_ObjectTable()
{
	// TODO:����
	return 0xf4;
}

ULONG ��ȡƫ��_ActiveProcessLinks()
{
	// TODO:����
	return 0xb8;
}

ULONG ��ȡƫ��_ImageFileName()
{
	return 0x16c;
}

BOOLEAN NTAPI �ص�_�����Ȩ(
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

VOID �߳�_�����Ȩ(PEPROCESS ep)
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
			pCur = (PEPROCESS)((PUCHAR)(*(PULONG)((PUCHAR)pCur + ��ȡƫ��_ActiveProcessLinks())) - ��ȡƫ��_ActiveProcessLinks());
			KdPrintEx((77, 0, "��ǰ����%s\r\n", (PUCHAR)pCur + ��ȡƫ��_ImageFileName()));

			if (PsGetProcessExitStatus(pCur) == STATUS_PENDING)
			{
				ExEnumHandleTable(*(PULONG)((PUCHAR)pCur + ��ȡƫ��_ObjectTable()), �ص�_�����Ȩ, ep, NULL);
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

		//	// TODO:������һ��Ӳ����(objecttable)
		//	if (PsGetProcessExitStatus(Process) == STATUS_PENDING)
		//	{
		//		ExEnumHandleTable(*(PULONG)((PUCHAR)Process + ��ȡƫ��_ObjectTable()), �ص�_�����Ȩ, ep, NULL);

		//		if (PsGetProcessExitStatus(Process) == STATUS_PENDING)
		//			ObDereferenceObject(Process);
		//	}
		//}

		LARGE_INTEGER tin = { 0 };
		tin.QuadPart = -10000 * 1000;
		KeDelayExecutionThread(KernelMode, FALSE, &tin);
	}
}

BOOLEAN �����Ȩ_pid(ULONG pid)
{
	PEPROCESS pEprocess = NULL;

	NTSTATUS status = PsLookupProcessByProcessId(pid, &pEprocess);

	if (!NT_SUCCESS(status))
	{
		KdPrintEx((77, 0, "��ȡeprocessʧ�� line = %d\r\n", __LINE__));
		return FALSE;
	}

	HANDLE hThread = NULL;
	PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, �߳�_�����Ȩ, pEprocess);
	if (hThread) NtClose(hThread);

	return TRUE; // ִ�гɹ�
}

NTSTATUS dispatch_func(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);

	// �󲿷�ʱ��û��Ҫ�жϣ�Ϊ���Ͻ������ж�һ�¡�����ͨ������ȷ�ĵ��úŵ���
	if (ioStack->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		// ��ȡ�����������Ĳ����ĳ���
		ULONG size = ioStack->Parameters.DeviceIoControl.InputBufferLength;
		// ͨ�ŵ�ʱ��ʹ�õĿ����룬��3��������
		ULONG IoControlCode = ioStack->Parameters.DeviceIoControl.IoControlCode;

		// ���⴫���ݵĻ�����
		ULONG OutputBufferLength = ioStack->Parameters.DeviceIoControl.OutputBufferLength;
		KdPrintEx((77, 0, "outputbufferlength = %d\r\n", OutputBufferLength));

		// �жϿ����룬���в�ͬ�Ĳ�����
		switch (IoControlCode)
		{
		case CTL_�����Ȩ:
		{
			// �����������ݵĻ�������ַ
			PLONG p = (PLONG)Irp->AssociatedIrp.SystemBuffer;

			ULONG pid = 0;
			RtlMoveMemory(&pid, p, sizeof(ULONG));
			KdPrintEx((77, 0, "pid = %u\r\n", pid));

			BOOLEAN status = �����Ȩ_pid(pid);

			// TODO: ��������״̬

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
	// �豸����
	UNICODE_STRING unName = { 0 };
	RtlInitUnicodeString(&unName, DEVICE_NAME);

	// �������ӣ�����ͨ�����������ҵ�0���豸��
	UNICODE_STRING symName = { 0 };
	RtlInitUnicodeString(&symName, SYM_NAME);

	PDEVICE_OBJECT pDevice = NULL;
	NTSTATUS status = IoCreateDevice(pDriver, DEVICE_EXTEND_SIZE, &unName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDevice);

	if (!NT_SUCCESS(status))
	{
		KdPrintEx((77, 0, "�����豸ʧ�� status = %d\r\n", status));
		return status;
	}

	// ��ʼ��extend����
	RtlZeroMemory(pDevice->DeviceExtension, DEVICE_EXTEND_SIZE);

	// ������������
	status = IoCreateSymbolicLink(&symName, &unName);
	// �������ʧ��
	if (!NT_SUCCESS(status))
	{
		// ɾ���豸
		IoDeleteDevice(pDevice);
		KdPrintEx((77, 0, "������������ʧ��status = %d\r\n", status));
		return status;
	}

	// �ɵ���һλ(Ϊ�˼��ݣ�win7����û���������)
	pDevice->Flags &= ~DO_DEVICE_INITIALIZING;

	// ����ͨѶ��ʽ
	pDevice->Flags |= DO_BUFFERED_IO;

	pDriver->MajorFunction[IRP_MJ_CREATE] = default_dispatch; // �����Ҫͨ�ţ�������䣬�����������ش���
	pDriver->MajorFunction[IRP_MJ_CLOSE] = default_dispatch; // �����Ҫͨ�ţ�������䣬�����������ش���
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_func;

	pDriver->DriverUnload = DRIVERUNLOAD;
	return STATUS_SUCCESS;
}