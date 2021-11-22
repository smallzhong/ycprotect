#pragma once

#include<ntifs.h> 
#include <ntddk.h>
#include <ntstrsafe.h>

typedef enum _MI_VAD_TYPE
{
	VadNone,
	VadDevicePhysicalMemory,
	VadImageMap,
	VadAwe,
	VadWriteWatch,
	VadLargePages,
	VadRotatePhysical,
	VadLargePageSection,
};

typedef struct _MMVAD_FLAGS
{
	ULONG CommitCharge : 19;//    : Pos 0, 19 Bits
	ULONG NoChange : 1;// Bit // 锁，但是在有些系统上没有用
	ULONG VadType : 3;//Bits // _MI_VAD_TYPE
	ULONG MemCommit : 1;// Bit
	ULONG Protection : 5;// Bits // 保护类型（如PAGE_NOACCESS）
	ULONG Spare : 2;// Bits
	ULONG PrivateMemory : 1;//Bit // 是否为Private，1为私有，0为Mapped
} MMVAD_FLAGS, *PMMVAD_FLAGS;

typedef struct _MMVAD
{
	ULONG u1;
	struct _MMVAD* LeftChild;
	struct _MMVAD* RightChild;
	ULONG StartingVpn;
	ULONG EndingVpn;
	ULONG u;
	ULONG PushLock;
	ULONG u5;
} MMVAD, * PMMVAD;

typedef struct _MMADDRESS_NODE
{
	ULONG u1;
	ULONG LeftChild;
	ULONG RightChild;
	ULONG StartingVpn;
	ULONG EndingVpn;
} MMADDRESS_NODE, PMMADDRESS_NODE;

typedef struct _MM_AVL_TABLE
{
	MMADDRESS_NODE BalancedRoot;
	ULONG DepthOfTree;
	//+0x014 NumberGenericTableElements : 0y000000000000000001001010 (0x4a)
	ULONG NodeHint;
	ULONG NodeFreeHint;
} MM_AVL_TABLE, * PMM_AVL_TABLE;


typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		VOID* Object;                                                       //0x0
		ULONG ObAttributes;                                                 //0x0
		struct _HANDLE_TABLE_ENTRY_INFO* InfoTable;                         //0x0
		ULONG Value;                                                        //0x0
	};
	union
	{
		ULONG GrantedAccess;                                                //0x4
		struct
		{
			USHORT GrantedAccessIndex;                                      //0x4
			USHORT CreatorBackTraceIndex;                                   //0x6
		};
		ULONG NextFreeTableEntry;                                           //0x4
	};
}HANDLE_TABLE_ENTRY,*PHANDLE_TABLE_ENTRY;

#define PROCESS_VM_READ           (0x0010)  // winnt
#define PROCESS_VM_WRITE          (0x0020)  // winnt

typedef BOOLEAN(NTAPI *EX_ENUMERATE_HANDLE_ROUTINE)(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
	);

BOOLEAN ExEnumHandleTable(
	__in PVOID HandleTable,
	__in EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
	__in PVOID EnumParameter,
	__out_opt PHANDLE Handle
);