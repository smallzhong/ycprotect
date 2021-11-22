/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_KMDFDriver2,
    0xa3b129e5,0x6bad,0x485c,0x8f,0x83,0x60,0x41,0xb6,0x31,0x20,0xd6);
// {a3b129e5-6bad-485c-8f83-6041b63120d6}
