#pragma once

#include "../proggerConfig.h"

typedef unsigned char progger_uint8;
typedef unsigned short progger_uint16;
typedef unsigned int progger_uint32;
typedef unsigned long long progger_uint64;

typedef char progger_int8;
typedef short progger_int16;
typedef int progger_int32;
typedef long long progger_int64;

typedef bool progger_bool;

typedef progger_uint64 progger_perfTime_t;

// Check to make sure that the size assumptions are correct for Windows only
#ifndef PROGGER_LINUX
static_assert(sizeof(progger_uint8) == 1, "size check failed");
static_assert(sizeof(progger_uint16) == 2, "size check failed");
static_assert(sizeof(progger_uint32) == 4, "size check failed");
static_assert(sizeof(progger_uint64) == 8, "size check failed");

static_assert(sizeof(progger_int8) == 1, "size check failed");
static_assert(sizeof(progger_int16) == 2, "size check failed");
static_assert(sizeof(progger_int32) == 4, "size check failed");
static_assert(sizeof(progger_int64) == 8, "size check failed");
#endif

enum progger_syscallTypes {
	PSCT_USER_INFO = 0,							// (ANNOTATE) CAN contain the username/domain name 

	PSCT_PROCESS_CREATE = 1,						// (ANNOTATE) MUST contain the process name including full path relative to FS root
												// CAN contain the operating system specific processId
	PSCT_PROCESS_EXIT = 2,						//

	PSCT_FILE_OPEN = 3,							// MUST contain the file name including full path relative to FS root
												// MUST generate and contain a unique file handle value
	PSCT_FILE_CLOSE = 4,						// MUST contain the file handle value
	PSCT_FILE_READ = 5,							// MUST contain the file handle value
												// MUST contain the byte length and offset
	PSCT_FILE_WRITE = 6,						// MUST contain the file handle value
												// MUST contain the byte length and offset

												// TODO: socket args
	PSCT_SOCKET_OPEN = 7,						//
	PSCT_SOCKET_CLOSE = 8,						//
	PSCT_SOCKET_READ = 9,						//
	PSCT_SOCKET_WRITE = 10,						//

	PSCT_DIRNODE_CREATE = 11,					// MUST contain the directory/file name relative to the FS root
	PSCT_DIRNODE_DELETE = 12,					// MUST contain the directory/file name relative to the FS root
	PSCT_DIRNODE_RENAME = 13,					// MUST contain the old and new directory/file name relative to the FS root
	PSCT_DIRNODE_LINK = 14,						// MUST contain the old and new directory/file name relative to the FS root
	PSCT_DIRNODE_CHANGE_OWNER = 15,				// MUST contain the new owner's user ID
	PSCT_DIRNODE_CHANGE_PERMISSIONS = 16,		//

	PSCT_HANDLE_DUPLICATE = 17,					// MUST contain the type of handle being duplicated (1=FILE, 2=SOCKET)
												// MUST contain the old handle value of the handle

	PSCT_DEBUG = 18								// For debugging use
}; // Size: 1 byte

enum progger_platformTypes {
	PP_WINDOWS = 0,
	PP_LINUX = 1
}; // Size: 1 byte
#ifndef PROGGER_LINUX
static_assert(PP_WINDOWS == 0, "Value check");
static_assert(PP_LINUX == 1, "Value check");
#endif

enum progger_handleType {
	PHT_FILE = 1,
	PHT_SOCKET = 2
}; // Size: 1 byte
#ifndef PROGGER_LINUX
static_assert(PHT_FILE == 1, "Value check");
static_assert(PHT_SOCKET == 2, "Value check");
#endif

#pragma pack(push, 1)
struct progger_header {
	progger_uint8 version;					// Required to be 0

	progger_uint16 length;                  // The length of the entire packet.
											// This is the first value as it will be passed

	progger_uint8 platform;					// Of type progger_platformTypes
	progger_uint8 type;						// Of type progger_syscallTypes

	progger_uint64 hostId;                  // Transparent to progger and should be persisted reboots and updates.
											/* 14 June TJChoi : for HostId  org progger_uint32 */

	progger_uint64 timestamp;               // Defined as the number of microseconds since the UNIX epoch.
											// Use getnstimeofday on Linux and KeQuerySystemTimePrecise on Windows.
											// Note that both don't provide the exact value required here and need
											// conversion.

#ifndef PROGGER_LINUX
	progger_uint32 userId;                  // Defined as a unique value that logs the first time it's encountered.
#else
	kuid_t userId;
#endif
											// This data is defined by the implementation of progger.

	progger_uint32 processId;               // Defined as a unique value that logs the first time it's encountered.
											// This data is defined by the implementation of progger.

	progger_uint8 attributeCount;           // The number of attributes following the header

#ifdef PROGGER_PREF
	progger_uint64 timeDelta;
#endif
}; // Size: 1 + 2 + 1 + 1 + 4 + 8 + 4 + 4 + 1 = 26 bytes

#if !defined(PROGGER_LINUX) && !defined(PROGGER_PREF)
static_assert(sizeof(struct progger_header) == 26, "progger_header must be 26 bytes long");
#elif !defined(PROGGER_LINUX)
static_assert(sizeof(struct progger_header) == 34, "progger_header must be 34 bytes long");
#endif

struct progger_attribute {
	progger_uint16 length;                  // The length of the attribute.
}; // Size: 2 + length bytes
#ifndef PROGGER_LINUX
static_assert(sizeof(struct progger_attribute) == 2, "progger_attribute must be 2 bytes long");
#endif

struct progger_userAttribute {
	struct progger_attribute header;
	
	progger_uint16 usernameLength;
	progger_uint16 sidLength;
	// Username Chars
	// Sid Chars
}; // Size: usernameLength + sidLength + 2 + 2 + 2 = 6+ bytes
#ifndef PROGGER_LINUX
static_assert(sizeof(struct progger_userAttribute) == 6, "progger_userAttribute must be 6 bytes long");
#endif

struct progger_processAttribute {
	struct progger_attribute header;

	progger_uint64 processHandle;
	progger_uint16 processPathLength;
}; // Size: processPathLength + 2 + 8 + 2 = 12+ bytes
#ifndef PROGGER_LINUX
static_assert(sizeof(struct progger_processAttribute) == 12, "progger_processAttribute must be 12 bytes long");
#endif

struct progger_fileOpenAttribute {
	struct progger_attribute header;

	progger_uint64 fileHandleID;
	progger_uint64 fileID;

	progger_bool created;

	progger_uint16 filenameLength;
#ifdef PROGGER_STACKTRACE
	progger_uint64 stackTrace[32];
#endif
	progger_uint32 securityLength;
}; // Size: filenameLength + securityLength + 2 + 8 + 8 + 2 + 4 = 24+ bytes

#if !defined(PROGGER_LINUX) && !defined(PROGGER_STACKTRACE)
static_assert(sizeof(struct progger_fileOpenAttribute) == 24, "progger_fileOpenAttribute must be 24 bytes long");
#elif !defined(PROGGER_LINUX)
static_assert(sizeof(struct progger_fileOpenAttribute) == 276, "progger_fileOpenAttribute must be 276 bytes long");
#endif

struct progger_fileAttribute {
	struct progger_attribute header;

	progger_uint64 fileHandleID;
	progger_uint64 fileID;
}; // Size: 2 + 8 + 8 = 18 bytes
#ifndef PROGGER_LINUX
static_assert(sizeof(struct progger_fileAttribute) == 18, "progger_fileAttribute must be 18 bytes long");
#endif

struct progger_fileReadWriteAttribute {
	struct progger_attribute header;

	progger_uint64 fileHandleID;
	progger_uint64 fileID;

	progger_int64 position;
	progger_uint64 length;
}; // Size: 2 + 8 + 8 + 8 + 8 = 34 bytes
#ifndef PROGGER_LINUX
static_assert(sizeof(struct progger_fileReadWriteAttribute) == 34, "progger_fileReadWriteAttribute must be 34 bytes long");
#endif

struct progger_setOwnerAttribute {
	struct progger_attribute header;

	progger_uint64 fileHandleID;
	progger_uint64 fileID;
	progger_uint16 filenameLength;

	progger_uint32 newOwnerID;

	progger_uint16 sidLength;
}; // Size: sidLength + 2 + 8 + 8 + 4 + 2 = 24+ bytes
#ifndef PROGGER_LINUX
static_assert(sizeof(struct progger_setOwnerAttribute) == 24, "progger_setOwnerAttribute must be 24 bytes long");
#endif

struct progger_handleDuplicateAttribute {
	struct progger_attribute header;

        progger_uint64 oldfileHandleID;
        progger_uint64 oldfileID;

	progger_uint64 newfileHandleID;
        progger_uint64 newfileID;

	progger_uint8 type;
}; // Size: 2 + 8 + 8 + 8 + 8 + 1 = 35
#ifndef PROGGER_LINUX
static_assert(sizeof(struct progger_handleDuplicateAttribute) == 35, "progger_handleDuplicateAttribute must be 35 bytes long");
#endif

struct progger_changePermissionsAttribute {
	struct progger_attribute header;

	// NOTE: added the IDs since Linux includes chmod and fchmod that use filenames and file descriptors
	progger_uint64 fileHandleID;
        progger_uint64 fileID;

#ifdef PROGGER_LINUX
	progger_uint16 mode;	
#endif

	progger_uint16 filenameLength;
}; // Size filenameLength + 2 + 2 = 4+ bytes
#ifndef PROGGER_LINUX
static_assert(sizeof(struct progger_changePermissionsAttribute) == 4, "progger_changePermissionsAttribute must be 4 bytes long");
#endif

struct progger_filenameAttribute {
	struct progger_attribute header;

	progger_uint16 filenameLength;
}; // Size filenameLength + 2 + 2 = 4+ bytes
#ifndef PROGGER_LINUX
static_assert(sizeof(struct progger_filenameAttribute) == 4, "progger_filenameAttribute must be 4 bytes long");
#endif

struct progger_fileLinkAttribute {
	struct progger_attribute header;

	progger_uint16 oldFilenameLength;
	progger_uint16 newFilenameLength;
}; // Size oldFilenameLength + newFilenameLength + 2 + 2 + 2 = 6+ bytes
#ifndef PROGGER_LINUX
static_assert(sizeof(struct progger_fileLinkAttribute) == 6, "progger_fileLinkAttribute must be 6 bytes long");
#endif

struct progger_networkAttribute {
	struct progger_attribute header;

	progger_uint32 remoteAddress;
	progger_uint16 sourcePort;
	progger_uint16 remotePort;
	progger_uint32 dataLength;
}; // Size 2 + 4 + 2 + 2 + 4 = 10 bytes
#ifndef PROGGER_LINUX
static_assert(sizeof(struct progger_networkAttribute) == 14, "progger_networkAttribute must be 14 bytes long");
#endif

struct progger_objectCallbackAttribute {
	struct progger_attribute header;

	progger_uint8 type;
	progger_uint32 returnCode;
};

#pragma pack(pop)

