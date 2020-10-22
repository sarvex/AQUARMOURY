# Wraith
[![](https://img.shields.io/badge/Category-Defense%20Evasion-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Language-C%20%2f%20C++%20%2f%20CSharp%20%2f%20Python3-E5A505?style=flat-square)]()

## Introduction
Wraith is a native loader designed to pave the way for the arrival of a **Stage-1/Beaconing implant** or **Stage-2/Post-Ex implant** in memory in a secure and stealthy manner. Specially designed to operate in heavily-monitored environments, it is designed with **PSP Evasion** as its primary goal.

The loader itself is fairly small(`~40 kB`) and converted into a PIC blob using [sRDI](https://github.com/monoxgas/sRDI) courtesy of [@monoxgas](https://twitter.com/monoxgas?lang=en). It can be executed locally using a `Shellcode Execution Cradle`(Ex: in `C#` cradle for use with `D2JS/G2JS`) or executed directly in-memory via the `Stage-0` payload.

Read below to know what are some of the OPSEC concerns faced by existing toolings and how `Wraith` aims to solve some of them.

## OPSEC Concerns & how we can address them
### Network Activity Monitoring - `IE COM Object`

One of the ways EDRs can detect our tooling is by monitoring for processes that reach the internet especially:
1) If the context is "untrusted"
2) The context is "trusted" but does not load `Wininet.dll` or `Winhttp.dll` or is not expected to have any network activity, reaches for suspicious domains etc.

So it follows that if we go for **Remote Payload Fetching** then it has to be done from a context from where **network activity is not considered unusual**.
Ex: Firefox, Chrome, Edge, IE, other browsers etc.

Luckily for us attackers, we can automate an IE browser instance programatically using [IE COM Object](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/aa752084(v=vs.85)) in the background without any visible windows.

![IE COM](https://github.com/slaeryan/AQUARMOURY/blob/master/Wraith/Screenshots/ie-com.PNG "IE COM")

This is an example of how we can fetch arbritary text data from our `Payload Staging Server`(Here seen using `AWS S3 bucket`) with `IE COM Object`.

Pretty neat eh? :)

One thing I want to point out here is that we will leave a crucial bread crumb this way for Defenders to follow. Can you guess what it is?

Yes, it is the IE Browser History which would reveal the payload URL among other things.

Luckily for us attackers(again!), MS provides with an interface known as [IUrlHistoryStg2](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms774948(v=vs.85)) which has a method called [ClearHistory](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms774947(v=vs.85)) to delete all browsing history data for the current user.

This way we can ensure that we leave absolutely no traces behind ;)

### Execution on Non-targeted asset/Sandbox/Emulator - `Execution Guardrails`
This is done to:
1) To prevent the accidental breaking of the rules of engagement. This will ensure that our malcode doesn’t end being executed on any unintended host which are out of the scope
2) To protect IP and hinder the efforts of blue teams trying to reverse engineer the implant on non-targeted assets and thwart analysis on automated malware sandboxes, AV/EDR emulators etc.

To this effect we have implemented 4 safety checks in our loader:
1) **Mutex Check - To enforce Single-Execution of payload**. This is done by attempting to create a mutex when the loader is executed and checking whether it already exists in which case the loader will terminate immediately. Otherwise, carry on execution as intended. This is obviously necessary since we don't want to execute the payload more than once on the same host whether accidentally or intentionally.
2) **Kill Date - To render the loader(and by extension the payload) harmless after the engagement ends**. This is done by checking the current date on the host with the hard-coded kill date and if it exceeds the kill date then we simply do not proceed.
3) **Static Endpoint Validation - To ensure our payload doesn't run on non-targeted assets**. This is done by comparing a `SHA-256` hash of host artifact(Hostname/Domainname) retrieved at runtime with the hard-coded `SHA-256` hash value of the same. If it matches, assume that our code has detonated on a targeted asset and proceed execution otherwise terminate. Additionally, we hard-code the hashed value instead of the plaintext value itself to make the process of identifying the target non-trivial.

![Workstation Artifact](https://github.com/slaeryan/AQUARMOURY/blob/master/Wraith/Screenshots/workstation.PNG "Workstation Artifact")

![Domain-Joined Artifact](https://github.com/slaeryan/AQUARMOURY/blob/master/Wraith/Screenshots/domain-joined.PNG "Domain-Joined Artifact")

Here we can see the respective artifact name and values for `Workstation` and `Domain-Joined` machines respectively.

4) **Dynamic Endpoint Validation - To have an emergency payload kill-switch**. This is done by encrypting the payload using `AES-256` in `CBC mode` with a `random IV` and a passphrase that is stored on a remote `Key Server`(again fetched using `IE COM Object`) instead of hard-coding it in the loader itself. This way if we suspect that we might be compromised in any way or blue teams are onto us, we can simply delete the passphrase from the keyserver or replace it with an incorrect one which in turn would make payload decryption and ergo execution fail.

All these elaborate safety measures also help us to protect our IP. In a worst case scenario, our `Payload Staging Server` and `Key Server` are burned but we can still save our later stages - C2 infrastructure and payload. This also partly explains our motivation behind using a loader to deliver the C2 payload.

Here is a screenshot demonstrating the flow:

![Execution Guardrails](https://github.com/slaeryan/AQUARMOURY/blob/master/Wraith/Screenshots/execution-guardrail.PNG "Execution Guardrails")

### Detection of Injection/C2 payload - `"Advanced Bird" APC Injection`
Part of the motivation behind using a loader is **to deliver the payload into the address space of a legitimate, signed and trusted process from where the beaconing network activity is not going to be flagged.** This is achieved using Process Injection.

We have chosen to use a variant of the [Early Bird APC Injection](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection) technique because we prioritise a more functional and stable technique over some exotic ROP-based injection containing over 200+ lines of code which is eventually going to get burned :)

I have taken the liberty to change a few things in the original algorithm to aid evasion. Ex: Removed the creation of a suspended process which can be a bit of an IoC. The workaround first creates a process the usual way and then suspends the primary thread.

But using such a well-known technique comes with a potential problem. It uses some pretty _cursed_ API calls in a particular sequence which are going to be picked up by any half-decent AV/EDR.

[Direct Syscalls](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/) to the rescue!

Next question is to hardcode or not?

We have chosen to use hardcoded syscall stubs for our loader thanks to [@j00ru](https://twitter.com/j00ru?lang=en) [syscall table](https://j00ru.vexillium.org/syscalls/nt/64/). However, considering the fact that syscall numbers change between diffrent versions of the OS and sometimes even between different Windows 10 builds, this is probably not a good choice(with DevOps people already flustered :)) The other alternative is extracting the syscall stub from `Ntdll` at runtime to free us of the requirement of hardcoding them. However, in my opinion this is a trade-off between stealth vs scalability with the former being slightly stealthier than the latter especially during RE of the implant(Ex: reading `Ntdll` from disk, looping through Export Table etc.). For red-team engagements with thorough reconnaisance of the target, hardcoding syscall stubs typically shouldn't be a problem though.

There is an implementation of dynamic syscalls known as [HellsGate](https://github.com/am0nsec/HellsGate) by [@am0nsec](https://twitter.com/am0nsec?lang=en) and [@smelly_vx](https://twitter.com/smelly__vx) but in the present form EDR trampolines potentially renders it useless :( 

Another viable alternative created by [@modexp](https://twitter.com/modexpblog) uses [Exception Directory to read the syscall stub](https://modexp.wordpress.com/2020/06/01/syscalls-disassembler/).

This is a screenshot of using "normal" APC Injection without syscalls which clearly shows that our API calls were intercepted by our pseudo-EDR a.k.a. API Monitor:

![API Monitor Detected](https://github.com/slaeryan/AQUARMOURY/blob/master/Wraith/Screenshots/api-monitor-detected.PNG "API Monitor Detected")

And this shows how our injection technique with direct syscalls would look through the lens of an EDR:

![API Monitor Undetected](https://github.com/slaeryan/AQUARMOURY/blob/master/Wraith/Screenshots/api-monitor-undetected.PNG "API Monitor Undetected")

As we can see, our injection wasn't intercepted by our _EDR_ and the **assumption here being that the EDR relies on Ring-3/User-Mode hooks instead of KernelMode ETW Threat Intelligence functions to gain visibility into potentially suspicious actions**(which most of them do thanks to MS :))

Oh and if you're wondering about the `NtAllocateVirtualMemory/NtWriteVirtualMemory` calls, it is actually called internally by `CreateProcessA` as visible from the Call Stack and the ones in the beginning highlighted in red are acually related to the `loader.exe` which inline-executes our injector blob and do not pertain to our remote injection technique itself as visible from the first argument which is `GetCurrentProcess`.

So now that we have managed to hide the act of injection itself, how do we protect our C2 payload?

Enter [CIG and ACG](https://blog.xpnsec.com/protecting-your-malware/) by [Adam Chester a.k.a. @_xpn_](https://twitter.com/_xpn_)!

`CIG` also popularly known as `blockdlls` **prevents any non-MS signed third-party EDR DLL from being injected into our spawned sacrificial "trusted" process which now contains the C2 payload. 

But some EDRs were quick to adapt to this mitigation policy and they quickly got their _evil_ DLL signed by MS which would render this useless. Bummer :(

Fortunately for us, there exists another mitigation policy known as `ACG` or `Arbritary Code Guard` which **prevents a process's ability to allocate new executable pages and/or change existing executable page protections which is required for EDR trampolines to work**. This means that EDR _evil_ DLL injection would fail even if it were signed ;)

The caveat here is that [Cobalt Strike payload Beacon](https://www.cobaltstrike.com/help-beacon) is currently **NOT** compatible with `ACG` and would break it. So readers be forewarned!

`Wraith` supports both `CIG` and `ACG` and can be configured using the config file.

One thing I want to point out here is that I have seen some blogs and tools using `SetMitigationPolicy` to add `ACG` and `CIG` after a process is created. I think that this is a flawed approach and it would not stop EDR DLL getting injected from the kernel into the process. The idea here is to create a process **with the mitigations enabled**.

Now would be a good time to introduce [PPID Spoofing](https://blog.didierstevens.com/2009/11/22/quickpost-selectmyparent-or-playing-with-the-windows-process-tree/) into the conversation which is **used to break the process chain(Word/Excel spawning our sacrificial process) by choosing an appropriate parent-child pair(once again configurable using config file) and protect our payload**.

Here's how it looks in-action:

![Protecting C2 Payload](https://github.com/slaeryan/AQUARMOURY/blob/master/Wraith/Screenshots/wraith-acg-ppid.PNG "Protecting C2 Payload")

In this way we can counter the holy trio of EDR detection using:
**1) API hooking - Direct Syscalls + CIG/ACG**
**2) Abnormal parent-child process relationships - PPID Spoofing**
**3) Logging network activity of processes - Injection into a legitimate process**

Now of course nothing is foolproof and these features are not without flaws. For example: `ACG` doesn't stop a remote process's ability to allocate/modify executable pages using `VirtualAllocEx`. Also, it could be [turned off](http://blog.sevagas.com/IMG/pdf/code_injection_series_part4.pdf) rather easily but EDRs usually stay away from any kinds of bypasses so that could potentially work in our favour :)

`PPID Spoofing` can be detected too using `ETW`(More on this later in the `Detections` section).

### Memory Analysis - `Delete PE Headers`

### Static Detection - `Sensitive String Obfuscation + Encoder`

To Be Continued...
















