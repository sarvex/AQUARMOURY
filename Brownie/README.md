# Brownie
[![](https://img.shields.io/badge/Category-Defense%20Evasion-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Language-C%20%2f%20C++%20%2f%20CSharp%20%2f%20Python3-E5A505?style=flat-square)]()

## Introduction
`Brownie` is a platform to rapidly prototype and weaponise DLL hijacks. In particular, we are interested in [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/) to **sideload our malicious code by a signed and legitimate executable**. It is sometimes wrongly(or rightly?) known as [DLL Sideloading](https://attack.mitre.org/techniques/T1574/002/) which has a very specific definition.

We are particularly interested in how this technique is an interesting(and often underrated) alternative to **Code Injection** that shares the same objectives i.e. **to evade AV/EDRs by executing malicious code from the address space of a "trusted" process**. We won't be looking at DLL hijacks for LPE or even Persistence as such although it can certainly be adapted for the latter purpose quite easily.

This post will be heavily borrowing from public research and it was a personal note before I decided to release it by packaging it up nicely with a bow.

So without any further ado, let's get started!

## How To:
As a quick recap here is the highlighted DLL Search Order that we will be targeting considering `SafeDllSearchMode` is turned **ON**.

![DLL Search Order](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/dll-search-order.png "DLL Search Order")

Furthermore, we will be targeting `System32` executables for this demonstration and won't be targeting third-party applications since those are target-specific.

So we will be using a slight variation of this technique known as **Relative Path DLL Hijacking** i.e. dropping the malicious DLL in a user-writeable folder and copying the legitimate, signed executable from `System32` to the folder before executing it finally to load our "evil" DLL.

Our first order of business is finding the right candidate for the job. There are many automated tools to do that and I found a wonderful [post](https://github.com/wietze/windows-dll-hijacking) that details almost 300 executables in `System32` that are vulnerable to DLL Hijacking but what kind of hackers would we be if we didn't try to find our own? ;)

Almost always, you'll hear someone say that DLL hijacks in Windows executables are plentiful. I fully agree considering the evidence. But that doesn't always mean that all of them are perfect candidates to exploit.

For example, some applications contain visual elements which upon execution will immediately notify the target effectively rendering it useless for use in covert operations.

With all that mind, we will initiate our good old-fashioned hunt!

The algorithm for the hunt goes something like:
1. Copy the executable from `System32` to our current working directory

![Target Executable](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/target-exe.PNG "Target Executable")

2. Run procmon with primarily two filters: 
`Result contains NOT FOUND -> include & Path ends with .dll -> include`

![ProcMon Filter](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/procmon-filter.PNG "ProcMon Filter")

3. Finally, execute the binary

![Hijackable DLL found](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/hijackable-dll-found.PNG "Hijackable DLL found")

Aand profit!!!

So if we rename an arbitrary DLL to `DUI70.dll` in the application's directory, it should get loaded by our target executable which in turn should execute our malcode right?

![No Go](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/no-go.PNG "No Go")

Welp not quite :(

Process Monitor logs clearly show that `DUI70.dll` is searched by `LicensingUI.exe` from the same directory it is executed from following the DLL Search Order in absence of absolute path in `LoadLibrary` call. So what happened?

Well if you think about it, it's not that the executable is loading the `DUI70` DLL because it just felt like doing so right? After all, it is being loaded for a purpose because the executable needs to perform some function(s) defined in the DLL which our "evil" DLL is obviously missing that in this case also causes the application to not start properly/crash i.e. We do not maintain stability in the target executable.

So how do we solve this problem? By using **DLL Proxying** or **delegating the legitimate functionality to the real DLL by linking the export table of "evil" DLL to the original DLL**.

![DLL Proxying](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/dll-proxying.png "DLL Proxying")

One of the simplest ways to implement this is by **export forwarding using linker redirects**. In other words, cloning all the exported functions from the real DLL and redirecting them to the real DLL and letting the Windows loader subsystem do the rest of the work for us.

```
#pragma comment(linker, "/export:{exportedFunctionName}={realDLLName/FullPath}.{exportedFunctionName},@{exportedFunctionalOrdinal}")
```

Here we can clearly examine the exports of our "evil" `DUI70.dll` redirected to the real `DUI70.dll` in `System32` using PEStudio:

![Export Forwarding](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/exports-forwarded.PNG "Export Forwarding")

There is a wonderful tool written by [Melvin Langvik](https://twitter.com/Flangvik) named [SharpDllProxy](https://github.com/Flangvik/SharpDllProxy) that aims to automate the mentioned process. While it is a nice alternative, for the purposes of our experiment, I found notably two problems with this approach:

1. We would need to re-compile our implant DLL every time we want to target an executable since this technique is dependent on it
2. The implant generated by `SharpDllProxy` loads the payload from disk which means it'll need to be dropped to disk as well

Enter [Koppeling](https://github.com/monoxgas/Koppeling) by [Nick Landers a.k.a. @monoxgas](https://twitter.com/monoxgas)!

Quoting from the [SBS blogpost](https://silentbreaksecurity.com/adaptive-dll-hijacking/):
```
The process goes like this:
 
1. We compile/collect our “evil” DLL for hijacking. It doesn’t need to be aware of any hijacking duty (unless you need to add hooking).
2. We clone the exports of a reference DLL into the “evil” DLL. The “real” DLL is parsed and the export table is duplicated into a new PE section. Export forwarding is used to correctly proxy functionality.
3. We use the freshly cloned DLL in any hijack. Stability is guaranteed and we can maintain execution inter-process.
```

What does this essentially mean for us attackers? This means that now we can weaponize our arbitrary DLL post-build without needing to re-compile for testing multiple targets.

Oh and if you haven't yet read the above post, I'd implore the readers to do so before continuing further.

I have already prepped our target-agnostic DLL which embeds the payload(malcode which we want to be executed) in the `Resource` section of PE. Upon loading, it extracts the payload from `rsrc` and executes it locally in a separate thread(to avoid loader lock complexities).

One thing I've noticed is that as soon I dropped our "evil" DLL in our testing VM, it'd almost immediately get detected and quarantined by Defender AV. Bummer :(

Upon closer signature inspection with [DefenderCheck](https://github.com/matterpreter/DefenderCheck) by [Matt Hand a.k.a. matterpreter](https://twitter.com/matterpreter), I'd soon learn that the [Metasploit]() calc shellcode signature is what got our _well-behaved_ DLL in trouble.

On learning this, I have taken the liberty the encrypt the payload with AES-256 in CBC mode with a random IV and adding code to our DLL which will decrypt the payload after resource extraction ergo you can say goodbye to static detections.

![Evading Defender Signature](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/evading-defender-sig.PNG "Evading Defender Signature")

I have also taken the liberty to build the `NetClone` project from **Koppeling** and `ILMerge`d all the dependency DLLs together into a portable package so that you don't have to(No need to thank me :) )

So continuing from Step 3 of our hunt where we left off previously:

4. Compile our target-agnostic DLL. But before that let's do one more thing. Copy the malcode which we want to execute to `Bin` directory and rename it as `payload_x64.bin` so that we can locate it while building our DLL. Finally, compile by executing `compile64.bat` from an x64 Developer Command Prompt. This will also encrypt the payload using a `Python` script before embedding it as an `RCDATA` resource in our DLL. Optionally, feel free to change the passphrase used to derive the symmetric key(you really should!) [here](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Python/AES.py#L41)

5. Once our DLL is built successfully(you can find it in `Bin` as `brownie_x64.dll`), we will move on to weaponizing it. From a Command Prompt, execute `prepdll.bat <Name of original DLL to clone>` which in our case would be `prepdll.bat DUI70`. On success message, we can find our weaponized evil-twin of `DUI70.dll` in `Bin` folder. We can further verify that `NetClone` worked as intended by inspecting PE sections too:

![Export Section](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/exports-newsection.PNG "Export Section")

6. Now all that remains is to execute our target binary `LicensingUI.exe` and wait for it to load our "evil" DLL(which in turn would also load the real DLL) and execute our malcode. Aand Bingo!

![LicensingUI](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/licensingui.PNG "LicensingUI")
Can you spot which is the real and which is our "evil" DLL? 

One thing I want to point out is that I have deliberately chosen a target that stays alive until termination in order to avoid additional complexities.

There are still tons of potential candidates waiting to be discovered and exploited and I can safely say this because I was able to find **6** previously unknown(or call it lesser-known if you will?) `System32` executables that are vulnerable to DLL Hijacking and was able to weaponize it in less than an hour.

## OPSEC Concerns
So we used a calc payload in our demonstration but almost certainly we won't be using that in a real engagement unless we want to annoy a friend right? :)

I'd **NOT** recommend using a C2 agent/Egress implant PIC blob as payload for this purpose simply because almost any half-decent AV/EDR would pick it up **especially if that executable does not load `Wininet.dll` or `Winhttp.dll` or is expected to not have any network activity**.

So what do we use for payload? I would recommend using a **loader PIC blob as payload** that injects the **Stage-1/Beaconing payload blob** to another process from where network activity is **NOT** considered unusual.

What this technique essentially helps us achieve is cloaking/shielding the malicious activity of **Code Injection** which could give us up especially when dealing with an EDR that doesn't use User-mode hooking to gain visibility into potentially suspicious actions(can be bypassed rather easily using well-placed direct syscalls) but rather relies on **Kernel-mode ETW Threat Intelligence** functions like **MDATP**. It will still **generate telemetry but will probably allow the activity since it is originating from an MS signed, trusted and legitimate binary** :)

## Detection/Mitigation
Here is a mandatory [CAPA](https://github.com/fireeye/capa) scan result of our `Brownie` DLL:

![CAPA Result](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/capa.PNG "CAPA Result")

And here is a Sysmon sample log with [SwiftOnSecurity](https://twitter.com/SwiftOnSecurity?) Sysmon configuration:

![Sysmon Normal](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/sysmon-wo-imageload.PNG "Sysmon Normal")

And here is a Sysmon sample log with Image Loaded event enabled - Sysmon Event ID 7:

![Sysmon Image Load](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/sysmon-w-imageload.PNG "Sysmon Image Load")

When it comes to Detection/Mitigation, [Samir Bousseaden](https://twitter.com/sbousseaden) is one of the best authorities to go to. 

I want to highlight [here](https://twitter.com/SBousseaden/status/1242869201091604481) one of his tweets.

In essence, a lot of false-positives could be weeded out with a rule like this if it can be made:
```
1. System32/SysWoW64 DLL loaded from anywhere other than their original location AND
2. An MS-signed binary loading a non-MS signed image
```

With that being said, I agree that this requires quite a bit of baselining in the target environment to produce high-quality telemetry.

## Credits
This section will consist of my favourite posts on DLL Hijacking and the authors from which I have heavily borrowed stuff from:

1. [https://silentbreaksecurity.com/adaptive-dll-hijacking/](https://silentbreaksecurity.com/adaptive-dll-hijacking/) - My favourite post on DLL Hijacking
2. [https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows) - Another awesome in-depth post detailing quite a number of binaries
3. [https://itm4n.github.io/windows-dll-hijacking-clarified/](https://itm4n.github.io/windows-dll-hijacking-clarified/) - Another nice read to clarify some stuff
4. [https://posts.specterops.io/automating-dll-hijack-discovery-81c4295904b0](https://posts.specterops.io/automating-dll-hijack-discovery-81c4295904b0) - Tbh has SpecterOps team ever disappointed?
5. [https://blog.nviso.eu/2020/10/06/mitre-attack-turned-purple-part-1-hijack-execution-flow/](https://blog.nviso.eu/2020/10/06/mitre-attack-turned-purple-part-1-hijack-execution-flow/) - One of the newer posts
6. [https://redteaming.co.uk/2020/07/12/dll-proxy-loading-your-favorite-c-implant/](https://redteaming.co.uk/2020/07/12/dll-proxy-loading-your-favorite-c-implant/) - Here's to our favourite Flangvik whose work inspired me to look into DLL Hijacks
7. [@SBousseaden](https://twitter.com/sbousseaden) for the detection methodologies
8. [@reenz0h](https://twitter.com/Sektor7Net) and [RTO: MalDev course](https://institute.sektor7.net/red-team-operator-malware-development-essentials) for the templates that I keep using to this date

## Author
Upayan ([@slaeryan](https://twitter.com/slaeryan)) [[slaeryan.github.io](https://slaeryan.github.io)]

## License
All the code included in this project(excluding NetClone) is licensed under the terms of the GNU GPLv2 license.

#

[![](https://img.shields.io/badge/slaeryan.github.io-E5A505?style=flat-square)](https://slaeryan.github.io) [![](https://img.shields.io/badge/twitter-@slaeryan-00aced?style=flat-square&logo=twitter&logoColor=white)](https://twitter.com/slaeryan) [![](https://img.shields.io/badge/linkedin-@UpayanSaha-0084b4?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/upayan-saha-404881192/)
