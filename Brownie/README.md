# Brownie
[![](https://img.shields.io/badge/Category-Defense%20Evasion-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Language-C%20%2f%20C++%20%2f%20CSharp%20%2f%20Python3-E5A505?style=flat-square)]()

## Introduction
`Brownie` is a platform to rapidly prototype and weaponise DLL hijacks. In particular, we are interested in [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/) to sideload our malicious code by a signed and legitimate executable which is sometimes wrongly(or rightly?) known as [DLL Sideloading](https://attack.mitre.org/techniques/T1574/002/) which has a very specific definition.

We are particularly interested in how this technique is an interesting(and often underrated) alternative to **Code Injection** that shares the same objectives i.e. to evade AV/EDRs by executing malicious code from the address space of a "trusted" process. We won't looking at DLL hijacks for LPE or even Persistence as such although it can certainly be adapted for the latter purpose quite easily.

This post will be heavily borrowing from public research and it was a personal note before I decided to release it by packaging it up nicely with a bow.

So without any further ado, let's get started!

## How To:
As a quick recap here is the highlighted DLL Search Order that we will be targeting considering `SafeDllSearchMode` is turned **ON**.

![DLL Search Order](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/dll-search-order.png "DLL Search Order")

Furthermore, we will be targeting `System32` executables for this demonstration and won't be targeting third-party applications since those are target-specific.

So we will be using a slight variation of this technique known as **Relative Path DLL Hijacking** i.e. dropping the malicious DLL in a user-writeable folder and copying the legitimate, signed executable from `System32` to the folder before executing it finally to load our "evil" DLL.

Our first order of business is finding the right candidate for the job. There are many automated tools to do that and I found a wonderful [post](https://github.com/wietze/windows-dll-hijacking) that details almost 300 executables in `System32` that are vulnerable to DLL Hijacking but what kind of hackers would we be if we didn't try to find our own?

Almost always, you'll hear someone say that DLL hijacks in Windows executables are a plentiful. I fully agree considering the evidence. But that doesn't always mean that we have found the perfect candidate to exploit.

For example: Some applications are GUI that contains visual elements which upon execution will immediately notify the target effectively rendering it useless for use in covert operations.

With all that mind, we will initiate our good old-fashioned hunt!

The algorithm for the hunt goes something like:
1. Copy the executable from `System32` to our current working directory

![Target Executable](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/target-exe.PNG "Target Executable")

2. Run procmon with primarily two filters: 
Result contains NOT FOUND -> include & Path ends with .dll -> include

![ProcMon Filter](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/procmon-filter.PNG "ProcMon Filter")

3. Finally, execute the binary

![Hijackable DLL found](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/hijackable-dll-found.PNG "Hijackable DLL found")

Aand profit!!!

So if we rename an arbritrary DLL to `DUI70.dll` in the application's directory, it should get loaded by our target executable which in turn should execute our malcode right?

![No Go](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/no-go.PNG "No Go")

Welp not quite :(

Process Monitor logs clearly shows that `DUI70.dll` is searched by `LicensingUI.exe` from the same directory it is executed from following the DLL Search Order in abscence of absolute path in `LoadLibrary` call. So what happened?

Well if you think about it, it's not that the executable is loading the `DUI70` DLL because it just felt like doing so right? After all it is being loaded for a purpose because the executable needs to perform some function(s) defined in the DLL which our "evil" DLL is obviously missing that in this case also causes the application to not start properly/crash i.e. We do not maintain stability in the target executable.

So how do we solve this problem? By using DLL Proxying or delegating the functionality to the real DLL by linking the export table of "evil" DLL to the original DLL.

![DLL Proxying](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/dll-proxying.png "DLL Proxying")

One of the simplest ways to implement this is by **export forwarding using linker redirects**. In other words, cloning all the exported functions from the real DLL and redirecting them to the real DLL and letting the Windows loader subsystem do the rest of the work for us.

```
#pragma comment(linker, "/export:{exportedFunctionName}={realDLLName/FullPath}.{exportedFunctionName},@{exportedFunctionalOrdinal}")
```

Here we can clearly examine the exports of our "evil" `DUI70.dll` redirected to the real `DUI70.dll` in `System32` using PEStudio:

![Export Forwarding](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/exports-forwarded.PNG "Export Forwarding")

There is wonderful tool written by [Melvin Langvik](https://twitter.com/Flangvik) named [SharpDllProxy](https://github.com/Flangvik/SharpDllProxy) that aims to automate the mentioned process. While it is a nice alternative, for the purposes of our experiment, I found notably two problems with this approach:

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

What this essentially mean for us attackers? This means that now we can weaponize our abritrary DLL post-build without needing to re-compile for testing multiple targets.

Oh and if you haven't yet read the above post, I'd implore the readers to do so before continuing further.

I have already prepped our target-agnostic DLL which embeds the payload(malcode which we want to be executed) in the `Resource` section of PE. Upon loading, it extracts the payload from `rsrc` and executes it locally in a separate thread(to avoid loader lock complexities).

One thing I've noticed is that as soon I dropped our "evil" DLL in our testing VM, it'd almost immediately get detected and quarantined by Defender AV. Bummer :(

Upon closer signature inspection with [DefenderCheck](https://github.com/matterpreter/DefenderCheck) by [Matt Hand a.k.a. matterpreter](https://twitter.com/matterpreter), I'd soon learn that the [Metasploit]() calc shellcode signature is what got our _well-behaved_ DLL in trouble.

On learning this, I have taken the liberty the encrypt the payload with AES-256 in CBC mode with a random IV and adding code to our DLL which will decrypt the payload after resource extraction ergo you can say goodbye to static detections.

![Evading Defender Signature](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/evading-defender-sig.PNG "Evading Defender Signature")

I have also taken the liberty to build the `NetClone` project from **Koppeling** and `ILMerge`d all the dependency DLLs together into a portable package so that you don't have to(No need to thank me :) )

So continuing from Step 3 of our hunt where we left off previously:

4. Compile our target-agnostic DLL. But before that let's do one more thing. Copy the malcode which we want to execute to `Bin` directory and rename it as `payload_x64.bin` so that we can locate it while building our DLL. Finally, compile using:

From a x64 Developer Command Prompt, execute `compile64.bat`. This will also encrypt the payload using a `Python` script before embedding it as a `RCDATA` resource in our DLL.

Optionally, feel free to change the passphrase used to derive the symmetric key(you really should!) [here](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Python/AES.py#L41)

5. Once our DLL is built successfully(you can find it in `Bin` as `brownie_x64.dll`), we will move on to weaponizing it.

From a Command Prompt, execute `prepdll.bat <Name of original DLL to clone>` which in our case would be `prepdll.bat DUI70`.

On success message, we can find our weaponized evil-twin of `DUI70.dll` in `Bin` folder. We can further verify that `NetClone` worked as intended by inspecting PE sections:

![Export Section](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/exports-newsection.PNG "Export Section")

6. Now all that remains is to execute our target binary `LicensingUI.exe` and wait for it to load our "evil" DLL(which in turn would also load the real DLL) and execute our malcode. Aand Bingo!

![LicensingUI](https://github.com/slaeryan/AQUARMOURY/blob/master/Brownie/Screenshots/licensingui.PNG "LicensingUI")















