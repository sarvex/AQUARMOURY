@ECHO OFF

ml64.exe /c /Cx Src\\syscalls64.asm
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W0 /Tp Src\\dllmain.cpp /link syscalls64.obj Kernel32.lib Ole32.lib OleAut32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /DLL /NODEFAULTLIB /ENTRY:DllMain /OUT:Bin\\wraith_x64.dll /MACHINE:x64 /STUB:Src\\stub.bin /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
cd Python & python ConvertToShellcode.py -c -f "" -u "" -i ..\\Bin\wraith_x64.dll & cd ..
sgn\\sgn.exe -a 64 -c 6 -plain-decoder -o Bin\\wraith_x64_encoded.bin Bin\\wraith_x64.bin
del dllmain.obj
del syscalls64.obj