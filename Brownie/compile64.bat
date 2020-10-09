@ECHO OFF

python Python\\aes.py Bin\\payload_x64.bin Bin\\payload_x64_encrypted.bin
rc Src\\Resource.rc
cvtres /MACHINE:x64 /OUT:Src\\Resource.o Src\\Resource.res
cl.exe /nologo /MT /Od /GS- /DNDEBUG /W0 /Tp Src\\DllProxyTemplate.cpp /link Src\\Resource.o Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /DLL /NODEFAULTLIB /ENTRY:DllMain /OUT:Bin\\brownie_x64.dll /MACHINE:x64 /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
del *.obj
del Src\\Resource.o
del Src\\Resource.res