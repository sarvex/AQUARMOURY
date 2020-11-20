@ECHO OFF

rc Src\\Resource.rc
cvtres /MACHINE:x64 /OUT:Src\\Resource.o Src\\Resource.res
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W0 /Tp Src\\dllmain.cpp /link Src\\Resource.o Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /DLL /NODEFAULTLIB /ENTRY:DllMain /OUT:Bin\\gnome_x64.dll /MACHINE:x64 /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
cd Python & python ConvertToShellcode.py ..\\Bin\gnome_x64.dll & cd ..
copy Bin\gnome_x64.bin Z:\
del dllmain.obj
del Src\\Resource.o
del Src\\Resource.res