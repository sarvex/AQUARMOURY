# Usage

1. Copy the PIC blob to Bin directory and rename it as "payload_x64.bin"
2. Copy the target executable to Bin directory
3. compile64.bat
4. prepdll.bat [name of hijackable dll without extension]
5. Execution of the target executable should result in successful implant DLL load and ergo, payload execution
6. Copy implant DLL from Bin