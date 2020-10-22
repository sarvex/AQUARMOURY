.code

; Reference: https://j00ru.vexillium.org/syscalls/nt/64/

; ---------------------------------------------------------------------
; Windows 7 SP1 / Server 2008 R2 specific syscalls
; ---------------------------------------------------------------------

NtWriteVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 37h
		syscall
		ret
NtWriteVirtualMemory7SP1 endp

NtProtectVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 4Dh
		syscall
		ret
NtProtectVirtualMemory7SP1 endp

NtReadVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 3Ch
		syscall
		ret
NtReadVirtualMemory7SP1 endp

NtQueryInformationProcess7SP1 proc
		mov r10, rcx
		mov eax, 16h
		syscall
		ret
NtQueryInformationProcess7SP1 endp

NtOpenProcess7SP1 proc
		mov r10, rcx
		mov eax, 23h
		syscall
		ret
NtOpenProcess7SP1 endp

NtAllocateVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 15h
		syscall
		ret
NtAllocateVirtualMemory7SP1 endp

NtQueueApcThread7SP1 proc
		mov r10, rcx
		mov eax, 42h
		syscall
		ret
NtQueueApcThread7SP1 endp

;----------------------------------------------------------------------
; Windows 8 / Server 2012 specific syscalls
; ---------------------------------------------------------------------

NtWriteVirtualMemory80 proc
		mov r10, rcx
		mov eax, 38h
		syscall
		ret
NtWriteVirtualMemory80 endp

NtProtectVirtualMemory80 proc
		mov r10, rcx
		mov eax, 4Eh
		syscall
		ret
NtProtectVirtualMemory80 endp

NtReadVirtualMemory80 proc
		mov r10, rcx
		mov eax, 3Dh
		syscall
		ret
NtReadVirtualMemory80 endp

NtQueryInformationProcess80 proc
		mov r10, rcx
		mov eax, 17h
		syscall
		ret
NtQueryInformationProcess80 endp

NtOpenProcess80 proc
		mov r10, rcx
		mov eax, 24h
		syscall
		ret
NtOpenProcess80 endp

NtAllocateVirtualMemory80 proc
		mov r10, rcx
		mov eax, 16h
		syscall
		ret
NtAllocateVirtualMemory80 endp

NtQueueApcThread80 proc
		mov r10, rcx
		mov eax, 43h
		syscall
		ret
NtQueueApcThread80 endp

;----------------------------------------------------------------------
; Windows 8.1 / Server 2012 R2 specific syscalls
; ---------------------------------------------------------------------

NtWriteVirtualMemory81 proc
		mov r10, rcx
		mov eax, 39h
		syscall
		ret
NtWriteVirtualMemory81 endp

NtProtectVirtualMemory81 proc
		mov r10, rcx
		mov eax, 4Fh
		syscall
		ret
NtProtectVirtualMemory81 endp

NtReadVirtualMemory81 proc
		mov r10, rcx
		mov eax, 3Eh
		syscall
		ret
NtReadVirtualMemory81 endp

NtQueryInformationProcess81 proc
		mov r10, rcx
		mov eax, 18h
		syscall
		ret
NtQueryInformationProcess81 endp

NtOpenProcess81 proc
		mov r10, rcx
		mov eax, 25h
		syscall
		ret
NtOpenProcess81 endp

NtAllocateVirtualMemory81 proc
		mov r10, rcx
		mov eax, 17h
		syscall
		ret
NtAllocateVirtualMemory81 endp

NtQueueApcThread81 proc
		mov r10, rcx
		mov eax, 44h
		syscall
		ret
NtQueueApcThread81 endp

;----------------------------------------------------------------------
; Windows 10 / Server 2016 specific syscalls
; ---------------------------------------------------------------------

NtWriteVirtualMemory10 proc
		mov r10, rcx
		mov eax, 3Ah
		syscall
		ret
NtWriteVirtualMemory10 endp

NtProtectVirtualMemory10 proc
		mov r10, rcx
		mov eax, 50h
		syscall
		ret
NtProtectVirtualMemory10 endp

NtReadVirtualMemory10 proc
		mov r10, rcx
		mov eax, 3Fh
		syscall
		ret
NtReadVirtualMemory10 endp

NtQueryInformationProcess10 proc
		mov r10, rcx
		mov eax, 19h
		syscall
		ret
NtQueryInformationProcess10 endp

NtOpenProcess10 proc
		mov r10, rcx
		mov eax, 26h
		syscall
		ret
NtOpenProcess10 endp

NtAllocateVirtualMemory10 proc
		mov r10, rcx
		mov eax, 18h
		syscall
		ret
NtAllocateVirtualMemory10 endp

NtQueueApcThread10 proc
		mov r10, rcx
		mov eax, 45h
		syscall
		ret
NtQueueApcThread10 endp

; ---------------------------------------------------------------------
  end
; ---------------------------------------------------------------------