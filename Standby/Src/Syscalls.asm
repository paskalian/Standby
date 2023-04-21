IFDEF RAX ; 64-bit
.CODE

NtOpenProcess proc
 
	mov r10, rcx
	mov eax, 26h
	test byte ptr [7FFE0308h], 1 ; KUSER_SHARED_DATA.SystemCall
	jnz short SYSCALL_DEFINED
	syscall
	ret
SYSCALL_DEFINED:
	int 2Eh
 
NtOpenProcess endp

NtAllocateVirtualMemory proc
 
	mov r10, rcx
	mov eax, 18h
	test byte ptr [7FFE0308h], 1 ; KUSER_SHARED_DATA.SystemCall
	jnz short SYSCALL_DEFINED
	syscall
	ret
SYSCALL_DEFINED:
	int 2Eh
 
NtAllocateVirtualMemory endp

NtFreeVirtualMemory proc
 
	mov r10, rcx
	mov eax, 1Eh
	test byte ptr [7FFE0308h], 1 ; KUSER_SHARED_DATA.SystemCall
	jnz short SYSCALL_DEFINED
	syscall
	ret
SYSCALL_DEFINED:
	int 2Eh
 
NtFreeVirtualMemory endp

NtReadVirtualMemory proc
 
	mov r10, rcx
	mov eax, 3Fh
	test byte ptr [7FFE0308h], 1 ; KUSER_SHARED_DATA.SystemCall
	jnz short SYSCALL_DEFINED
	syscall
	ret
SYSCALL_DEFINED:
	int 2Eh
 
NtReadVirtualMemory endp

NtWriteVirtualMemory proc
 
	mov r10, rcx
	mov eax, 3Ah
	test byte ptr [7FFE0308h], 1 ; KUSER_SHARED_DATA.SystemCall
	jnz short SYSCALL_DEFINED
	syscall
	ret
SYSCALL_DEFINED:
	int 2Eh
 
NtWriteVirtualMemory endp

NtProtectVirtualMemory proc
 
	mov r10, rcx
	mov eax, 50h
	test byte ptr [7FFE0308h], 1 ; KUSER_SHARED_DATA.SystemCall
	jnz short SYSCALL_DEFINED
	syscall
	ret
SYSCALL_DEFINED:
	int 2Eh
 
NtProtectVirtualMemory endp

NtCreateThreadEx proc
 
	mov r10, rcx
	mov eax, 0C7h
	test byte ptr [7FFE0308h], 1 ; KUSER_SHARED_DATA.SystemCall
	jnz short SYSCALL_DEFINED
	syscall
	ret
SYSCALL_DEFINED:
	int 2Eh
 
NtCreateThreadEx endp



ELSE ; 32-bit
.386P
.MODEL FLAT, C

.CODE



NtOpenProcess proc
 
	mov eax, 26h
	syscall
	ret
 
NtOpenProcess endp

NtAllocateVirtualMemory proc
 
	mov eax, 18h
	syscall
	ret
 
NtAllocateVirtualMemory endp

NtFreeVirtualMemory proc
 
	mov eax, 1Eh
	syscall
	ret
 
NtFreeVirtualMemory endp

NtReadVirtualMemory proc
 
	mov eax, 3Fh
	syscall
	ret
 
NtReadVirtualMemory endp

NtWriteVirtualMemory proc
 
	mov eax, 3Ah
	syscall
	ret
 
NtWriteVirtualMemory endp

NtProtectVirtualMemory proc
 
	mov eax, 50h
	syscall
	ret
 
NtProtectVirtualMemory endp

NtCreateThreadEx proc
 
	mov eax, 0C7h
	syscall
	ret
 
NtCreateThreadEx endp




ENDIF



END