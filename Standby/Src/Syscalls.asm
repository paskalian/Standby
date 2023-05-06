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

NtOpenThread proc
 
	mov r10, rcx
	mov eax, 137h
	test byte ptr [7FFE0308h], 1 ; KUSER_SHARED_DATA.SystemCall
	jnz short SYSCALL_DEFINED
	syscall
	ret
SYSCALL_DEFINED:
	int 2Eh
 
NtOpenThread endp

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

ENDIF
END