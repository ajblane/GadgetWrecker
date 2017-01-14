[section] .text

global _start
global FreeBranchTesteax
global FreeBranchTestecx
global FreeBranchTestedx
global FreeBranchTestebx
global FreeBranchTestebp
global FreeBranchTestesi
global FreeBranchTestEDI

_start:
	mov eax, FreeBranchTesteax
	call eax
	
	mov ecx, FreeBranchTestecx
	call ecx

	mov edx, FreeBranchTestedx
	call edx
 
	mov ebx, FreeBranchTestebx
	call ebx

	mov ebp, FreeBranchTestebp
	call ebp

	mov esi, FreeBranchTestesi
	call esi
	
	mov EDI, FreeBranchTestEDI
	call EDI
	
	jmp _start
	ret
	
FreeBranchTestEDI:
	xor eax, eax
	mov ecx, 1
	push edx
	pop edx
	ret 
	
FreeBranchTestesi:
	xor eax, eax
	mov ecx, 1
	push edx
	pop edx
	ret 
	
FreeBranchTestebp:
	xor eax, eax
	mov ecx, 1
	push edx
	pop edx
	ret 	
	
FreeBranchTestebx:
	xor eax, eax
	mov ecx, 1
	push edx
	pop edx
	ret 
	
FreeBranchTestedx:
	xor eax, eax
	mov ecx, 1
	push edx
	pop edx
	ret 
	
FreeBranchTestecx:
	xor eax, eax
	mov ecx, 1
	push edx
	pop edx
	ret 
	
FreeBranchTesteax:
	xor eax, eax
	mov ecx, 1
	push edx
	pop edx
	ret 