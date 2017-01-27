[section] .text

global _start
global FreeBranchTesteax
global FreeBranchTestecx
global FreeBranchTestedx
global FreeBranchTestebx
global FreeBranchTestebp
global FreeBranchTestesi
global FreeBranchTestEDI

LocationOfStart dd _start

ErrorLoc:
	INT3
	INT3
	INT3
	INT3
	INT3
	INT3
_start:
	mov eax, FreeBranchTesteax
	call eax
	cmp ecx, 1
	jne ErrorLoc
	
	mov ecx, FreeBranchTestecx
	call ecx
	cmp ecx, 2
	jne ErrorLoc

	mov edx, FreeBranchTestedx
	call edx
	cmp ecx, 3
	jne ErrorLoc
 
	mov ebx, FreeBranchTestebx
	call ebx
	cmp ecx, 4
	jne ErrorLoc

	mov ebp, FreeBranchTestebp
	call ebp
	cmp ecx, 5
	jne ErrorLoc

	mov esi, FreeBranchTestesi
	call esi
	cmp ecx, 6
	jne ErrorLoc
	
	mov EDI, FreeBranchTestEDI
	call EDI
	cmp ecx, 7
	jne ErrorLoc
	
	jmp dword [LocationOfStart]
	ret
	
FreeBranchTestEDI:
	call FreeBranchTestesi
	cmp ecx, 6
	jne ErrorLoc
	xor eax, eax
	mov ecx, 7
	push edx
	pop edx
	ret 
	
FreeBranchTestesi:
	call FreeBranchTestebp
	cmp ecx, 5
	jne ErrorLoc
	
	xor eax, eax
	mov ecx, 6
	push edx
	pop edx
	ret 
	
FreeBranchTestebp:
	call FreeBranchTestebx
	cmp ecx, 4
	jne ErrorLoc
	
	xor eax, eax
	mov ecx, 5
	push edx
	pop edx
	ret 	
	
FreeBranchTestebx:
	call FreeBranchTestedx
	cmp ecx, 3
	jne ErrorLoc
	
	xor eax, eax
	mov ecx, 4
	push edx
	pop edx
	ret 
	
FreeBranchTestedx:
	call FreeBranchTestecx
	cmp ecx, 2
	jne ErrorLoc
	
	xor eax, eax
	mov ecx, 3
	push edx
	pop edx
	ret 
	
FreeBranchTestecx:
	call FreeBranchTesteax
	cmp ecx, 1
	jne ErrorLoc
	
	xor eax, eax
	mov ecx, 2
	push edx
	pop edx
	ret 
	
FreeBranchTesteax:
	xor eax, eax
	mov ecx, 1
	push edx
	pop edx
	ret 