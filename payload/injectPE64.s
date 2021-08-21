;	GetStdHandle: e688d490
;	WriteConsoleA: e68953b0
;	ExitProcess: e688e0a0
;	CloseHandle: e68948e0

global _start

section .text
 	_start:
		jmp string

	print:
		pop rsi
		mov rdi, 0x9eb5d490 ; GetStdHandle
		mov rcx, 0x9eb653b0 ; WriteConsoleA

		push	-11 ; Arg1: request handle for standard output
		call	rdi ; _GetStdHandle ; Result: in eax
		;
		; BOOL WINAPI WriteConsole(
		;       _In_        HANDLE hConsoleOutput,
		;       _In_        const VOID *lpBuffer,
		;       _In_        DWORD nNumberOfCharsToWrite,
		;       _Out_       LPDWORD lpNumberOfCharsWritten,
		;       _Reserved_  LPVOID lpReserved ) ;
		;
		push    dword 0         ; Arg5: Unused so just use zero
		push    0			 	; Arg4: push pointer to numCharsWritten
		push    0xe			    ; Arg3: push length of output string
		push    rsi             ; Arg2: push pointer to output string
		push	rax				; Arg1: push handle returned from _GetStdHandle
		call	rcx				; _WriteConsoleA
		jmp		end

	string:
		call print
		db `....WOODY....\n`

	end:
		jmp 0xffffffff

;	_start:
;		;pusha
;
;		push	-11
;		mov		rax, 0x9eb5d490
;		call	rax
;
;		push	0x000a
;		push	'COP'
;		mov		rcx, rsp
;		push	rbx
;		mov		rbx, rsp
;		push	0
;		push	rbx
;		push	5
;		push	rcx
;		mov		rdi, rax ; save handle
;		push	rax
;		mov		rax, 0x9eb653b0
;		call	rax
;
;		;popa
;
;		;close handle
;		push	rdi
;		mov		rax, 0x9eb648e0
;		call	rax
;
;
;		mov		rax, 0xFFFFFFFF
;		push	rax
;		ret