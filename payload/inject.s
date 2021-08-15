;   _______________________________________________
;   |n_sys  |1   |2   |3   |4   |5   |6   |result |
;   |rax    |rdi |rsi |rdx |r10 |r8  |r9  |rax    |
;   ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

global start

start:
    xor rax, rax
    xor rdi, rdi
    xor rdx, rdx
	jmp string ; tecnica jmp-call-pop https://marcosvalle.github.io/osce/2018/05/06/JMP-CALL-POP-technique.html

print:
	mov rax, 0x1 ; sys_call write
	mov rdi, 0x1 ; 1# arg -> fd stdout
	pop rsi ; 2# arg -> inserisco in rsi la string pushata da call
	mov rdx, 0xe ; 3# arg -> len stringa = 14
	syscall
	jmp end

string:
	call print
	db `....WOODY....\n`
end:
	xor rax, rax
	xor rdi, rdi
	xor rdx, rdx
	xor rsi, rsi
	jmp 0xffffffff