;   _______________________________________________
;   |n_sys  |1   |2   |3   |4   |5   |6   |result |
;   |rax    |rdi |rsi |rdx |r10 |r8  |r9  |rax    |
;   ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

global start

start:
    xor rax, rax
    xor rdi, rdi
    xor rdx, rdx

	mov r13, 0xffffffff ; new entry
	mov r12, 0xffffffff ; size text section
	mov r11, 0xffffffff ; offset text section

	lea rdi, [ rel start ]
	neg r13
	add rdi, r13
	add rdi, r11
	mov r10, rdi
	and rdi, -0x1000
	neg rdi
	add r10, rdi
	neg rdi
	add r12, r10

	mov rax, 0xa ; chiamata a mprotect per avere i permessi di scrittura su .text per decriptare
	mov rsi, r12 ; grandezza della sezione
	mov rdx, 0x07 ; PROT_READ | PROT_WRITE | PROT_EXEC
	syscall

    add rdi, r10 ; offset section text
    neg r10
    add r12, r10 ; ripristino size

    mov rdx, r12 ; size tot
    mov rsi, rdi ; section offset
    mov rax, -1

    jmp key
decrypt:
   	pop r9 ; key string
   	mov r10, 0xa ; key len
   	xor ecx, ecx ; contatore key len
   	xor r11, r11
loop:
   	inc rax ; incremento contatore sezione .text
   	mov r8, [r9 + rcx]
   	xor byte [rsi + rax], r8b ; xor tra carattere sezione .text e carattere key
   	inc cl ; incremento contatore stringa key
   	cmp byte [r9 + rcx], 0 ; controllo se la stringa della key sia finita
   	cmove ecx, r11d ; se la stringa key è finita la riposiziono all'inizio
   	cmp rax, rdx ; controllo se sono arrivato alla fine della sezione .text
   	jb loop ; se non sono alla fine della sezione .text riparte il loop

    ;exit(result)
    ;	mov	rdi,rcx			; result
    ;	mov	rax,60			; exit(2)
    ;	syscall

	jmp string ; tecnica jmp-call-pop https://marcosvalle.github.io/osce/2018/05/06/JMP-CALL-POP-technique.html

print:
	mov rax, 0x1 ; sys_call write
	mov rdi, 0x1 ; 1# arg -> fd stdout
	pop rsi ; 2# arg -> inserisco in rsi la string pushata da call
	mov rdx, 0xe ; 3# arg -> len stringa = 14
	syscall
	jmp end

key:
	call decrypt
	db `KeyDecrypt`, 0x0

string:
	call print
	db `....WOODY....\n`
end:
	xor rax, rax
	xor rdi, rdi
	xor rdx, rdx
	xor rsi, rsi
	jmp 0xffffffff