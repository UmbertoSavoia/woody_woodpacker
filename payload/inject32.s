;   _______________________________________________
;   |n_sys  |1   |2   |3   |4   |5   |6   |result |
;   |eax    |ebx |ecx |edx |esi |edi |ebp |eax    |
;   ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

global start

start:
	pusha
	call get_eip
	mov ebx, eax
	sub ebx, 6

	mov ecx, 0xffffffff ; new entry
	mov edx, 0xffffffff ; size text section
	mov esi, 0xffffffff ; offset text section

	sub edx, 100 ; <--------

	; raggiungo la posizione della sezione text
	neg ecx
	add ebx, ecx
	add ebx, esi
	; allineo ebx per mprotect
	mov edi, ebx
	and ebx, -0x1000
	;
	neg ebx
	add edi, ebx
	neg ebx
	add edx, edi


	mov eax, 0x7d ; chiamata a mprotect per avere i permessi di scrittura su .text per decriptare
	mov ecx, edx ; grandezza della sezione
	mov edx, 0x07 ; PROT_READ | PROT_WRITE | PROT_EXEC
	int 0x80

	add ebx, edi
	neg edi
	add edx, edi

	; ebx text offset
	; ecx text size

decrypt:
	mov eax, -1
loop:
	inc eax;
	xor byte [ebx + eax], 0x41
	cmp eax, ecx
    jb loop

   ;exit(result)
    ;	mov	ebx, eax			; result
    ;	mov	eax,1			; exit(2)
    ;	int 0x80

	jmp string ; tecnica jmp-call-pop https://marcosvalle.github.io/osce/2018/05/06/JMP-CALL-POP-technique.html

get_eip:
	mov eax, [esp]
    ret

print:

	mov eax, 0x4 ; sys_call write
	mov ebx, 0x1 ; 1# arg -> fd stdout
	pop ecx ; 2# arg -> inserisco in esi la string pushata da call
	mov edx, 0xe ; 3# arg -> len stringa = 14
	int 0x80 ; syscall per architettura 32bit

	jmp end

;key:
;	call decrypt
;	db `KeyDecrypt`, 0x0

string:
	call print
	db `....WOODY....\n`
end:
	xor eax, eax
	xor edi, edi
	xor edx, edx
	xor esi, esi
	popa
	jmp 0xffffffff