;   _______________________________________________
;   |n_sys  |1   |2   |3   |4   |5   |6   |result |
;   |eax    |ebx |ecx |edx |esi |edi |ebp |eax    |
;   ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

global start

start:
;	push ebx
;	push esp
;	push ebp
;
;	mov edi, 0xffffffff ; new entry
;	mov esp, 0xffffffff ; size text section
;	mov ebp, 0xffffffff ; offset text section
;
;	lea ebx, [ rel start ]
;	neg edi
;	add ebx, edi
;	add ebx, ebp			;   ebx      ok da qui in giu
;	mov edi, ebx
;	and ebx, -0x1000
;	neg ebx
;	add edi, ebx
;	neg ebx
;	add esp, edi
;
;	mov eax, 0xa ; chiamata a mprotect per avere i permessi di scrittura su .text per decriptare
;	mov ecx, esp ; grandezza della sezione
;	mov edx, 0x07 ; PROT_READ | PROT_WRITE | PROT_EXEC
;	;int 0x80
;
;    add ebx, edi ; offset section text
;    neg edi
;    add esp, edi ; ripristino size
;
;    mov edx, esp ; size tot
;    mov ecx, ebx ; section offset
;    mov eax, -1
;
;    jmp key
;decrypt:
;   	pop esp ; key string
;   	mov edi, 0xa ; key len
;   	xor esi, esi ; contatore key len
;   	xor ebp, ebp
;loop:
;   	inc eax ; incremento contatore sezione .text
;   	mov ebx, [esp + esi]
;   	;xor [ecx + eax], ebx ; xor tra carattere sezione .text e carattere key
;   	inc cl ; incremento contatore stringa key
;   	cmp byte [esp + esi], 0 ; controllo se la stringa della key sia finita
;   	cmove esi, ebp ; se la stringa key è finita la riposiziono all'inizio
;   	cmp eax, edx ; controllo se sono arrivato alla fine della sezione .text
;   	jb loop ; se non sono alla fine della sezione .text riparte il loop
;
;    ;exit(result)
;    ;	mov	edi,0xd			; result
;    ;	mov	eax,60			; exit(2)
;    ;	syscall
;
;	pop ebp
;	pop esp
;	pop ebx

	jmp string ; tecnica jmp-call-pop https://marcosvalle.github.io/osce/2018/05/06/JMP-CALL-POP-technique.html

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
	jmp 0xffffffff
