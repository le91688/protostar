Enter the following commands in BASH to set the environment variable GREENIE:

1)  GREENIE=`echo -e "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1234\x0a\x0d\x0a\x0d"`
2)  export GREENIE

Next run the binary stack2 from the same shell session you ran the above commands and win!

Line 1 above assignes the winning input to a variable GREENIE in bash.  Line 2 exports GREENIE as an environment variable.  Note, GREENIE is assigned a value that is longer than 64 bytes (the ascii character '4' is the 64th byte) so when we copy the contents of GREENIE into buffer (line 20 of the source code) it will overflow the buffer defined in the source code for this exercise.  

Because of modified's position on the stack it will be overwritten by the hex value 0x0d0a0d0a.  Note, the value of GREENIE will be stored with 'a' in the lowest memory address.  Whence, we overwrite modify with the appropriate value by writing 0xa in the least significant byte position (little endian), i.e., the lowest addressed byte of modify.