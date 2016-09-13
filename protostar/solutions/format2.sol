In this challenge we wish to overwrite the global variable target with a value of 64.  objdump -t gives the address of target, namely, 0x080496e4.

We then input a series of 'a' chars followed by a few %x chars to reveal how many %x are required before printf's routine starts grabbing arguments from our format string.
This info is used so that the arg for %n will be grabbed from the beginning of our format string in buffer.  Now, we simply replace the first 4 'a' chars with the address of target, and adjust the number of 'a' chars until we get the desired result.

In my environment the following was used as the winning input.

\xe4\x96\x04\x08aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%x%x%x%n

The following wrapper was used to launch the program so non-printable chars could be provided as input.

while read -r line; do echo -e $line; done | ./format2