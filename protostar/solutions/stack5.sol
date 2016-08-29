Stack5 turned out to be rather interesting.  In this challenge we try to inject our own shellcode and jump to it to achieve execution.  We rely on overflowing a stack based buffer to overwrite the return address.

What made it so interesting was naturally, injecting our own code, but also since I'm analyzing the binaries outside the challenge supplied VM I had to deal with ASLR.  Note, I did not overcome ASLR in any clever way, but rather had to learn how to turn it off in Linux.  Moreover, ASLR was only moving the stack around, not the text portion of the executable.  This didn't happen with each instance when running the program in gdb, so it wasn't immediately clear why my inputs failed when simply running the program outside of gdb.  In order to figure out what was going on I used gdb to attach to the process via the command gdb -p `pgrep stack5`.

However, kernel hardening made attaching difficult, and in fact seemingly impossible in my Cloud9 environment.  Whence, I spun up an EC2 instance of Ubuntu, attached to the process and learned the stack was jumping around.  This led me to suspect ALSR, so I disabled it running: echo 0 > /proc/sys/kernel/randomize_va_space.  Having changed this setting, I could launch the program and maintain expect the stack would be configured somewhat uniformly at run time.

With this done it was quite simple to exploit.  I found some shell code online at: http://shell-storm.org/shellcode/files/shellcode-827.php, and injected it with the following input:
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x80\xd6\xff\xff\x90\xd6\xff\xff

I used the following wrapper as in other exercises to input non-printable character to stdin of stack5:
while read -r line; do echo -e $line; done | ./stack5

Note, the 23 bytes of shellcode followed by a string of 'a' chars.  Following the 'a' chars are the the inputs to overwrite the saved %ebp and %eip.  Note, the further left a byte is in the input above, the lower its address in memory.  Whence, 0xffffd690 will be represented in memory correctly using the above input.

