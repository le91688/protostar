In this challenge we'll attempt to execute code that can't simply be placed on the stack.

Since we can't return to the stack which we control, we'll have to return to a different executable area to attempt to gain control.

First approach: return to libc.
We see in the source that multiple headers will be included, each corresponding to a library that will be loaded, in this case at run time.
We'll use code from such dynamic library to launch a shell.  In this case, well use the function system() from the standard C library.
Launch the program using our wrapper to enable input of arbitrary bytes: while read -r line; do echo -e $line; done | ./stack6.

Note the declaration of system: int system(const char *cmd) from the standard library.  So, in source code, if we wish to lauch a shell we would call system("/bin/sh").
We'll use gdb to find the location of system() in libc at run time.  Also, we should be able to find a reference to "/bin/sh" via gdb.  We'll use these two bits of info to structure the stack in such a way that we return to system with a pointer to "/bin/sh" passed as an argument.

From another shell launch:
gdb -p `pgrep stack6`
.
In gdb we type the following:
print &system 
We discover system is at 0x0xf7e60e70 (at least on my machine, which differs from the VM provided in the challenges).  Then, we'll use the following command in gdb to get a pointer to "/bin/sh":
find &system, +999999999, "/bin/sh" 
This gives an address for "/bin/sh" at 0xf7f7ea8c.

We have:
0xf7e60e70  address of system
0xf7f7ea8c  address of /bin/sh

Next, we use objdump -d to see the start of buffer is 0x4C bytes below the $ebp.  So we'll fill buffer with 0x4c 'a' chars, overwrite saved ebp with 'bbbb', and saved $eip with the address of system.  Finally, we'll overwrite a dummy saved $eip and then the argument for system(), namely, the pointer to "/bin/sh".  See the below winning input using the method 'return to libc':

aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbb\x70\x0e\xe6\xf7bbbb\x8c\xea\xf7\xf7


