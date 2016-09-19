In this exercise we will overwrite a pointer on the heap to execute the winner() function.

Referring to the source code we can see the internet structure pointed to by i1, and i1->name will sit on the heap at an address just below i2->priority.
GDB can be used to determine i1->name is 20 bytes below i2->name in memory.  Now we use the unsafe strcpy() function to overflow the buffer allocated for i1->name in order to overwrite i2->name with an address of our choosing.
I chose to overwrite the address returned to by the main function.  The overwrite occurs with the second call to strcpy() and copies our second parameter to the address we chose to overwrite i2->name with.
Whence, if we supply the address of winner() as our second parameter we win.  Entering the following at the command line won the round in my environment.

./heap1 `echo -e "aaaaaaaaaaaaaaaaaaaa\x6c\xd6\xff\xff"` `echo -e "\x94\x84\x04\x08"`