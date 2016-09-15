#include <sys/socket.h> //provides sockets and related structs and funcs.
#include <netinet/in.h>  //provides INADDR_ANY ip address
#include <stdio.h>
#include <string.h>

int main()
{
    //Step 1: open a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if( sock < 0 )
    {
        puts("socket open failed");
        return -1;
    }
    
    //Step 2: bind to port/address.
    //We skip step 2 on the client side and let an arbitrary ephemeral port get assigned.
    
    //Step 3:  Connect to the server.
    //Connect to server.  This requires an address structure to define the server ip/port.
    struct sockaddr_in sock_address; //this structure required by connect function.
    memset(&sock_address, 0, sizeof(sock_address));
    sock_address.sin_family = AF_INET; //internet family
    struct in_addr server_address; //the s_addr member of this will be the ip address of the server
    //0x7f000001 is the hex representation of 127.0.0.1  
    //htonl converts this integer from little endian (x86 host) to big endian (network)
    server_address.s_addr = htonl(0x7f000001);
    sock_address.sin_addr = server_address;
    sock_address.sin_port = htons(2998); //see exercise source code
    if( connect(sock, (struct sockaddr *) &sock_address, sizeof(sock_address)) < 0 )
    {
        puts("connection failed");
        return -1;
    }
    
    //Step 4: Read/write to socket
    char buffer_in[200], buffer_out[100];
    memset(buffer_in, 0, sizeof(buffer_in));
    puts("attempting to read");
    read(sock, buffer_in, sizeof(buffer_in));
    snprintf(buffer_out, sizeof(buffer_out), "%d", (int)*(int *)buffer_in);
    int len = strlen(buffer_out);
    buffer_out[strlen(buffer_out)] = '\n';
    buffer_out[strlen(buffer_out)] = '\r';
    buffer_out[strlen(buffer_out)] = '\0';
    len += 3;
    
    write(sock, buffer_out, len);
    memset(buffer_in, 0, sizeof(buffer_in));
    read(sock, buffer_in, 50 );
    puts(buffer_in);
    return 0;
}