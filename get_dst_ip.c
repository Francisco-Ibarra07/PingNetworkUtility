#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

int main(int argc, char** argv) {

  if (argc != 2) {
    printf("\nUsage: sudo %s <hostname or ip address>", argv[0]);
    exit(1);
  }

  printf("Starting\n");

  char *input = argv[1];
  struct hostent *dst_hostent; 

  // Get host information and store in struct hostent
  dst_hostent = gethostbyname(input);
  if (dst_hostent == NULL) {
    perror("Error on gethostbyname()");
    exit(1);
  }
  
  // IP string and using inet_ntoa using h_addr and casting to struct in_addr*
  struct in_addr *dst_addr = (struct in_addr*) dst_hostent->h_addr_list[0];
  char* IP = inet_ntoa(*dst_addr);
  
  printf("IP for host %s: %s\n", input, IP);
  printf("End\n");
}
