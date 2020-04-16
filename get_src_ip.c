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


int main() {
  printf("Starting\n");
  char src_ip[32];
  char src_hostname[32];
  struct hostent *src_hostent; 

  // Get localhost name and store it in a char array
  if(gethostname(src_hostname, sizeof(src_hostname)) < 0) {
    perror("Error on gethostname()");
    exit(1);
  }
  printf("Source hostname: %s\n", src_hostname);

  // Get host information and store in struct hostent
  src_hostent = gethostbyname(src_hostname);
  if (src_hostent == NULL) {
    perror("Error on gethostbyname()");
    exit(1);
  }
  
  // IP string and using inet_ntoa using h_addr and casting to struct in_addr*
  struct in_addr *host_addr = (struct in_addr*) src_hostent->h_addr_list[0];
  char* IP = inet_ntoa(*host_addr);
  
  printf("IP: %s\n", IP);
  printf("End\n");
}


