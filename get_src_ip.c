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

  if(gethostname(src_hostname, sizeof(src_hostname)) < 0) {
    perror("Error on gethostname()");
    exit(1);
  }
  printf("Source hostname: %s\n", src_hostname);

  src_hostent = gethostbyname(src_hostname);
  if (src_hostent == NULL) {
    perror("Error on gethostbyname()");
    exit(1);
  }
  
  char *temp = src_hostent->h_aliases[0];
  printf("Temp: %s\n", temp);
  
  printf("h length: %d\n", src_hostent->h_length);
  printf("h type: %d\n", src_hostent->h_addrtype);
  printf("h name: %s\n", src_hostent->h_name);
  printf("End\n");
}


