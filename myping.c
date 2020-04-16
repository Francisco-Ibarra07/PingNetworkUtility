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

/* One's Complement checksum algorithm */
unsigned short cksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

    if (nleft == 1)
    {
      *(unsigned char *)(&answer) = *(unsigned char *)w;
      sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return (answer);
}

// TODO: Checksum is not correct
// TODO: icmp messages stopped showing up? Needs a reboot maybe
// TODO: Change way that you get source IP
// TODO: Implement check for argv to get dst hostname or ip
// TODO: Maybe switch to ip instead of iphdr
int main(int argc, char *argv[]) {

  // Make sure file is ran with 'sudo'
  if (getuid() != 0) {
    perror("This program requires it to be ran as root");
    exit(EXIT_FAILURE);
  }

  // Make sure user inputted a hostname or ip address
  if (argc != 2) {
    printf("\nUsage: sudo %s <hostname or ip address>", argv[0]);
    exit(1);
  }

  printf("Starting\n");

  // Get source IP address
  char src_hostname[32];
  struct hostent *src_hostent; 
  if(gethostname(src_hostname, sizeof(src_hostname)) < 0) {
    perror("Error on gethostname()");
    exit(1);
  }
  src_hostent = gethostbyname(src_hostname);
  if (src_hostent == NULL) {
    perror("Error on gethostbyname()");
    exit(1);
  }
  struct in_addr *src_addr = (struct in_addr*) src_hostent->h_addr_list[0];
  char* src_ip_str = inet_ntoa(*src_addr);
  printf("Source hostname: %s\n", src_hostname);
  printf("Source IP address: %s\n", src_ip_str);
  puts("");

  // Get destination IP address
  char *user_input = argv[1];
  struct hostent *dst_hostent = gethostbyname(user_input);
  if (dst_hostent == NULL) {
    perror("Error on gethostbyname()");
    exit(1);
  }
  struct in_addr *dst_addr = (struct in_addr*) dst_hostent->h_addr_list[0];
  char* dst_ip_str = inet_ntoa(*dst_addr); 
  printf("IP for host %s: %s\n", user_input, dst_ip_str);
  
  // User input stuff
  char *TEMP_SRC_IP = "192.168.0.6"; // my temp ip
  char *TEMP_TEST_IP = "104.17.176.85"; // cloudflare.com
  char *TEMP_TEST_HOSTNAME = "google.com";

  // Socket/Host stuff :p
  int socket_fd;
  struct sockaddr_in server_sock_addr;
  struct hostent *server_hostent;
  struct hostent *source_hostent;

  // Network layer stuff :p
  char src_ip[32];
  char dst_ip[32];
  char datagram[20];
  memset(datagram, 0, sizeof(datagram));
  char recieving_buffer[500];
  struct iphdr *ip_header = (struct iphdr*) datagram;
  struct icmphdr *icmp_header = (struct icmphdr*) (ip_header + 1);

  // Get destination ip address
  server_hostent = gethostbyname(TEMP_TEST_HOSTNAME);
  if (server_hostent == NULL) {
    perror("Hostname/IP does not exist");
    exit(1);
  }
  server_sock_addr.sin_addr = (*(struct in_addr*) server_hostent->h_addr_list[0]);
  server_sock_addr.sin_family = AF_INET;

  // Create our socket and setup our options
  socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (socket_fd < 0) {
    perror("Error on socket()");
    exit(1);
  }
  int one = 1;
  if(setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
    perror("Error on setsockopt()");
    exit(1);
  }

  // Setup our IP Header
  ip_header->ihl = 5;
  ip_header->version = 4;
  ip_header->tos = 0;
  ip_header->tot_len = htons(sizeof(datagram));
  ip_header->id = htons(321);
  ip_header->frag_off = htons(0);
  ip_header->ttl = 64;
  ip_header->protocol = IPPROTO_ICMP;
  ip_header->check = cksum((unsigned short*)datagram, ip_header->ihl);
  ip_header->saddr = inet_addr(TEMP_SRC_IP);  //(*(struct in_addr*) source_hostent->h_addr);
  ip_header->daddr = inet_addr(TEMP_TEST_IP); // (*(struct in_addr*) server_hostent->h_addr);

  // Setup our ICMP header
  icmp_header->type = ICMP_ECHO;
  icmp_header->code = 0;
  icmp_header->un.echo.id = 130;
  icmp_header->un.echo.sequence = 1;

  printf("Size of iph: %lu\n", sizeof(ip_header));
  printf("Size of icmphdr: %lu\n", sizeof(icmp_header));

  // Send out our data
  struct sockaddr *dst = (struct sockaddr*)&server_sock_addr;
  int dst_size = sizeof(server_sock_addr);
  int bytes_sent = sendto(socket_fd, datagram, sizeof(datagram), 0, dst, dst_size);
  if (bytes_sent < 0) {
    perror("Error on sendto()");
  }
  else {
    printf("Packet sent. sent: %d\n", bytes_sent);
  }

  printf("End");
}
