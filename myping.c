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
  printf("IP address for host %s: %s\n", user_input, dst_ip_str);
  puts("");
  
  // Create our socket and setup our options
  int one = 1;
  struct sockaddr_in server_sock_addr;
  server_sock_addr.sin_addr = *dst_addr;
  server_sock_addr.sin_family = AF_INET;
  int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (socket_fd < 0) {
    perror("Error on socket()");
    exit(1);
  }
  if(setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
    perror("Error on setsockopt()");
    exit(1);
  }

  // User input stuff
  char *TEMP_SRC_IP = "192.168.0.6"; // my temp ip
  char *TEMP_TEST_IP = "104.17.176.85"; // cloudflare.com
  char *TEMP_TEST_HOSTNAME = "google.com";

  // Setup our IP Header
  char datagram[20];
  uint16_t datagram_size = sizeof(datagram);
  memset(datagram, 0, sizeof(datagram));
  struct ip *ip_header = (struct ip*) datagram;
  ip_header->ip_hl = 5;                       /* header length */
  ip_header->ip_v = 4;                        /* IP version */
  ip_header->ip_tos = 0;                      /* type of service */
  ip_header->ip_len = htons(datagram_size);   /* total length */
  ip_header->ip_id = htons(321);              /* IP id */
  ip_header->ip_off = htons(0);               /* fragment offset field */
  ip_header->ip_ttl = 64;                     /* time to live */
  ip_header->ip_p = IPPROTO_ICMP;             /* protocol */
  ip_header->ip_sum = 0;                      /* checksum */
  ip_header->ip_src = *src_addr;              /* src ip address */
  ip_header->ip_dst = *dst_addr;              /* dst ip address */

  // Setup our ICMP header
  struct icmphdr *icmp_header = (struct icmphdr*) (ip_header + 1);
  icmp_header->type = ICMP_ECHO;
  icmp_header->code = 0;
  icmp_header->un.echo.id = 130;
  icmp_header->un.echo.sequence = 1;

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
