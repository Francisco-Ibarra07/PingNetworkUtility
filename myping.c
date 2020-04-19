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

#define IP_HEADER_LENGTH 20
#define ICMP_HEADER_LENGTH 8

/* One's Complement checksum algorithm */
// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

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

  printf("Starting\n\n");

  // Get source IP address and src hostname
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

  // Initialize icmp data to send
  uint8_t *data;
  data = (uint8_t*) malloc(IP_MAXPACKET * sizeof(uint8_t));
  if (data != NULL) {
    memset(data, 0, IP_MAXPACKET * sizeof(uint8_t));
  }
  else {
    perror("Error on icmp_data malloc()");
    exit(1);
  }
  int icmp_data_length = 4;
  data[0] = 'p';
  data[1] = 'i';
  data[2] = 'n';
  data[3] = 'g';

  // Setup our IP Header
  struct ip ip_header;
  ip_header.ip_hl = 5;                       /* header length */
  ip_header.ip_v = 4;                        /* IP version */
  ip_header.ip_tos = 0;                      /* type of service */
  ip_header.ip_len = htons(IP_HEADER_LENGTH + ICMP_HEADER_LENGTH + icmp_data_length);   /* total length */
  ip_header.ip_id = htons(0);              /* IP id */
  ip_header.ip_ttl = 255;                     /* time to live */
  ip_header.ip_p = IPPROTO_ICMP;             /* protocol */
  ip_header.ip_src = *src_addr;              /* src ip address */
  ip_header.ip_dst = *dst_addr;              /* dst ip address */

  int* flags = (int*) malloc(4 * sizeof(int));
  flags[0] = 0;
  flags[1] = 0;
  flags[2] = 0;
  flags[3] = 0;
  ip_header.ip_off = htons((flags[0] << 15) + (flags[1] << 14) +(flags[2] << 13) + flags[3]); /* fragment offset field */
  ip_header.ip_sum = 0;                      /* checksum */
  ip_header.ip_sum = checksum((uint16_t*) &ip_header, IP_HEADER_LENGTH); /* checksum */

  // Setup our ICMP header
  struct icmp icmp_header;
  icmp_header.icmp_type = ICMP_ECHO;
  icmp_header.icmp_code = 0;
  icmp_header.icmp_id = htons(getpid());
  icmp_header.icmp_seq = 0;
  icmp_header.icmp_cksum = 0;


  // Prepare packet to send
  uint8_t *packet = (uint8_t*) malloc(IP_MAXPACKET * sizeof(uint8_t));
  memcpy(packet, &ip_header, IP_HEADER_LENGTH); // Copy IP header first
  memcpy((packet + IP_HEADER_LENGTH), &icmp_header, ICMP_HEADER_LENGTH); // Copy ICMP header AFTER IP header
  memcpy((packet + IP_HEADER_LENGTH + ICMP_HEADER_LENGTH), data, icmp_data_length);

  // Calculate ICMP header checksum
  icmp_header.icmp_cksum = checksum ((uint16_t *) (packet + IP_HEADER_LENGTH), ICMP_HEADER_LENGTH + icmp_data_length);
  memcpy ((packet + IP_HEADER_LENGTH), &icmp_header, ICMP_HEADER_LENGTH);

  // Create our socket and setup our options
  int on = 1;
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(struct sockaddr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr = *dst_addr; 

  int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (socket_fd < 0) {
    perror("Error on socket()");
    exit(1);
  }
  if(setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    perror("Error on setsockopt()");
    exit(1);
  }

  // Send out our data
  int bytes_sent = sendto(
    socket_fd, 
    packet, 
    IP_HEADER_LENGTH + ICMP_HEADER_LENGTH + icmp_data_length, 
    0, 
    (struct sockaddr*) &server_addr, // Need to cast sockaddr_in to sockaddr*
    sizeof(struct sockaddr)
   );

  if (bytes_sent < 0) {
    perror("Error on sendto()");
  }
  else {
    printf("Packet sent. sent: %d\n", bytes_sent);
    puts("Attempting to read");
    int response = recv(socket_fd, packet, sizeof(packet), 0);
    printf("Response from recv: %d\n", response);
  }

  close(socket_fd);
  free(flags);
  free(data);
  free(packet);

  printf("End\n");
  return 0;
}
