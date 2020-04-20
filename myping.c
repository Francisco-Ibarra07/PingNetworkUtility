#include <stdio.h>
#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

bool PING_LOOP = true;

#define ONE_MILLION 1E6
#define IP_HEADER_LENGTH 20
#define ICMP_HEADER_LENGTH 8

// Holds the options for the ping command
struct Options {
  int TTL;
  int TIMEOUT;
  bool VERBOSE;
  bool EXIT_ON_TIMEOUT;
  char DESTINATION[255];
  float PING_RATE;
};

// Prints out usage for the this ping program
void print_usage(char* cmd) {
  printf("Usage: sudo %s [-ev] [-i interval] [-t TTL] [-W timeout] destination\n", cmd);
}

// Function used to get time since epoch in milliseconds
long get_time_ms() {
  struct timeval t;
  gettimeofday(&t, NULL);
  return t.tv_sec * 1000 + t.tv_usec / 1000;
}

// Function used to calculate the ip and icmp header checksums
uint16_t checksum (uint16_t *addr, int len) {
  int count = len;
  uint32_t sum = 0;
  uint16_t answer = 0;

  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  answer = ~sum;
  return (answer);
}

// If 'Ctr-C' is pressed, this breaks the infinite loop
void signal_handler() {
  PING_LOOP = false;
}

void createPacket(uint8_t* packet, size_t size, int seq, int TTL, 
                  struct in_addr *src_addr, struct in_addr *dst_addr ) 
{
  // Setup our IP Header
  struct ip ip_header;
  ip_header.ip_hl = 5;
  ip_header.ip_v = 4;
  ip_header.ip_tos = 0;
  ip_header.ip_len = htons(IP_HEADER_LENGTH + ICMP_HEADER_LENGTH);
  ip_header.ip_id = htons(0);
  ip_header.ip_ttl = TTL;
  ip_header.ip_p = IPPROTO_ICMP;
  ip_header.ip_src = *src_addr;
  ip_header.ip_dst = *dst_addr;
  ip_header.ip_off = htons(0);
  ip_header.ip_sum = 0;
  ip_header.ip_sum = checksum((uint16_t*) &ip_header, IP_HEADER_LENGTH);

  // Setup our ICMP header
  struct icmp icmp_header;
  icmp_header.icmp_type = ICMP_ECHO;
  icmp_header.icmp_code = 0;
  icmp_header.icmp_id = htons(getpid());
  icmp_header.icmp_seq = htons(seq);
  icmp_header.icmp_cksum = 0;

  // Append IP + ICMP headers
  memcpy(packet, &ip_header, IP_HEADER_LENGTH);
  memcpy((packet + IP_HEADER_LENGTH), &icmp_header, ICMP_HEADER_LENGTH);

  // Calculate ICMP header checksum
  icmp_header.icmp_cksum = checksum ((uint16_t *) (packet + IP_HEADER_LENGTH), ICMP_HEADER_LENGTH);
  memcpy ((packet + IP_HEADER_LENGTH), &icmp_header, ICMP_HEADER_LENGTH);
}

// This function is used to set any flags or options passed in through argv
void get_options(struct Options* options, int argc, char **argv) {
  int opt;

  // Set any flags or options passed in through argv
  while((opt = getopt(argc, argv, "evi:t:W:")) != -1) {
    switch (opt) {
      case 'e': 
        options->EXIT_ON_TIMEOUT = true;
        break;

      case 'v': 
        options->VERBOSE = true;
        break;

      case 'i':
        options->PING_RATE = atof(optarg);
        if (options->PING_RATE <= 0) {
          fprintf(stderr, "interval must be a number greater than 0");
          exit(EXIT_FAILURE);
        }
        break;

      case 't':
        options->TTL = atoi(optarg);
        if (options->TTL <= 0) {
          fprintf(stderr, "ttl must be a number greater than 0");
          exit(EXIT_FAILURE);
        }
        else if (options->TTL > 255) {
          fprintf(stderr, "ttl cannot be greater than 255");
          exit(EXIT_FAILURE);
        }
        break;
      
      case 'W':
        options->TIMEOUT = atoi(optarg);
        if (options->TIMEOUT <= 0) {
          fprintf(stderr, "timeout must be a number greater than 0");
          exit(EXIT_FAILURE);
        }
        break;
    
      default:
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
        break;
    }
  }

  // Get the destination (it should be the first extra arg)
  // Make sure it is not NULL and it is not > 255 chars
  char* destination = argv[optind];
  if (destination == NULL) {
    fprintf(stderr, "destination was not supplied");
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }
  else if (strlen(destination) > 255) {
    fprintf(stderr, "destination name needs to be under 255 characters\n");
    exit(EXIT_FAILURE);
  }
  else {
    strncpy(options->DESTINATION, destination, strlen(destination));
  }
}

int main(int argc, char *argv[]) {

  if (getuid() != 0) {
    fprintf(stderr, "This program requires it to be ran as root\n");
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }

  if (argc < 2) {
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }

  // Set default options
  struct Options ping_options;
  ping_options.TTL = 64; 
  ping_options.TIMEOUT = 1;
  ping_options.PING_RATE = 1.0;
  ping_options.VERBOSE = false;
  ping_options.EXIT_ON_TIMEOUT = false;

  // Override default options with any options/flags passed through argv
  get_options(&ping_options, argc, argv);

  // Get hostname of this machine
  char src_hostname[255];
  if(gethostname(src_hostname, sizeof(src_hostname)) < 0) {
    fprintf(stderr, "Hostname of this machine could not be determined\n");
    exit(EXIT_FAILURE);
  }

  // Get source IP address
  struct in_addr *src_addr;
  struct hostent *src_hostent = gethostbyname(src_hostname);
  if (src_hostent == NULL) {
    fprintf(stderr, "Source IP address could not be found\n");
    exit(EXIT_FAILURE);
  }
  src_addr = (struct in_addr*) src_hostent->h_addr_list[0];

  // Convert source inet address into string for later use
  char src_ip_str[32];
  strncpy(src_ip_str, inet_ntoa(*src_addr), sizeof(src_ip_str));

  // Get destination IP address
  struct in_addr *dst_addr;
  struct hostent *dst_hostent = gethostbyname(ping_options.DESTINATION);
  if (dst_hostent == NULL) {
    fprintf(stderr, "Destination with name '%s' could not be found\n", ping_options.DESTINATION);
    exit(EXIT_FAILURE);
  }
  dst_addr = (struct in_addr*) dst_hostent->h_addr_list[0];

  // Convert destination inet address into string for later use
  char dst_ip_str[32];
  strcpy(dst_ip_str, inet_ntoa(*dst_addr));

  // Print out settings that will be used if verbose flag was set
  if (ping_options.VERBOSE) {
    printf("--- SETTINGS ---\n");
    printf("TTL: %d hop(s)\n", ping_options.TTL);
    printf("Timeout: %d second(s)\n", ping_options.TIMEOUT);
    printf("Interval: %.2f second(s)\n", ping_options.PING_RATE);
    printf("Source hostname: %s\n", src_hostname);
    printf("Source IP address: %s\n", src_ip_str);
    printf("Destination hostname: %s\n", ping_options.DESTINATION);
    printf("Destination IP address: %s\n", dst_ip_str);
    printf("--- --- ---\n\n");
  }

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

  signal(SIGINT, signal_handler);

  // Timeout stuff
  struct timeval timeout;
  timeout.tv_sec = ping_options.TIMEOUT; 
  timeout.tv_usec = 0;

  // Socket set for select()
  fd_set socket_set;
  FD_ZERO(&socket_set);
  FD_SET(socket_fd, &socket_set);

  // Ping Statistics
  int packets_transmitted = 0; // each packet sent
  int packets_recieved = 0; // each packet recieved
  int packet_errors = 0; // ttl timeout or icmp errors
  int packets_lost = 0; // No replies/timeouts
  long current_rtt = 0; 
  long min_rtt = 0;
  long max_rtt = 0;
  float avg_rtt = 0;
  long cumulative_rtt = 0;
  long loop_start_time = get_time_ms();
  unsigned long loop_total_time = 0;

  // Init packet variables
  int packet_sequence = 0;
  uint8_t *packet = (uint8_t*) malloc(IP_MAXPACKET * sizeof(uint8_t));
  size_t packet_size = sizeof(IP_MAXPACKET * sizeof(uint8_t));

  int total_sending_bytes = IP_HEADER_LENGTH + ICMP_HEADER_LENGTH;
  printf("PING %s (%s) 0x%x(%dD) bytes of data.\n", ping_options.DESTINATION, dst_ip_str, total_sending_bytes, total_sending_bytes);
  while(PING_LOOP) {
    createPacket(packet, packet_size, packet_sequence, ping_options.TTL, src_addr, dst_addr);

    long packet_start_time = get_time_ms();
    timeout.tv_sec = ping_options.TIMEOUT; 
    timeout.tv_usec = 0;

    int bytes_sent = sendto(
      socket_fd, 
      packet, 
      IP_HEADER_LENGTH + ICMP_HEADER_LENGTH, 
      0, 
      (struct sockaddr*) &server_addr, // Need to cast sockaddr_in to sockaddr*
      sizeof(struct sockaddr)
    );

    if (bytes_sent < 0) {
      perror("Error on sendto()");
      break;
    }

    int result = select(socket_fd + 1, &socket_set, NULL, NULL, &timeout);
    if (result == -1) {
      perror("Error on select()");
      packet_errors++;
      packets_lost++;
      break;
    }
    else if (result == 0) {
      packets_lost++;
      if (ping_options.VERBOSE) {
        printf("TIMEOUT: %d second(s) have passed since sending out an echo request to %s(%s)\n", 
                ping_options.TIMEOUT, ping_options.DESTINATION, dst_ip_str);
      }
      if (ping_options.EXIT_ON_TIMEOUT) {
        break;
      }
    }
    else {
      char recv_buffer[50];
      int bytes_read = recv(socket_fd, recv_buffer, sizeof(recv_buffer), 0);
      if (bytes_read < 0) {
        perror("recv() error");
        exit(1);
      }
      bytes_read -= IP_HEADER_LENGTH;

      // TODO: Put if's in a function
      current_rtt = get_time_ms() - packet_start_time;
      cumulative_rtt += current_rtt;
      if (current_rtt > max_rtt) {
        max_rtt = current_rtt;
      }
      if (min_rtt == 0) {
        min_rtt = current_rtt;
      }
      else if (current_rtt < min_rtt) {
        min_rtt = current_rtt;
      }

      // Read the network layer message (skip to the icmp header portion)
      struct icmp *icmp_reply = (struct icmp*) (recv_buffer + IP_HEADER_LENGTH);
      if (icmp_reply->icmp_type == ICMP_ECHOREPLY) {
        printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d rtt=%lu ms\n", 
                bytes_read, ping_options.DESTINATION, dst_ip_str, 
                packet_sequence, ping_options.TTL, current_rtt);
        packets_recieved++;
      }
      else if (icmp_reply->icmp_type == ICMP_TIME_EXCEEDED) { 
        packet_errors++;
        packets_lost++;
        printf("From %s (%s): icmp_seq=%d Time to live exceeded (%d hops)\n", 
                ping_options.DESTINATION, dst_ip_str, packet_sequence, ping_options.TTL);
      }
    }
    
    packets_transmitted++;
    packet_sequence++;
    usleep((__useconds_t) (ping_options.PING_RATE * ONE_MILLION));
  }

  loop_total_time = get_time_ms() - loop_start_time;
  if (packets_recieved == 1) {
    avg_rtt = min_rtt;
  }
  else {
    avg_rtt = (float) cumulative_rtt / (float) packets_transmitted;
  }
  float packet_loss_percentage = ((float) packets_lost / (float) packets_transmitted) * 100;

  printf("\n--- %s ping statistics ---\n", ping_options.DESTINATION);
  if (packet_errors > 0) {
    printf("%d packets transmitted, %d recieved, +%d errors, %.0f%% packet loss, time %lums\n", 
            packets_transmitted, packets_recieved, packet_errors, 
            packet_loss_percentage, loop_total_time);
  }
  else {
    printf("%d packets transmitted, %d recieved, %.0f%% packet loss, time %lums\n", packets_transmitted, packets_recieved, packet_loss_percentage, loop_total_time);
    printf("rtt min/avg/max = %lu/%.2f/%lu ms\n", min_rtt, avg_rtt, max_rtt);
  }

  close(socket_fd);
  free(packet);

  return 0;
}
