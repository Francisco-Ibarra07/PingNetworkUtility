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

// Holds statistics throughout the ping loop
struct Statistics {
  unsigned short packets_transmitted;
  unsigned short packets_recieved;
  unsigned short packet_errors;
  unsigned short packets_lost;
  unsigned long min_rtt;
  unsigned long max_rtt;
  float avg_rtt;
  unsigned long cumulative_rtt;
  unsigned long loop_start_time;
  unsigned long loop_total_time;
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

// Takes in a pointer (packet) and fills the pointer up with the appropriate
// IP and ICMP header information. Once this function completes, the packet
// will be formatted correctly in order to be sent through a socket.
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

void start_ping(int socket_fd, struct sockaddr_in* server_addr, struct in_addr* src_addr, 
                struct in_addr* dst_addr, struct Statistics* pstats, struct Options* opts) 
{
  // Allocate some memory so we can store our packet
  uint8_t *packet = (uint8_t*) malloc(IP_MAXPACKET * sizeof(uint8_t));
  size_t packet_size = sizeof(IP_MAXPACKET * sizeof(uint8_t));
  int packet_length = IP_HEADER_LENGTH + ICMP_HEADER_LENGTH;
  int packet_sequence = 0;
  
  // Use a socket set so we can utilize the select function.
  // The select() function will notify us when our socket has data
  // available to be read.
  fd_set socket_set;
  FD_ZERO(&socket_set);
  FD_SET(socket_fd, &socket_set);

  // Get the presentation format of the src and dst addresses so
  // they can be used whenever we call printf() (just so it looks nice :p)
  char src_ip_str[32];
  strncpy(src_ip_str, inet_ntoa(*src_addr), sizeof(src_ip_str));
  char dst_ip_str[32];
  strncpy(dst_ip_str, inet_ntoa(*dst_addr), sizeof(dst_ip_str));

  // This 'timeout' var defines how long select() should wait until
  // it times out.
  struct timeval timeout;

  printf("PING %s (%s) 0x%x(%dD) bytes of data.\n", 
          opts->DESTINATION, dst_ip_str, packet_length, packet_length);
  
  // Begin the ping loop
  pstats->loop_start_time = get_time_ms();
  while(PING_LOOP) {

    // Always set our timeouts before each new packet
    timeout.tv_sec = opts->TIMEOUT; 
    timeout.tv_usec = 0;

    // Use this function to initialize a packet with an IP and ICMP header
    createPacket(packet, packet_size, packet_sequence, opts->TTL, src_addr, dst_addr);

    long packet_sent_time = get_time_ms();

    // Send our packet to the destination address
    int bytes_sent = sendto(socket_fd, packet, packet_length, 0,
                            (struct sockaddr*) server_addr, sizeof(struct sockaddr));
    if (bytes_sent < 0) {
      perror("sendto");
      pstats->packet_errors++;
      break;
    }

    int res = select(socket_fd + 1, &socket_set, NULL, NULL, &timeout);
    // Error with select() occurred
    if (res == -1) {
      perror("select");
      pstats->packet_errors++;
      pstats->packets_lost++;
      break;
    }
    // Timeout occurred
    else if (res == 0) {
      pstats->packets_lost++;
      printf("TIMEOUT: %d second(s) have passed since sending out an echo request to %s(%s)\n", 
              opts->TIMEOUT, opts->DESTINATION, dst_ip_str);
    }
    // ICMP message recieved
    else {
      char recv_buffer[50];
      int bytes_read = recv(socket_fd, recv_buffer, sizeof(recv_buffer), 0);
      if (bytes_read < 0) {
        perror("recv");
        pstats->packet_errors++;
        break;
      }
      bytes_read -= IP_HEADER_LENGTH;

      long current_rtt = get_time_ms() - packet_sent_time;
      pstats->cumulative_rtt += current_rtt;
      if (current_rtt > pstats->max_rtt) {
        pstats->max_rtt = current_rtt;
      }
      if (pstats->min_rtt == 0) {
        pstats->min_rtt = current_rtt;
      }
      else if (current_rtt < pstats->min_rtt) {
        pstats->min_rtt = current_rtt;
      }

      // Read the network layer message (skip to the icmp header portion)
      struct icmp *icmp_reply = (struct icmp*) (recv_buffer + IP_HEADER_LENGTH);
      if (icmp_reply->icmp_type == ICMP_ECHOREPLY) {
        printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d rtt=%lu ms\n", 
                bytes_read, opts->DESTINATION, dst_ip_str, 
                packet_sequence, opts->TTL, current_rtt);

        pstats->packets_recieved++;
      }
      else if (icmp_reply->icmp_type == ICMP_TIME_EXCEEDED) { 
        pstats->packet_errors++;
        pstats->packets_lost++;
        printf("From %s (%s): icmp_seq=%d Time to live exceeded (%d hops)\n", 
                opts->DESTINATION, dst_ip_str, packet_sequence, opts->TTL);
      }
    }
    
    pstats->packets_transmitted++;
    packet_sequence++;
    usleep((__useconds_t) (opts->PING_RATE * ONE_MILLION));
  } // End of while()

  pstats->loop_total_time = get_time_ms() - pstats->loop_start_time;
  free(packet);
}

void print_ping_stats(struct Statistics* pstats) {

  if (pstats->packets_recieved == 1) {
    pstats->avg_rtt = pstats->min_rtt;
  }
  else {
    pstats->avg_rtt = (float) pstats->cumulative_rtt / (float) pstats->packets_transmitted;
  }
  float packet_loss_percentage = ((float) pstats->packets_lost / (float) pstats->packets_transmitted) * 100;

  if (pstats->packet_errors > 0) {
    printf("%d packets transmitted, %d recieved, +%d errors, %.0f%% packet loss, time %lums\n", 
            pstats->packets_transmitted, pstats->packets_recieved, pstats->packet_errors, 
            packet_loss_percentage, pstats->loop_total_time);
  }
  else {
    printf("%d packets transmitted, %d recieved, %.0f%% packet loss, time %lums\n", 
            pstats->packets_transmitted, pstats->packets_recieved, packet_loss_percentage, 
            pstats->loop_total_time);

    printf("rtt min/avg/max = %lu/%.2f/%lu ms\n", pstats->min_rtt, pstats->avg_rtt, pstats->max_rtt);
  }
}

int main(int argc, char *argv[]) {

  // We are using raw sockets so make sure program is ran with 'sudo'
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
  strncpy(dst_ip_str, inet_ntoa(*dst_addr), sizeof(dst_ip_str));

  // Create our raw socket and setup our options
  int on = 1;
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(struct sockaddr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr = *dst_addr; 
  int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (socket_fd < 0) {
    perror("socket");
    exit(EXIT_FAILURE);
  }
  if(setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }

  // If verbose flag was set, print out the options that will be used
  // when the ping starts
  if (ping_options.VERBOSE) {
    printf("--- SETTINGS ---\n");
    printf("TTL: %d hop(s)\n", ping_options.TTL);
    printf("Timeout: %d second(s)\n", ping_options.TIMEOUT);
    printf("Interval: %.2f second(s)\n", ping_options.PING_RATE);
    printf("Exit on timeout: %s\n", (ping_options.EXIT_ON_TIMEOUT ? "true" : "false"));
    printf("Source hostname: %s\n", src_hostname);
    printf("Source IP address: %s\n", src_ip_str);
    printf("Destination hostname: %s\n", ping_options.DESTINATION);
    printf("Destination IP address: %s\n", dst_ip_str);
    printf("--- --- ---\n\n");
  }

  // Create a Statistics struct that will contain all of the ping 
  // statistics once the pinging is finished
  struct Statistics pstats;
  pstats.packets_transmitted = 0;
  pstats.packets_recieved = 0;
  pstats.packet_errors = 0;
  pstats.packets_lost = 0;
  pstats.min_rtt = 0;
  pstats.max_rtt = 0;
  pstats.avg_rtt = 0.0;
  pstats.cumulative_rtt = 0;
  pstats.loop_start_time = 0;
  pstats.loop_total_time = 0;

  // Create a SIGINT handler to end the infinite pinging loop
  signal(SIGINT, signal_handler);

  // Start the infinite ping (until there is an interrupt :p)
  start_ping(socket_fd, &server_addr, src_addr, dst_addr, &pstats, &ping_options);

  // Print out statistics
  printf("\n--- %s ping statistics ---\n", ping_options.DESTINATION);
  print_ping_stats(&pstats);

  close(socket_fd);

  return 0;
}
