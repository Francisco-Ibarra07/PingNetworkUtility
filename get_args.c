#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include <stdbool.h>

void print_usage(char* cmd) {
  printf("Usage: %s [-i interval] destination\n", cmd);
}

void error_msg(char* msg) {
  perror(msg);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {

  if (argc < 2) {
    print_usage(argv[0]);
    exit(1);
  }

  int opt;
  float ping_rate = 1.0;

  while ((opt = getopt(argc, argv, "i:")) != -1) {
    switch (opt) {
      case 'i':
        ping_rate = atof(optarg);
        if (ping_rate <= 0) {
          error_msg("interval must be a number greater than 0");
        }
        break;
    
      default:
        print_usage(argv[0]);
        exit(1);
        break;
    }
  }

  printf("Hostname: %s\n", argv[optind]);
  printf("Ping rate: %.2f\n", ping_rate);
  return 0;
}
