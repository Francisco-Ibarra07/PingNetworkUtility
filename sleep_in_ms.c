#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

long get_time_ms() {
  struct timeval t;
  gettimeofday(&t, NULL);
  return t.tv_sec * 1000 + t.tv_usec / 1000;
}

int main(int argc, char const *argv[])
{
  puts("Sleeping"); 
  float t = 1.0;
  long start = get_time_ms();
  usleep(t * 1E6);
  printf("Total: %ldms\n", (get_time_ms() - start));
  puts("End"); 
  return 0;
}
