# Ping CLI Application

## 🚀 Getting Started

To compile and run do:
```
gcc ping.c -o ping
sudo ./ping [-ev] [-i interval] [-t TTL] [-W timeout] destination
```

Options:
```
-e  exit on timeout
      This flag can be used if you with for the ping program to stop if one packet has timed out.
      
-i  interval
      Wait interval seconds between sending each packet. The default is to wait 1 second. Interval must be a  
      number greater than 0. You may pass in a number like 0.4 to set the interval to 0.4 seconds.
      
-t  TTL
      The time to live of the packet. Default value is set to 64. Value must be in range of [0, 255].
      
-W  timeout
      Time to wait for a response in seconds.
      
-v  verbose output

destination   Hostname or IPv4 address (e.g google.com)
```
