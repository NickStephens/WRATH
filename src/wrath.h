#include <pcap.h>
#include "wrath-structs.h"

// This file includes prototypes for all functions to export in the WRATH project

// takes a list of command-line arguments
// and returns a pointer to an array of key-value pairs
void arg_eval(int, char **, struct arg_values *);

// places wrath in a position to victimize the 
// packets specified by the filter
// (intializes pcap)
pcap_t *wrath_position(struct arg_values *);

void wrath_inject(u_char *, const struct pcap_pkthdr *, const u_char *);
