#include <libnet.h>
#include <pcap.h>
#include "wrath-structs.h"

// This file includes prototypes for all functions to export in the WRATH project

// takes a list of command-line arguments
// and returns a pointer to an array of key-value pairs
void arg_eval(int, char **, struct arg_kv *);
