#ifndef __sig_h
#define __sig_h

#include <signal.h>
#include <stdio.h>

// events
#define TIMER_FIRED	1
#define DUMP_PEERLIST	2

int ctlevents;

FILE *logstd;
FILE *logerr;

int pfd[2];

void sigh(int s);

#endif
