#ifndef __session_h
#define __session_h

#include <netinet/in.h>
#include <poll.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "proto.h"


typedef struct {
	struct sockaddr_in peer;	// address of the remote peer
	int type;			// socket type, defaults to SOCK_STREAM

	unsigned char *rx;		// receive buffer
	size_t rxbytes;			// bytes in receive buffer
	unsigned char *tx;		// send buffer
	size_t txoff;			// send buffer offset
	size_t txbytes;			// bytes in send buffer

	int used;			// indicates if this session slot is in use
	int connecting;			// indicates if connection establishment is in progress
	int closed_by_peer;		// indicates that the session was closed by the remote peer

	time_t session_start;		// session start time
	time_t last_action;		// time of last activity

	ssize_t peerlist_index;		// corresponding peer list index
} session_t;

#define RESERVED_FDS	1
#define ctlevfd		fds[nfds-1]

nfds_t nfds;
session_t *session;
struct pollfd *fds;
int dummyfd;

void session_terminate(nfds_t i);
void session_init(size_t i, struct sockaddr_in *saddr, size_t peerlist_index);
int session_get_next_free(void);
int session_connect(size_t i);
int session_done(size_t i);
time_t session_last_action(size_t i);
time_t session_start_time(size_t i);
void session_delete(size_t i);
ssize_t session_receive(size_t i);
void session_prepare_for_send(size_t i, unsigned char *data, size_t len);
ssize_t session_send(size_t i);

#endif
