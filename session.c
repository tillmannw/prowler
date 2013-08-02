#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "proto.h"
#include "session.h"


void session_terminate(nfds_t i) {
	close(fds[i].fd);
	fds[i].fd = dummyfd;
	fds[i].events = 0;
	fds[i].revents = 0;

	return;
}

void session_init(size_t i, struct sockaddr_in *saddr, size_t peerlist_index) {
	memset(&session[i], 0, sizeof(session_t));
	memcpy(&session[i].peer, saddr, sizeof(struct sockaddr_in));

	session[i].peer.sin_family = AF_INET;

	if ((session[i].session_start = session[i].last_action = time(NULL)) == -1) {
		perror("time()");
		exit(EXIT_FAILURE);
	}

	session[i].used = 1;
	session[i].peerlist_index = peerlist_index;

	return;
}

int session_connect(size_t i) {
	int flags;

	// create socket
	if ((fds[i].fd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	// set socket options (reuseaddr, non-blocking)
	if (((flags = fcntl(fds[i].fd, F_GETFL, 0)) == -1) ||
	    (fcntl(fds[i].fd, F_SETFL, flags | O_NONBLOCK) == -1)) {
		perror("fcntl()");
		exit(EXIT_FAILURE);
	}

	fds[i].events = POLLOUT | POLLIN;

	if (connect(fds[i].fd, (struct sockaddr *) &session[i].peer, sizeof(struct sockaddr_in)) == -1) {
		switch (errno) {
		case EINPROGRESS:
			break;
		case ENETUNREACH:
			return -1;
			break;
		default:
			perror("connect()");
			exit(EXIT_FAILURE);
		}
		session[i].connecting = 1;
	}

	if (session[i].peerlist_index != -1) {
		peerlist[session[i].peerlist_index].last_connect = time(NULL);
		peerlist[session[i].peerlist_index].active = 1;
	}

	return fds[i].fd;	
}

int session_get_next_free(void) {
	int i;
	
	for (i = 0; i < nfds - RESERVED_FDS; ++i) 
		if (session[i].used == 0) return i;

	printf("error: file descriptor limit exceeded. use -f.\n");
	exit(EXIT_FAILURE);

	return -1;
}

void session_delete(size_t i) {
	if (session[i].rx != NULL) free(session[i].rx);

	if (session[i].peerlist_index != -1)
		peerlist[session[i].peerlist_index].active = 0;

	memset(&session[i], 0, sizeof(session_t));

	return;
}

int session_done(size_t i) {
	if (session[i].closed_by_peer == 0) return 0;

	shutdown(fds[i].fd, SHUT_RD);

	// return if not done sending/dumping
	if (session[i].txbytes || session[i].rxbytes) return 0;

	session_delete(i);

	return 1;
}

time_t session_last_action(size_t i) {
	return session[i].last_action;
}

time_t session_start_time(size_t i) {
	return session[i].session_start;
}

ssize_t session_receive(size_t i) {
	ssize_t bytes;

	if ((session[i].last_action = time(NULL)) == -1) {
		perror("time()");
		exit(EXIT_FAILURE);
	}

	if ((session[i].rx = realloc(session[i].rx, session[i].rxbytes + BUFSIZ)) == NULL) {
		perror("realloc()");
		exit(EXIT_FAILURE);
	}

	switch ((bytes = recv(fds[i].fd, session[i].rx + session[i].rxbytes, BUFSIZ, 0))) {
	case -1:
		if (errno == EAGAIN) break;
		perror("recv()");
		return -1;
	case 0:
		// connection closed by peer, turn off receive polling
		session[i].closed_by_peer = 1;
		fds[i].events &= ~POLLIN;
		return 0;
	default:
		break;
	}

	session[i].rxbytes += bytes;

	return bytes;
}

void session_prepare_for_send(size_t i, unsigned char *data, size_t len) {
	session[i].tx = data;
	session[i].txbytes = len;
	session[i].txoff = 0;
	fds[i].events |= POLLOUT;

	return;
}

ssize_t session_send(size_t i) {
	ssize_t bytes;

	if (session[i].tx == NULL || session[i].txbytes == 0) {
		// nothing to send
		return 0;
	}

	if ((bytes = send(fds[i].fd, session[i].tx + session[i].txoff, session[i].txbytes, 0)) == -1) {
		if (errno != EAGAIN) {
			perror("send()");
			return -1;
		}
	}

	memmove(session[i].tx, session[i].tx + bytes, session[i].txbytes - bytes);
	session[i].txoff += bytes;
	session[i].txbytes -= bytes;

	// turn off send polling if there's nothing to send
	if (session[i].txbytes == 0) { fds[i].events &= ~POLLOUT; }

	return bytes;
}
