#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "proto.h"
#include "session.h"

extern FILE *logstd;

typedef struct {
	peer_t src, dst;
} mapping_t;


void peer_add(u_int32_t ipaddr, u_int16_t port, void *data) {
	size_t i;

	if (!ipaddr || !port) return;

	for (i = 0; i < peerlist_size; ++i) {
		if (ipaddr == peerlist[i].ipaddr) return;

		// TODO: perform further deduplication checks here, e.g., based on peer IDs
	}

	// add new entry
	if ((peerlist = realloc(peerlist, (peerlist_size + 1) * sizeof(peer_t))) == NULL) {
		perror("realloc()");
		exit(EXIT_FAILURE);
	}

	peerlist[peerlist_size].ipaddr = ipaddr;
	peerlist[peerlist_size].port = port;
	peerlist[peerlist_size].data = data;
	peerlist[peerlist_size].last_contact = 0;
	peerlist[peerlist_size].active = 0;
	peerlist[peerlist_size].unresponsive = 0;
	peerlist[peerlist_size].index = peerlist_size;

	peerlist_size++;

	return;
}

int peerlist_process(size_t peerlist_index, unsigned char *msg, size_t size) {
	return -1;
}
