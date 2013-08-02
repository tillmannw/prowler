#ifndef __proto_h
#define __proto_h


#define PEERID_SIZE 16

typedef struct {
	u_int32_t ipaddr;
	u_int16_t port;
	int unresponsive;	// indicates that the peer does currently not responde
	int active;		// indicates that the peer is currently active
	size_t index;		// index of this peer in the peerlist
	time_t last_connect;	// timestamp of last connection attempt
	time_t last_contact;	// timestamp of last contact with the peer
	void *data;		// pointer for additional protocol specific data like peer IDs
} peer_t;

peer_t *peerlist;
size_t peerlist_size;

void peer_add(u_int32_t ipaddr, u_int16_t port, void *data);
int peerlist_process(size_t peerlist_index, unsigned char *msg, size_t size);

#endif
