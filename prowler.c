// prowler -- (C) 2013 Tillmann Werner

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "sig.h"
#include "proto.h"
#include "session.h"
#include "util.h"

#define ACTIVE_TIMEOUT	30
#define CHECK_INTERVAL	10
#define UNRESP_TRIES	3	// < 1 means keep trying

#define REPORT_STATS	5

#define SESSION_TIMEOUT	10
#define TOTAL_TIMEOUT	30
#define BACKLOG_SIZE	0xff

int main(int argc, char *argv[]) {
	nfds_t i;
	int opt, bytes, verbose;
	useconds_t slowdown;
	struct sigaction saction;
	struct rlimit rlim;
	char *logname;
	time_t reftime;

	slowdown = 0;
	logname = NULL;
	logstd = NULL;
	logerr = NULL;
	ctlevents = 0;
	verbose = 0;

	// install signal handler
	memset(&saction, 0, sizeof(struct sigaction));
	saction.sa_handler = sigh;
	saction.sa_flags |= SA_NOCLDWAIT;
	if ((sigaction(SIGINT, &saction, NULL) == -1) ||
	    (sigaction(SIGALRM, &saction, NULL) == -1) ||
	    (sigaction(SIGUSR1, &saction, NULL) == -1)) {
		perror("sigaction()");
		exit(EXIT_FAILURE);
	}

	if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
		perror("getrlmit()");
		exit(EXIT_FAILURE);
	}
	rlim.rlim_max = 0;

	while ((opt = getopt(argc, argv, "f:hl:rs:v")) != -1) {
		switch (opt) {
		case 'f':
			rlim.rlim_max = rlim.rlim_cur = strtoul(optarg, NULL, 0);
			break;
		case 'h':
			printf("prowler (C) 2013 by Tillmann Werner\n");
			printf("\nUsage: %s [-f fd-limit] [-h] [-l logfile] [-s slowdown] peerlist\n\n", argv[0]);
			exit(EXIT_SUCCESS);
		case 'l':
			logname = optarg;
			break;
		case 's':
			slowdown = strtoul(optarg, 0, 0);
			break;
		case 'v':
			verbose++;
			break;
		default:
			printf("Usage: %s [-f fd-limit] [-h] [-l logfile] [-s slowdown] peerlist\n\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc) {
		printf("Usage: %s [-f fd-limit] [-h] [-l logfile] [-s slowdown] peerlist\n\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	close(STDIN_FILENO);

	// open log file
	if (logname)  {
		if ((logstd = logerr = fopen(logname, "a")) == NULL) {
			perror("fopen()");
			exit(EXIT_FAILURE);
		}
	} else {
		logstd = stdout;
		logerr = stderr;
	}

	printf("\n   prowler (C) 2013 Tillmann Werner\n\n");


	// set maximum number of open files if a value was specified
	if (rlim.rlim_max && setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
		perror("setrlmit()");
		exit(EXIT_FAILURE);
	}

	if (verbose)
		printf("open file descriptor limit: %lu\n", rlim.rlim_cur);


	// allocate memory for poll fd set and session array
	nfds = (rlim.rlim_cur) - 4; // std{out,err}, dummyfd and one for accept
	if (((fds = calloc(nfds, sizeof(struct pollfd))) == NULL) ||
	    ((session = calloc(nfds, sizeof(session_t))) == NULL)) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	// init slots with dummy fd
	if ((dummyfd = open("/dev/null", 0, 0)) == -1) {
		perror("open()");
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < nfds - 1; ++i) {
		fds[i].fd = dummyfd;
		fds[i].events = 0;
		fds[i].revents = 0;
	}

	// create control event pipe
	if (pipe(pfd) == -1) {
		perror("pipe()");
		exit(EXIT_FAILURE);
	}
	ctlevfd.fd = pfd[0];
	ctlevfd.events = POLLIN;
	ctlevfd.revents = 0;
	

	// read initial peerlist from file
	char *line = NULL;
	FILE *peerfile = NULL;
	size_t linelen = 0;
	if ((peerfile = fopen(argv[optind], "r")) == NULL) {
		perror("fopen()");
		exit(EXIT_FAILURE);
	}
	char *portstr;
	struct sockaddr_in saddr;
	while (getline(&line, &linelen, peerfile) != -1) {
		if ((portstr = strchr(line, ':')) == NULL) continue;
		*portstr = 0;
		saddr.sin_addr.s_addr = inet_addr(line);
		saddr.sin_port = htons(strtoul(portstr + 1, 0, 0));

		int i = session_get_next_free();

		if (i == -1) break;
		
		session_init(i, &saddr, -1);
		if (session_connect(i) == -1) {
			session_delete(i);
			continue;
		}
		peer_add(saddr.sin_addr.s_addr, ntohs(saddr.sin_port), NULL);
	}
	
	if (ferror(peerfile)) {
		perror("getline()");
		exit(EXIT_FAILURE);
	}

	fclose(peerfile);
	if (line != NULL) free(line);

	// prepare timer events, check for timed out peers every second
	reftime = time(NULL);
	alarm(1);	// not exactly beautiful, but portable

	// main loop
	fprintf(logstd, "[%s] -- prowler started --\n", timestr());
	for (;;) {
		switch (poll(fds, nfds, -1)) {
		case -1:
			if (errno == EINTR) break;
			perror("poll()");
			exit(EXIT_FAILURE);
		default:
			// handle control events on event pipe before doing anything else
			if (ctlevfd.revents & POLLIN) {
				// read byte from event pipe
				unsigned char c;
				read(ctlevfd.fd, &c, 1);

				if (ctlevents & TIMER_FIRED) {
					reftime = time(NULL);

					// check for timed out sockets and status updates
					size_t active_peers = 0;
					for (i = 0; i < peerlist_size; ++i) {
						if (difftime(reftime, peerlist[i].last_contact) > SESSION_TIMEOUT) {
							peerlist[i].active = 0;
							session_delete(i);
							continue;
						}

						if (difftime(reftime, peerlist[i].last_contact) < ACTIVE_TIMEOUT)
							active_peers++;

						if (peerlist[i].active) continue;

						if (difftime(reftime, peerlist[i].last_connect) < CHECK_INTERVAL)
							continue;

						if (UNRESP_TRIES > 0 && peerlist[i].unresponsive > UNRESP_TRIES)
							continue;

						// try to contact unresponsive peer again
						int j = session_get_next_free();

						if (j == -1) break;
						
						saddr.sin_addr.s_addr = peerlist[i].ipaddr;
						saddr.sin_port = htons(peerlist[i].port);
	
						session_init(j, &saddr, i);
						if (session_connect(i) == -1) {
							session_delete(i);
							continue;
						}
						if (session[j].connecting == 0) {
							if (session[j].connecting && session[j].peerlist_index != -1)
								peerlist[session[j].peerlist_index].unresponsive = 0;
									// TODO: queue up data for sending here
						}
					}
					fprintf(logstd, "[%s]  seen %lu peers, %lu are active\n", timestr(), peerlist_size, active_peers);

					// unset control event
					ctlevents &= ~TIMER_FIRED;
				}
				if (ctlevents & DUMP_PEERLIST) {
					fprintf(logstd, "current peerlist:\n");
					size_t i;
					for (i = 0; i < peerlist_size; ++i)
						fprintf(logstd, "%s:%d\n", inet_ntoa(*(struct in_addr *) &peerlist[i].ipaddr), peerlist[i].port);

					// unset control event
					ctlevents &= ~DUMP_PEERLIST;
				}
			}

			// check connected sockets for events
			for (i = 0; i < nfds - RESERVED_FDS; ++i) {
				if (fds[i].revents == 0) continue;
				if (fds[i].revents & POLLERR) {
					// error on socket, e.g., connect() failed
					if (session[i].connecting && session[i].peerlist_index != -1) {
						if (difftime(reftime, peerlist[i].last_contact) > CHECK_INTERVAL) {
							peerlist[session[i].peerlist_index].unresponsive++;
						}
					}

					session_delete(i);
					session_terminate(i);
				} else if (fds[i].revents & POLLIN) {
					switch (bytes = session_receive(i)) {
					case -1:
						// receive error
						session_delete(i);
						session_terminate(i);
					case 0:
						// connection closed by peer, process received data
						if (session_done(i)) session_terminate(i);
						break;
					default:
						// TODO: process received data here


						if (session_done(i)) session_terminate(i);
						break;
					}
				} else if (fds[i].revents & POLLOUT) {
					if (session[i].connecting) {
						// connected
						peerlist[i].last_contact = reftime;

						if (session[i].connecting && session[i].peerlist_index != -1)
							peerlist[session[i].peerlist_index].unresponsive = 0;

						session[i].connecting = 0;

						// TODO: queue up data for sending here
						break;
					}

					// send data
					switch (bytes = session_send(i)) {
					case -1:
						// send error
						session_delete(i);
						session_terminate(i);
						break;
					default:
						if (session[i].txbytes == 0) {
							// data sent, now receive response
							fds[i].events &= ~POLLOUT;
							fds[i].events |= POLLIN;
						}
						break;
					}
				} else {
					// unhandled event, terminate session
					session_delete(i);
					session_terminate(i);
				}
			}

			break;
		}

		if (slowdown) usleep(slowdown);
	}

	// never reached
	return EXIT_SUCCESS;
}
