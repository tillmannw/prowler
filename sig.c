#include <stdlib.h>
#include <unistd.h>

#include "sig.h"
#include "session.h"
#include "util.h"

void sigh(int s) {
	nfds_t i;

	switch (s) {
	case SIGUSR1:
		ctlevents |= DUMP_PEERLIST;
		// atomic write to our control event pipe
		if (write(pfd[1], "\x01", 1) == -1) {
			perror("write()");
		}
		break;
	case SIGALRM:
		ctlevents |= TIMER_FIRED;
		// atomic write to our control event pipe
		if (write(pfd[1], "\x01", 1) == -1) {
			perror("write()");
		}
		// reschedule timer event
		alarm(1);

		break;
	case SIGINT:
		// clean up and terminate
		for (i = 0; i < nfds; ++i) close(fds[i].fd);
		free(fds);
		free(session);
		fprintf(logstd, "\r[%s] -- terminated --\n", timestr());
		fclose(logstd);
		exit(EXIT_SUCCESS);
	default:
		break;
	}

	return;
}
