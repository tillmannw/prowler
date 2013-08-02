// util.c -- (C) 2013 Tillmann Werner

#include <stdio.h>
#include <sys/time.h>
#include <time.h>

char tstr[26];

inline char *timestr(void) {
	struct tm *tm;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	tm = gmtime(&tv.tv_sec);
	strftime(tstr, 20, "%F %H:%M:%S", tm);
	snprintf(tstr + 19, 7, ".%05u", (unsigned int) tv.tv_usec);

	return tstr;
}
