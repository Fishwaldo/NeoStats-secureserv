/* NetStats - IRC Statistical Services Copyright (c) 1999 Adam Rutter,
** Justin Hammond http://codeworks.kamserve.com
*
** Based from GeoStats 1.1.0 by Johnathan George net@lite.net
*
** NetStats CVS Identification
** $Id: SecureServ.h,v 1.1 2003/04/18 04:38:43 fishwaldo Exp $
*/


#ifndef TS_H
#define TS_H

#include "modconfig.h"

typedef struct virientry {
	char name[MAXHOST];
	int dettype;
	int var1;
	int var2;
	char ctcptype[MAXHOST];
	char recvmsg[MAXHOST];
	char sendmsg[MAXHOST];
	int action;
	int nofound;
	int noopen;
} virientry;

/* Detection Types */
#define DET_CTCP 0
#define DET_MSG 1

/* Action List */
#define ACT_SVSJOIN 0
#define ACT_AKILL 1
#define ACT_WARN 2
#define ACT_NOTHING 3


char *s_ts;


struct ts {
	int init;
	int timedif;
	int doscan;
	int viriversion;
	char signonscanmsg[512];
	char akillinfo[512];
	char nohelp[512];
	int breakorcont;
	int doakill;
	int dosvsjoin;
	int helpcount;

} ts;


struct exempts {
	char host[MAXHOST];
	int server;
	char who[MAXNICK];
	char reason[MAXHOST];
};

typedef struct exempts exemptinfo;


/* this is the list of viri */

list_t *viri;

/* this is the list of exempted hosts/servers */
list_t *exempt;

/* this is the size of the exempt list */
#define MAX_EXEMPTS	100
#define MAX_VIRI	100

/* ts.c */
int findscan(const void *key1, const void *key2);



#endif /* TS_H */
