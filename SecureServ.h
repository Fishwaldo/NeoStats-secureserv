/* NetStats - IRC Statistical Services Copyright (c) 1999 Adam Rutter,
** Justin Hammond http://codeworks.kamserve.com
*
** Based from GeoStats 1.1.0 by Johnathan George net@lite.net
*
** NetStats CVS Identification
** $Id: SecureServ.h,v 1.11 2003/05/24 06:04:56 fishwaldo Exp $
*/


#ifndef TS_H
#define TS_H

#include "modconfig.h"
#include <pcre.h>




typedef struct virientry {
	char name[MAXHOST];
	int dettype;
	int var1;
	int var2;
	char ctcptype[MAXHOST];
	char recvmsg[MAXHOST];
	pcre *pattern;
	pcre_extra *patternextra;
	char sendmsg[MAXHOST];
	int action;
	int nofound;
	int noopen;
} virientry;

/* Detection Types */
#define DET_CTCP 0
#define DET_MSG 1
#define DET_NICK 2
#define DET_IDENT 3
#define DET_REALNAME 4
#define DET_CHAN 5
#define DET_BUILTIN 10

/* Action List */
#define ACT_SVSJOIN 0
#define ACT_AKILL 1
#define ACT_WARN 2
#define ACT_NOTHING 3


char *s_SecureServ;


struct SecureServ {
	int inited;
	int timedif;
	int doscan;
	int viriversion;
	char signonscanmsg[512];
	char akillinfo[512];
	char nohelp[512];
	char HelpChan[CHANLEN];
	int breakorcont;
	int doakill;
	int akilltime;
	int dosvsjoin;
	int helpcount;
	int verbose;
	int stayinchantime;
	int sampletime;
	int JoinThreshold;
	int autoupgrade;
	int doUpdate;
	int dofizzer;
	int MaxAJPP;
	char MaxAJPPChan[CHANLEN];
	int trigcounts[20];
	int actioncounts[20];
	int definitions[20];
	char updateurl[255];
	char updateuname[255];
	char updatepw[255];
	char lastchan[CHANLEN];
	char lastnick[MAXNICK];
} SecureServ;


struct exempts {
	char host[MAXHOST];
	int server;
	char who[MAXNICK];
	char reason[MAXHOST];
};

typedef struct exempts exemptinfo;

struct rn {
	char nick[MAXNICK];
	char user[MAXUSER];
	char host[MAXHOST];
	char rname[MAXHOST];
};

typedef struct rn randomnicks;

/* this is the list of viri */

list_t *viri;

/* this is the list of exempted hosts/servers */
list_t *exempt;


/* this is the list of random nicknames */

list_t *nicks;

/* this is the size of the exempt list */
#define MAX_EXEMPTS	100
#define MAX_VIRI	100
#define MAX_NICKS	100
/* SecureServ.c */
void gotpositive(User *u, virientry *ve, int type);
int Chan_Exempt(Chans *c);

/* OnJoin.c */
void JoinNewChan();
void OnJoinBotMsg(User *, char **, int );
int CheckChan(User *u, char *requestchan);

/* FloodCheck.c */
void ss_init_chan_hash();
int ss_new_chan(char **av, int ac);
int ss_join_chan(char **av, int ac);
int ss_del_chan(char **av, int ac);

/* SecureServ_help.c */
extern const char *ts_help[];
extern const char *ts_help_oper[];
extern const char *ts_help_set[];
extern const char *ts_help_checkchan[];
extern const char *ts_help_login[];
extern const char *ts_help_logout[];
extern const char *ts_help_cycle[];
extern const char *ts_help_update[];
extern const char *ts_help_status[];
extern const char *ts_help_exclude[];
extern const char *ts_help_list[];

#endif /* TS_H */
