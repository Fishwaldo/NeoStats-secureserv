/* NeoStats - IRC Statistical Services Copyright 
** Copyright (c) 1999-2003 Justin Hammond
** http://www.neostats.net/
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
**  USA
**
** NeoStats CVS Identification
** $Id$
*/


#ifndef TS_H
#define TS_H

#include "modconfig.h"

#define VIRI_DAT_DIR		"data"
#define VIRI_DAT_NAME		"data/viri.dat"
#define CUSTOM_DAT_NAME		"data/customviri.dat"
#define NUM_DAT_FILES	2

#define REQUIREDAPIVER 1

#define MAXVIRNAME		64
#define MAXREASON		128
#define MAXCTCPTYPE		64
#define LOCALBUFSIZE	32

typedef struct virientry {
	char name[MAXVIRNAME];
	int dettype;
	int var1;
	int var2;
	char ctcptype[MAXCTCPTYPE];
	char recvmsg[BUFSIZE];
	pcre *pattern;
	pcre_extra *patternextra;
	char sendmsg[BUFSIZE];
	int action;
	int nofound;
	int noopen;
	int iscustom;
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

extern char s_SecureServ[MAXNICK];

typedef struct UserDetail {
	int type;
	void *data;
} UserDetail;

/* type list */
#define USER_HELPER 1
#define USER_INFECTED 2

#define SS_BUF_SIZE 255
#define MAX_PATTERN_TYPES	20

struct SecureServ {
	int inited;
	int timedif;
	int doscan;
	int viriversion;
	char signonscanmsg[BUFSIZE];
	char akillinfo[BUFSIZE];
	char nohelp[BUFSIZE];
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
	int DoOnJoin;
	int BotEcho;
	char MaxAJPPChan[CHANLEN];
	int trigcounts[MAX_PATTERN_TYPES];
	int actioncounts[MAX_PATTERN_TYPES];
	int definitions[MAX_PATTERN_TYPES];
	char updateurl[SS_BUF_SIZE];
	char updateuname[MAXNICK];
	char updatepw[MAXNICK];
	char lastchan[CHANLEN];
	char lastnick[MAXNICK];
	char monbot[MAXNICK];
	int nfcount;
	int doprivchan;
	char ChanKey[CHANLEN];
	int closechantime;
	int FloodProt;
	struct sockaddr_in sendtohost;
	int sendtosock;
	int signoutaway;
	int report;
	int joinhelpchan;
	int modnum;
	char sampleversion[SS_BUF_SIZE];
} SecureServ;


struct exempts {
	char host[MAXHOST];
	int server;
	char who[MAXNICK];
	char reason[MAXREASON];
};

typedef struct exempts exemptinfo;

struct rn {
	char nick[MAXNICK];
	char user[MAXUSER];
	char host[MAXHOST];
	char rname[MAXREALNAME];
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
#define MAX_VIRI	-1
#define MAX_NICKS	100

/* SecureServ.c */
void gotpositive(User *u, virientry *ve, int type);
int Chan_Exempt(Chans *c);
int is_exempt(User *u);

/* OnJoin.c */
void JoinNewChan();
void OnJoinBotMsg(User *, char **, int );
int CheckChan(User *u, char *requestchan);
int MonChan(User *u, char *requestchan);
int ss_kick_chan(char **argv, int ac);
int ListMonChan(User *u);
int StopMon(User *u, char *chan);
int LoadMonChans();
int MonChanCount(void);

/* FloodCheck.c */
void InitJoinFloodHash(void);
int ss_join_chan(char **av, int ac);
int ss_del_chan(char **av, int ac);
int CheckLockChan(void);
int InitNickFloodHash(void);
int CleanNickFlood(void);
int NickFloodSignoff(char * n);
int CheckNickFlood(User* u);

/* Helpers.c */
void Helpers_init(void);
int Helpers_add(User *u, char **av, int ac);
int Helpers_del(User *u, char *nick);
int Helpers_list(User *u);
int Helpers_chpass(User *u, char **av, int ac);
int Helpers_Login(User *u, char **av, int ac);
int Helpers_Logout(User *u);
int Helpers_signoff(User *u);
int Helpers_away(char **av, int ac);
int Helpers_Assist(User *u, char **av, int ac);

/* SecureServ_help.c */
extern const char *ts_help[];
extern const char *ts_help_on_help[];
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
extern const char *ts_help_bots[];
extern const char *ts_help_monchan[];
extern const char *ts_help_assist[];
extern const char *ts_help_helper[];
extern const char *ts_help_helpers[];
extern const char *ts_help_reload[];
#endif /* TS_H */
