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
** $Id: SecureServ.h,v 1.16 2003/07/23 10:29:57 fishwaldo Exp $
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
	int DoOnJoin;
	char MaxAJPPChan[CHANLEN];
	int trigcounts[20];
	int actioncounts[20];
	int definitions[20];
	char updateurl[255];
	char updateuname[255];
	char updatepw[255];
	char lastchan[CHANLEN];
	char lastnick[MAXNICK];
	int nfcount;
	int doprivchan;
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


/* this is the nickflood stuff */
struct nicktrack_ {
	char nick[MAXNICK];
	int changes;
	int when;
};

typedef struct nicktrack_ nicktrack;

hash_t *nickflood;

/* this is a mess, but its aim is to handle the different IRCd's support */

#ifndef MODE_ADMONLY
#define MODE_ADMONLY 0
#endif

#ifndef MODE_OPERSONLY
#define MODE_OPERSONLY 0
#endif


#ifndef MODE_OPERONLY
#define MODE_OPERONLY MODE_OPERSONLY
#endif

#ifndef MODE_INVITE
#define MODE_INVITE MODE_INVITEONLY
#endif

/* this is the size of the exempt list */
#define MAX_EXEMPTS	100
#define MAX_VIRI	100
#define MAX_NICKS	100
/* SecureServ.c */
void gotpositive(User *u, virientry *ve, int type);
int Chan_Exempt(Chans *c);
int is_exempt(User *u);
/* OnJoin.c */
void JoinNewChan();
void OnJoinBotMsg(User *, char **, int );
int CheckChan(User *u, char *requestchan);
int ss_kick_chan(char **argv, int ac);

/* FloodCheck.c */
void ss_init_chan_hash();
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
