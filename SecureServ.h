/* NeoStats - IRC Statistical Services Copyright 
** Copyright (c) 1999-2004 Justin Hammond
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

#ifndef SECURESERV_H
#define SECURESERV_H

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
#define DET_CHANMSG 6
#define DET_BUILTIN 10

/* Action List */
#define ACT_SVSJOIN 0
#define ACT_AKILL 1
#define ACT_WARN 2
#define ACT_NOTHING 3
#define ACT_KILL 4

/* Scanner flags for User scanning */
#define SCAN_NICK		0x00000001
#define SCAN_IDENT		0x00000002
#define SCAN_REALNAME	0x00000004

extern char s_SecureServ[MAXNICK];

typedef struct UserDetail {
	int type;
	void *data;
} UserDetail;

typedef struct ServerDetail {
	int tsoutcount;
} ServerDetail;

typedef struct ChannelDetail {
	int scanned;
} ChannelDetail;

/* type list */
#define USER_HELPER 1
#define USER_INFECTED 2


#define SS_BUF_SIZE 255
#define MAX_PATTERN_TYPES	20

struct SecureServ {
	char user[MAXUSER]; 
	char host[MAXHOST]; 
	char realname[MAXREALNAME]; 
	int isonline;
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
	int monchancycletime;
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
	char botquitmsg[BUFSIZE];
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
	int monchancycle;
	int treatchanmsgaspm;
} SecureServ;

/* SecureServ.c */
void do_servversion();

/* update.c */
int do_update(User *u, char **av, int ac);
void GotHTTPAddress(char *data, adns_answer *a);
int AutoUpdate(void);

/* OnJoin.c */
void JoinNewChan();
void OnJoinBotMsg(User *u, char *botname, char *msg);
int ListMonChan(User *u);
int LoadMonChans();
int MonChanCount(void);
int OnJoinBotConf(void);
int ViriCount(void);
int InitOnJoinBots(void);
int ExitOnJoinBots(void);
int do_bots(User* u, char **argv, int argc);
int do_checkchan(User* u, char **argv, int argc);
int do_monchan(User* u, char **argv, int argc);
int do_cycle(User* u, char **argv, int argc);
int do_set_monbot(User* u, char **argv, int argc);
int CheckOnjoinBotKick(char **argv, int ac);
int MonJoin(Chans *c);
int MonBotDelChan(Chans *);
int CheckMonBotKill(char* nick);
void OnJoinDelChan(Chans* c);

/* scan.c */
int ScanFizzer(User *u);
int ScanChan(User* u, Chans *c);
int ScanUser(User *u, unsigned flags);
int ScanMsg(User *u, char* buf, int chanmsg);
int ScanCTCP(User *u, char* buf);
int do_list(User *u, char **av, int ac);
int do_reload(User *u, char **av, int ac);
void InitScanner(void);
void load_dat(void);

/* exempts.c */
int SS_IsChanExempt(Chans *c);
int SS_IsUserExempt(User *u);
int SS_do_exempt(User* u, char **argv, int argc);
int SS_InitExempts(void);

/* FloodCheck.c */
int InitJoinFlood(void);
int JoinFloodJoinChan(User *u, Chans *c);
int JoinFloodDelChan(Chans *c);
int CheckLockChan(void);
int InitNickFlood(void);
int CleanNickFlood(void);
int NickFloodSignOff(char * n);
int CheckNickFlood(User* u);
 
/* Helpers.c */
int HelpersInit(void);
int HelpersLogin(User *u, char **av, int ac);
int HelpersLogout(User *u, char **av, int ac);
int HelpersSignoff(User *u);
int HelpersAway(char **av, int ac);
int HelpersAssist(User *u, char **av, int ac);
int do_helpers(User *u, char **av, int ac);
int HelpersChpass(User *u, char **av, int ac);


/* SecureServ_help.c */
extern const char *ts_help_checkchan[];
extern const char *ts_help_login[];
extern const char *ts_help_logout[];
extern const char *ts_help_chpass[];
extern const char *ts_help_cycle[];
extern const char *ts_help_update[];
extern const char *ts_help_status[];
extern const char *ts_help_exclude[];
extern const char *ts_help_list[];
extern const char *ts_help_bots[];
extern const char *ts_help_monchan[];
extern const char *ts_help_assist[];
extern const char *ts_help_helpers[];
extern const char *ts_help_reload[];

extern const char ts_help_login_oneline[];
extern const char ts_help_logout_oneline[];
extern const char ts_help_chpass_oneline[];
extern const char ts_help_assist_oneline[];
extern const char ts_help_checkchan_oneline[];
extern const char ts_help_status_oneline[];
extern const char ts_help_exclude_oneline[];
extern const char ts_help_cycle_oneline[];
extern const char ts_help_list_oneline[];
extern const char ts_help_update_oneline[];
extern const char ts_help_bots_oneline[];
extern const char ts_help_monchan_oneline[];
extern const char ts_help_helpers_oneline[];
extern const char ts_help_reload_oneline[];

extern const char *ts_help_set_splittime[];
extern const char *ts_help_set_chankey[];
extern const char *ts_help_set_version[];
extern const char *ts_help_set_signonmsg[];
extern const char *ts_help_set_botquitmsg[];
extern const char *ts_help_set_akillmsg[];
extern const char *ts_help_set_nohelpmsg[];
extern const char *ts_help_set_helpchan[];
extern const char *ts_help_set_autosignout[];
extern const char *ts_help_set_joinhelpchan[];
extern const char *ts_help_set_report[];
extern const char *ts_help_set_floodprot[];
extern const char *ts_help_set_doprivchan[];
extern const char *ts_help_set_checkfizzer[];
extern const char *ts_help_set_multicheck[];
extern const char *ts_help_set_akill[];
extern const char *ts_help_set_akilltime[];
extern const char *ts_help_set_chanlocktime[];
extern const char *ts_help_set_nfcount[];
extern const char *ts_help_set_dojoin[];
extern const char *ts_help_set_doonjoin[];
extern const char *ts_help_set_botecho[];
extern const char *ts_help_set_verbose[];
extern const char *ts_help_set_monchancycle[];
extern const char *ts_help_set_treatchanmsgaspm[];
extern const char *ts_help_set_monchancycletime[];
extern const char *ts_help_set_cycletime[];
extern const char *ts_help_set_monbot[];
extern const char *ts_help_set_autoupdate[];
extern const char *ts_help_set_sampletime[];
extern const char *ts_help_set_updateinfo[];
extern const char *ts_help_set_onjoinbotmodes[];

extern char onjoinbot_modes[MODESIZE];


int is_monchan(char* chan);

/* these are needed for 2.5.14 compatibility */
#ifndef EVENT_SERVER
#define EVENT_SERVER EVENT_NEWSERVER
#endif


#endif /* SECURESERV_H */
