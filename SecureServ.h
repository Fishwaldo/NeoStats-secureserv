/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2005 Adam Rutter, Justin Hammond, Mark Hetherington
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
#define DET_AWAYMSG 7
#define DET_QUITMSG 8
#define DET_BUILTIN 10
#define DET_MAX		DET_BUILTIN

/* Action List */
#define ACT_SVSJOIN 0
#define ACT_AKILL 1
#define ACT_WARN 2
#define ACT_NOTHING 3
#define ACT_KILL 4
#define ACT_MAX ACT_KILL

extern Bot *ss_bot;

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
	int doscan;
	int datfileversion;
	char akillinfo[BUFSIZE];
	char nohelp[BUFSIZE];
	char HelpChan[MAXCHANLEN];
	int breakorcont;
	int doakill;
	int akilltime;
	int dosvsjoin;
	int helpcount;
	int verbose;
	int stayinchantime;
	int monchancycletime;
	int autoupgrade;
	int doUpdate;
	int dofizzer;
	int DoOnJoin;
	int BotEcho;
	int helpers;
	int defcount;
	char updateurl[SS_BUF_SIZE];
	char updateuname[MAXNICK];
	char updatepw[MAXNICK];
	char monbot[MAXNICK];
	char botquitmsg[BUFSIZE];
	int doprivchan;
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

/* update.c */
int ss_cmd_update(CmdParams *cmdparams);
int ss_cmd_set_updateinfo(CmdParams *cmdparams, SET_REASON reason);
int ss_cmd_set_autoupdate_cb (CmdParams *cmdparams, SET_REASON reason);
void GotHTTPAddress(char *data, adns_answer *a);
int AutoUpdate(void);

/* OnJoin.c */
int JoinNewChan(void);
void OnJoinBotStatus (CmdParams *cmdparams);
int ss_event_message (CmdParams *cmdparams);
int ss_event_versionrequest (CmdParams *cmdparams);
int LoadMonChans();
int ViriCount(void);
int InitOnJoinBots(void);
void FiniOnJoinBots(void);
int ss_cmd_bots(CmdParams *cmdparams);
int ss_cmd_checkchan(CmdParams *cmdparams);
int ss_cmd_monchan(CmdParams *cmdparams);
int ss_cmd_cycle(CmdParams *cmdparams);
int ss_cmd_set_monbot (CmdParams *cmdparams, SET_REASON reason);
int ss_event_kickbot(CmdParams *cmdparams);
int ss_event_emptychan(CmdParams *cmdparams);
int MonJoin(Channel *c);
int CheckMonBotKill(CmdParams *cmdparams);
int MonBotCycle(void);

/* scan.c */
void ScanStatus (CmdParams *cmdparams);
int ScanFizzer(Client *u);
int ScanChannelName(Client* u, Channel *c);
int ScanNick(Client *u);
int ScanIdent(Client *u);
int ScanRealname(Client *u);
int ScanPrivmsg(Client *u, char* buf);
int ScanChanMsg(Client *u, char* buf);
int ScanCTCPVersion(Client *u, char* buf);
int ss_cmd_list(CmdParams *cmdparams);
int ss_cmd_reload(CmdParams *cmdparams);
void InitScanner(void);
void load_dat(void);

/* Helpers.c */
int InitHelpers(void);
void FiniHelpers(void);
int ss_cmd_login(CmdParams *cmdparams);
int ss_cmd_logout(CmdParams *cmdparams);
int ss_cmd_assist(CmdParams *cmdparams);
int ss_cmd_helpers(CmdParams *cmdparams);
int ss_cmd_chpass(CmdParams *cmdparams);
int HelpersSignoff(CmdParams *cmdparams);
int HelpersAway(CmdParams *cmdparams);
void HelpersStatus (CmdParams *cmdparams);
int ss_cmd_set_helpers_cb(CmdParams *cmdparams, SET_REASON reason);

/* SecureServ_help.c */
extern const char *ts_help_checkchan[];
extern const char *ts_help_login[];
extern const char *ts_help_logout[];
extern const char *ts_help_chpass[];
extern const char *ts_help_cycle[];
extern const char *ts_help_update[];
extern const char *ts_help_status[];
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
extern const char ts_help_cycle_oneline[];
extern const char ts_help_list_oneline[];
extern const char ts_help_update_oneline[];
extern const char ts_help_bots_oneline[];
extern const char ts_help_monchan_oneline[];
extern const char ts_help_helpers_oneline[];
extern const char ts_help_reload_oneline[];

extern const char *ts_help_set_version[];
extern const char *ts_help_set_helpers[];
extern const char *ts_help_set_signonmsg[];
extern const char *ts_help_set_botquitmsg[];
extern const char *ts_help_set_akillmsg[];
extern const char *ts_help_set_nohelpmsg[];
extern const char *ts_help_set_helpchan[];
extern const char *ts_help_set_autosignout[];
extern const char *ts_help_set_joinhelpchan[];
extern const char *ts_help_set_report[];
extern const char *ts_help_set_doprivchan[];
extern const char *ts_help_set_checkfizzer[];
extern const char *ts_help_set_multicheck[];
extern const char *ts_help_set_akill[];
extern const char *ts_help_set_akilltime[];
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
extern const char *ts_help_set_updateinfo[];
extern const char *ts_help_set_onjoinbotmodes[];

extern char onjoinbot_modes[MODESIZE];

#endif /* SECURESERV_H */
