/* NeoStats - IRC Statistical Services Copyright (c) 1999-2002 NeoStats Group Inc.
** Copyright (c) 1999-2002 Adam Rutter, Justin Hammond
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

#include "modconfig.h"
#include <stdio.h>
#include <fnmatch.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#else
#include <unistd.h>
#endif

#include "stats.h"
#include "dl.h"
#include "log.h"
#include "conf.h"
#include "SecureServ.h"
#include "http.h"

static int ScanNick(char **av, int ac);
void LoadConfig(void);
int check_version_reply(char *origin, char **av, int ac);
int do_set(User *u, char **av, int ac);
int do_status(User *u, char **av, int ac);
int do_reload(User *u, char **av, int ac);
int do_update(User *u, char **av, int ac);
void datver(HTTP_Response *response);
void datdownload(HTTP_Response *response);
static int CheckNick(char **av, int ac);
static int DelNick(char **av, int ac);
static void GotHTTPAddress(char *data, adns_answer *a);
int AutoUpdate(void);

static char ss_buf[SS_BUF_SIZE];
char s_SecureServ[MAXNICK];

ModuleInfo __module_info = {
	"SecureServ",
	"A Trojan Scanning Bot",
	"1.1",
	__DATE__,
	__TIME__
};


int new_m_version(char *origin, char **av, int ac) {
	snumeric_cmd(RPL_VERSION,origin, "Module SecureServ Loaded, Version: %s %s %s",__module_info.module_version,__module_info.module_build_date,__module_info.module_build_time);
	return 0;
}

Functions __module_functions[] = {
	{ MSG_VERSION,	new_m_version,	1 },
#ifdef HAVE_TOKEN_SUP
	{ TOK_VERSION,	new_m_version,	1 },
#endif
	{ MSG_NOTICE,   check_version_reply, 1},
#ifdef HAVE_TOKEN_SUP
	{ TOK_NOTICE,   check_version_reply, 1},
#endif
	{ NULL,		NULL,		0 }
};



int __Bot_Message(char *origin, char **argv, int argc)
{
	User *u;
	UserDetail *ud;

	SET_SEGV_LOCATION();
	u = finduser(origin); 
	if (!u) { 
		nlog(LOG_WARNING, LOG_CORE, "Unable to find user %s (ts)", origin); 
		return -1; 
	} 
	/* first, figure out what bot its too */
	if (strcasecmp(argv[0], s_SecureServ)) {
		OnJoinBotMsg(u, argv, argc);
		return -1;
	}

	if (!strcasecmp(argv[1], "help")) {
		if (argc == 2) {
			privmsg_list(u->nick, s_SecureServ, ts_help);
			if ((UserLevel(u) < NS_ULEVEL_OPER) && (u->moddata[SecureServ.modnum] != NULL)) {
				ud = (UserDetail *)u->moddata[SecureServ.modnum];
				if (ud->type == USER_HELPER) {
					privmsg_list(u->nick, s_SecureServ, ts_help_helper);
				}
			}
			if (UserLevel(u) >= NS_ULEVEL_OPER) {
				privmsg_list(u->nick, s_SecureServ, ts_help_helper);
				privmsg_list(u->nick, s_SecureServ, ts_help_oper);
			}
			privmsg_list(u->nick, s_SecureServ, ts_help_on_help);			
		} else if (argc == 3) {
			if ((!strcasecmp(argv[2], "set")) && (UserLevel(u) >= NS_ULEVEL_ADMIN)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_set);
			} else if (!strcasecmp(argv[2], "assist")) {
				if (u->moddata[SecureServ.modnum] != NULL) {
					ud = (UserDetail *)u->moddata[SecureServ.modnum];
					if (ud->type == USER_HELPER) {
						privmsg_list(u->nick, s_SecureServ, ts_help_assist);
						return 1;
					}
				}
				if (UserLevel(u) > NS_ULEVEL_OPER) {
					privmsg_list(u->nick, s_SecureServ, ts_help_assist);
					return 1;
				}
			} else if (!strcasecmp(argv[2], "login")) {
				privmsg_list(u->nick, s_SecureServ, ts_help_login);
			} else if (!strcasecmp(argv[2], "logout")) {
				privmsg_list(u->nick, s_SecureServ, ts_help_logout);
			} else if ((!strcasecmp(argv[2], "helpers")) && (UserLevel(u) >= NS_ULEVEL_OPER)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_helpers);
			} else if ((!strcasecmp(argv[2], "list")) && (UserLevel(u) >= NS_ULEVEL_OPER)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_list);
			} else if ((!strcasecmp(argv[2], "exclude")) && (UserLevel(u) >= 50)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_exclude);
			} else if ((!strcasecmp(argv[2], "checkchan")) && (UserLevel(u) >= NS_ULEVEL_OPER)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_checkchan);
			} else if ((!strcasecmp(argv[2], "cycle")) && (UserLevel(u) >= NS_ULEVEL_OPER)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_cycle);
			} else if ((!strcasecmp(argv[2], "update")) && (UserLevel(u) >= NS_ULEVEL_ADMIN)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_update);
			} else if ((!strcasecmp(argv[2], "status")) && (UserLevel(u) >= NS_ULEVEL_OPER)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_status);
			} else if ((!strcasecmp(argv[2], "bots")) && (UserLevel(u) >= 100)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_bots);
			} else if ((!strcasecmp(argv[2], "MONCHAN")) && (UserLevel(u) > NS_ULEVEL_OPER)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_monchan);
			} else if ((!strcasecmp(argv[2], "RELOAD")) && (UserLevel(u) > NS_ULEVEL_OPER)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_reload);
			} else {				
				prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help for more info", s_SecureServ);
			}
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help for more info", s_SecureServ);
		}
		return 1;
	} else if (!strcasecmp(argv[1], "login")) {
		Helpers_Login(u, argv, argc);
		return 1;		
 	} else if (!strcasecmp(argv[1], "logout")) {
		Helpers_Logout(u, argv, argc);
 		return 1;
	} else if (!strcasecmp(argv[1], "helpers")) {
		do_helpers(u, argv, argc);
 		return 1;
	} else if (!strcasecmp(argv[1], "list")) {
		do_list(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[1], "ASSIST")) {
		Helpers_Assist(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[1], "EXCLUDE")) {
		do_exempt(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[1], "BOTS")) {
		do_bots(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[1], "checkchan")) {
		do_checkchan(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[1], "monchan")) {
		do_monchan(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[1], "cycle")) {
		do_cycle(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[1], "set")) {
		do_set(u, argv, argc);
		return 1;		
	} else if (!strcasecmp(argv[1], "status")) {
		do_status(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[1], "update")) {
		do_update(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[1], "reload")) {
		do_reload(u, argv, argc);
		return 1;	
	} else {
		prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help", s_SecureServ);
	}
	return 1;
}



int do_set(User *u, char **av, int ac) {
	int i, j;
	char *buf;
	
	if (UserLevel(u) < NS_ULEVEL_ADMIN) {
		prefmsg(u->nick, s_SecureServ, "Permission is denied");
		chanalert(s_SecureServ, "%s tried to use SET, but Permission was denied", u->nick);
		return -1;
	}

	if (ac < 3 ) {
		prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
		return 1;
	}
	
	if (!strcasecmp(av[2], "SPLITTIME")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		i = atoi(av[3]);	
		if ((i <= 0) || (i > 1000)) {
			prefmsg(u->nick, s_SecureServ, "Value out of Range.");
			return 1;
		}
		/* if we get here, all is ok */
		SecureServ.timedif = i;
		prefmsg(u->nick, s_SecureServ, "Signon Split Time is set to %d", i);
		chanalert(s_SecureServ, "%s Set Signon Split Time to %d", u->nick, i);
		SetConf((void *)i, CFGINT, "SplitTime");
		return 1;
	} else if (!strcasecmp(av[2], "UPDATEINFO")) {
		if (ac < 5) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set", s_SecureServ);
			return 1;
		}
		SetConf((void *)av[3], CFGSTR, "UpdateUname");
		SetConf((void *)av[4], CFGSTR, "UpdatePassword");
		strlcpy(SecureServ.updateuname, av[3], MAXNICK);
		strlcpy(SecureServ.updatepw, av[4], MAXNICK);
		chanalert(s_SecureServ, "%s changed the Update Username and Password", u->nick);
		prefmsg(u->nick, s_SecureServ, "Update Username and Password has been updated to %s and %s", SecureServ.updateuname, SecureServ.updatepw);
		return 1;
	} else if (!strcasecmp(av[2], "CHANKEY")) {
		if ((ac < 4) || (strlen(av[3]) > CHANLEN)) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set", s_SecureServ);
			return 1;
		}
		SetConf((void *)av[3], CFGSTR, "ChanKey");
		strlcpy(SecureServ.ChanKey, av[3], CHANLEN);
		chanalert(s_SecureServ, "%s changed the Channel Flood Protection key to %s", u->nick, SecureServ.ChanKey);
		prefmsg(u->nick, s_SecureServ, "Channel Flood Protection Key has been updated to %s", SecureServ.ChanKey);
		return 1;
	} else if (!strcasecmp(av[2], "VERSION")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Version Checking is now enabled");
			chanalert(s_SecureServ, "%s has enabled Version Checking", u->nick);
			SetConf((void *)1, CFGINT, "DoVersionScan");
			SecureServ.doscan = 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Version Checking is now Disabled");
			chanalert(s_SecureServ, "%s has disabled Version Checking", u->nick);
			SetConf((void *)0, CFGINT, "DoVersionScan");
			SecureServ.doscan = 0;
			return 1;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
	} else if (!strcasecmp(av[2], "AUTOSIGNOUT")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Helper Away Auto logout is now enabled");
			chanalert(s_SecureServ, "%s has enabled Helper Away Auto Logout", u->nick);
			SetConf((void *)1, CFGINT, "DoAwaySignOut");
			SecureServ.signoutaway = 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Helper Away Auto logout is now Disabled");
			chanalert(s_SecureServ, "%s has disabled Helper Away Auto logout", u->nick);
			SetConf((void *)0, CFGINT, "DoAwaySignOut");
			SecureServ.signoutaway = 0;
			return 1;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
	} else if (!strcasecmp(av[2], "JOINHELPCHAN")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "SecureServ will join the Help Channel");
			chanalert(s_SecureServ, "%s has enabled SecureServ to join the HelpChannel", u->nick);
			SetConf((void *)1, CFGINT, "DoJoinHelpChan");
			SecureServ.joinhelpchan = 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "SecureServ will not join the Help Channel");
			chanalert(s_SecureServ, "%s has disabled SecureServ joining the Help Channel", u->nick);
			SetConf((void *)0, CFGINT, "DoJoinHelpChan");
			SecureServ.joinhelpchan = 0;
			return 1;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
	} else if (!strcasecmp(av[2], "REPORT")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Reporting is now enabled");
			chanalert(s_SecureServ, "%s has enabled Reporting", u->nick);
			SetConf((void *)1, CFGINT, "DoReport");
			SecureServ.report = 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Reporting is now Disabled");
			chanalert(s_SecureServ, "%s has disabled Reporting", u->nick);
			SetConf((void *)0, CFGINT, "DoReport");
			SecureServ.report = 0;
			return 1;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
	} else if (!strcasecmp(av[2], "FLOODPROT")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Channel Flood Protection is now enabled");
			chanalert(s_SecureServ, "%s has enabled Channel Flood Protection", u->nick);
			SetConf((void *)1, CFGINT, "DoFloodProt");
			SecureServ.FloodProt = 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Channel Flood Protection is now Disabled");
			chanalert(s_SecureServ, "%s has disabled Channel Flood Protection", u->nick);
			SetConf((void *)0, CFGINT, "DoFloodProt");
			SecureServ.FloodProt = 0;
			return 1;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
	} else if (!strcasecmp(av[2], "DOPRIVCHAN")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Private Channel Checking is now enabled");
			chanalert(s_SecureServ, "%s has enabled Private Channel Checking", u->nick);
			SetConf((void *)1, CFGINT, "DoPrivChan");
			SecureServ.doprivchan = 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Private Channel Checking is now Disabled");
			chanalert(s_SecureServ, "%s has disabled Private Channel Checking", u->nick);
			SetConf((void *)0, CFGINT, "DoPrivChan");
			SecureServ.doprivchan = 0;
			return 1;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
	} else if (!strcasecmp(av[2], "CHECKFIZZER")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Fizzer Virus Checking is now enabled");
			chanalert(s_SecureServ, "%s enabled Fizzer Virus Checking", u->nick);
			SetConf((void *)1, CFGINT, "FizzerCheck");
			SecureServ.dofizzer = 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Fizzer Checking is now disabled");
			chanalert(s_SecureServ, "%s disabled Fizzer Checking", u->nick);
			SetConf((void *)0, CFGINT, "FizzerCheck");
			SecureServ.dofizzer = 0;
			return 1;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
	} else if (!strcasecmp(av[2], "MULTICHECK")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Complete Version Checking is now enabled");
			chanalert(s_SecureServ, "%s enabled Complete Version Checking", u->nick);
			SetConf((void *)1, CFGINT, "MultiCheck");
			SecureServ.breakorcont = 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Complete Version Checking is now disabled");
			chanalert(s_SecureServ, "%s disabled Complete Version Checking", u->nick);
			SetConf((void *)0, CFGINT, "MultiCheck");
			SecureServ.breakorcont = 0;
			return 1;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
	} else if (!strcasecmp(av[2], "AKILL")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Akill'ing is now enabled");
			chanalert(s_SecureServ, "%s enabled Akill", u->nick);
			SetConf((void *)1, CFGINT, "DoAkill");
			SecureServ.doakill = 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Akill'ing is now disabled");
			chanalert(s_SecureServ, "%s disabled Akill", u->nick);
			SetConf((void *)0, CFGINT, "DoAkill");
			SecureServ.doakill = 0;
			return 1;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
	} else if (!strcasecmp(av[2], "AKILLTIME")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		i = atoi(av[3]);	
		if (i <= 0) {
			prefmsg(u->nick, s_SecureServ, "Value out of Range.");
			return 1;
		}
		/* if we get here, all is ok */
		SecureServ.akilltime = i;
		prefmsg(u->nick, s_SecureServ, "Akill Time is set to %d Seconds", i);
		chanalert(s_SecureServ, "%s Set Akill Time to %d Seconds", u->nick, i);
		SetConf((void *)i, CFGINT, "AkillTime");
		return 1;
	} else if (!strcasecmp(av[2], "CHANLOCKTIME")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		i = atoi(av[3]);	
		if ((i <= 0) || (i > 600)) {
			prefmsg(u->nick, s_SecureServ, "Value out of Range.");
			return 1;
		}
		/* if we get here, all is ok */
		SecureServ.closechantime = i;
		prefmsg(u->nick, s_SecureServ, "Channel Flood Protection will be active for %d seconds", i);
		chanalert(s_SecureServ, "%s Set Channel Flood Protection time to %d seconds", u->nick, i);
		SetConf((void *)i, CFGINT, "ChanLockTime");
		return 1;
	} else if (!strcasecmp(av[2], "NFCOUNT")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		i = atoi(av[3]);	
		if ((i <= 0) || (i > 100)) {
			prefmsg(u->nick, s_SecureServ, "Value out of Range.");
			return 1;
		}
		/* if we get here, all is ok */
		SecureServ.nfcount = i;
		prefmsg(u->nick, s_SecureServ, "NickFlood Count is set to %d in 10 Seconds", i);
		chanalert(s_SecureServ, "%s Set NickFlood Count to %d Seconds in 10 Seconds", u->nick, i);
		SetConf((void *)i, CFGINT, "NFCount");
		return 1;
	} else if (!strcasecmp(av[2], "DOJOIN")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "SVSJOINing is now enabled");
			chanalert(s_SecureServ, "%s enabled SVSJOINing", u->nick);
			SetConf((void *)1, CFGINT, "DoSvsJoin");
			SecureServ.dosvsjoin = 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "SVSJOINing is now disabled");
			chanalert(s_SecureServ, "%s disabled SVSJOINing", u->nick);
			SetConf((void *)0, CFGINT, "DoSvsJoin");
			SecureServ.dosvsjoin = 0;
			return 1;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
	} else if (!strcasecmp(av[2], "DOONJOIN")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "OnJoin Virus Checking is now enabled");
			chanalert(s_SecureServ, "%s enabled OnJoin Virus Checking", u->nick);
			SetConf((void *)1, CFGINT, "DoOnJoin");
			SecureServ.DoOnJoin = 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "OnJoin Virus Checking is now disabled");
			chanalert(s_SecureServ, "%s disabled OnJoin Virus Checking", u->nick);
			SetConf((void *)0, CFGINT, "DoOnJoin");
			SecureServ.DoOnJoin = 0;
			return 1;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
	} else if (!strcasecmp(av[2], "BOTECHO")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "OnJoin Bot Echo is now enabled");
			chanalert(s_SecureServ, "%s enabled OnJoin Bot Echo", u->nick);
			SetConf((void *)1, CFGINT, "BotEcho");
			SecureServ.BotEcho= 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "OnJoin Bot Echo is now disabled");
			chanalert(s_SecureServ, "%s disabled OnJoin Bot Echo", u->nick);
			SetConf((void *)0, CFGINT, "BotEcho");
			SecureServ.BotEcho= 0;
			return 1;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
	} else if (!strcasecmp(av[2], "VERBOSE")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Verbose Mode is now enabled");
			chanalert(s_SecureServ, "%s enabled Verbose Mode", u->nick);
			SetConf((void *)1, CFGINT, "Verbose");
			SecureServ.verbose = 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Verbose Mode is now disabled");
			chanalert(s_SecureServ, "%s disabled Verbose Mode", u->nick);
			SetConf((void *)0, CFGINT, "Verbose");
			SecureServ.verbose = 0;
			return 1;
		}
	} else if (!strcasecmp(av[2], "CYCLETIME")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		i = atoi(av[3]);	
		if ((i <= 0) || (i > 1000)) {
			prefmsg(u->nick, s_SecureServ, "Value out of Range.");
			return 1;
		}
		/* if we get here, all is ok */
		SecureServ.stayinchantime = i;
		change_mod_timer_interval ("JoinNewChan", i);
		prefmsg(u->nick, s_SecureServ, "Cycle Time is set to %d Seconds", i);
		chanalert(s_SecureServ, "%s Set Cycle Time to %d Seconds",u->nick,  i);
		SetConf((void *)i, CFGINT, "CycleTime");
		return 1;
	} else if (!strcasecmp(av[2], "MONBOT")) {
		do_set_monbot(u, av, ac);
		return 1;
	} else if (!strcasecmp(av[2], "AUTOUPDATE")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			if ((strlen(SecureServ.updateuname) > 0) && (strlen(SecureServ.updatepw) > 0)) {
				prefmsg(u->nick, s_SecureServ, "AutoUpdate Mode is now enabled");
				chanalert(s_SecureServ, "%s enabled AutoUpdate Mode", u->nick);
				SetConf((void *)1, CFGINT, "AutoUpdate");
				SecureServ.autoupgrade = 1;
				return 1;
			} else {
				prefmsg(u->nick, s_SecureServ, "You can not enable AutoUpdate, as you have not set a username and password");
				return 1;
			}
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "AutoUpdate Mode is now disabled");
			chanalert(s_SecureServ, "%s disabled AutoUpdate Mode", u->nick);
			SetConf((void *)0, CFGINT, "AutoUpdate");
			SecureServ.autoupgrade = 0;
			return 1;
		}
	} else if (!strcasecmp(av[2], "SAMPLETIME")) {
		if (ac < 5) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		i = atoi(av[3]);
		j = atoi(av[4]);	
		if ((i <= 0) || (i > 1000)) {
			prefmsg(u->nick, s_SecureServ, "SampleTime Value out of Range.");
			return 1;
		}
		if ((j <= 0) || (i > 1000)) {
			prefmsg(u->nick, s_SecureServ, "Threshold Value is out of Range");
			return 1;
		}
		/* if we get here, all is ok */
		SecureServ.sampletime = i;
		SecureServ.JoinThreshold = j;
		prefmsg(u->nick, s_SecureServ, "Flood Protection is now enabled at %d joins in %d Seconds", j, i);
		chanalert(s_SecureServ, "%s Set Flood Protection to %d joins in %d Seconds", u->nick, j, i);
		SetConf((void *)i, CFGINT, "SampleTime");
		SetConf((void *)j, CFGINT, "JoinThreshold");
		return 1;
	} else if (!strcasecmp(av[2], "SIGNONMSG")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
		buf = joinbuf(av, ac, 3);			
		strlcpy(SecureServ.signonscanmsg, buf, BUFSIZE);
		prefmsg(u->nick, s_SecureServ, "Signon Message is now set to %s", buf);
		chanalert(s_SecureServ, "%s set the Signon Message to %s", u->nick, buf);
		SetConf((void *)buf, CFGSTR, "SignOnMsg");
		free(buf);
	} else if (!strcasecmp(av[2], "AKILLMSG")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
		buf = joinbuf(av, ac, 3);			
		strlcpy(SecureServ.akillinfo, buf, BUFSIZE);
		prefmsg(u->nick, s_SecureServ, "Akill Message is now set to %s", buf);
		chanalert(s_SecureServ, "%s set the Akill Message to %s", u->nick, buf);
		SetConf((void *)buf, CFGSTR, "AkillMsg");
		free(buf);
	} else if (!strcasecmp(av[2], "NOHELPMSG")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
		buf = joinbuf(av, ac, 3);			
		strlcpy(SecureServ.nohelp, buf, BUFSIZE);
		prefmsg(u->nick, s_SecureServ, "No Help Message is now set to %s", buf);
		chanalert(s_SecureServ, "%s set the No Help Message to %s", u->nick, buf);
		SetConf((void *)buf, CFGSTR, "NoHelpMsg");
		free(buf);
	} else if (!strcasecmp(av[2], "HELPCHAN")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
		if (av[3][0] != '#') {
			prefmsg(u->nick, s_SecureServ, "Invalid Channel %s", av[3]);
			return 1;
		}
		strlcpy(SecureServ.HelpChan, av[3], CHANLEN);
		prefmsg(u->nick, s_SecureServ, "Help Channel is now set to %s", av[3]);
		chanalert(s_SecureServ, "%s set the Help Channel to %s", u->nick, av[3]);
		SetConf((void *)av[3], CFGSTR, "HelpChan");
	} else if (!strcasecmp(av[2], "LIST")) {
		prefmsg(u->nick, s_SecureServ, "Current SecureServ Settings:");
		prefmsg(u->nick, s_SecureServ, "SPLITTIME:    %d", SecureServ.timedif);
		prefmsg(u->nick, s_SecureServ, "VERSION:      %s", SecureServ.doscan ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "MULTICHECK:   %s", SecureServ.breakorcont ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "FLOODPROT:    %s", SecureServ.FloodProt ? "Enabled" : "Disabled");
		if (SecureServ.FloodProt) {
			prefmsg(u->nick, s_SecureServ, "SAMPLETIME:   %d/%d Seconds", SecureServ.JoinThreshold, SecureServ.sampletime);
			prefmsg(u->nick, s_SecureServ, "CHANLOCKTIME: %d seconds", SecureServ.closechantime);
			prefmsg(u->nick, s_SecureServ, "CHANKEY:      %s", SecureServ.ChanKey);
		}
		prefmsg(u->nick, s_SecureServ, "DOONJOIN:     %s", SecureServ.DoOnJoin ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "BOTECHO:      %s", SecureServ.BotEcho ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "DOPRIVCHAN:   %s", SecureServ.doprivchan ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "MONBOT:       %s", (strlen(SecureServ.monbot) > 0) ? SecureServ.monbot : "Not Set");
		prefmsg(u->nick, s_SecureServ, "AKILL:        %s", SecureServ.doakill ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "AKILLTIME:    %d", SecureServ.akilltime);
		prefmsg(u->nick, s_SecureServ, "NFCOUNT       %d in 10 seconds", SecureServ.nfcount);
		prefmsg(u->nick, s_SecureServ, "DOJOIN:       %s", SecureServ.dosvsjoin ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "VERBOSE:      %s", SecureServ.verbose ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "CYCLETIME:    %d", SecureServ.stayinchantime);
		prefmsg(u->nick, s_SecureServ, "UPDATEINFO:   %s", strlen(SecureServ.updateuname) > 0 ? "Set" : "Not Set");
		if ((UserLevel(u) > NS_ULEVEL_ADMIN) & (strlen(SecureServ.updateuname))) {
			prefmsg(u->nick, s_SecureServ, "Update Username is %s, Password is %s", SecureServ.updateuname, SecureServ.updatepw);
		}
		prefmsg(u->nick, s_SecureServ, "AUTOUPDATE:   %s", SecureServ.autoupgrade ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "REPORT:       %s", SecureServ.report ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "AUTOSIGNOUT:  %s", SecureServ.signoutaway ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "JOINHELPCHAN: %s", SecureServ.joinhelpchan ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "SIGNONMSG:    %s", SecureServ.signonscanmsg);
		prefmsg(u->nick, s_SecureServ, "AKILLMSG:     %s", SecureServ.akillinfo);
		prefmsg(u->nick, s_SecureServ, "NOHELPMSG:    %s", SecureServ.nohelp);
		prefmsg(u->nick, s_SecureServ, "HELPCHAN:     %s", SecureServ.HelpChan);
		prefmsg(u->nick, s_SecureServ, "End Of List");
		prefmsg(u->nick, s_SecureServ, "Type /msg %s HELP SET for more information on these settings", s_SecureServ);
		return 1;
	} else {
		prefmsg(u->nick, s_SecureServ, "Unknown Set option %s. try /msg %s help set", av[2], s_SecureServ);
		return 1;
	}		
	return 1;
}
int do_status(User *u, char **av, int ac)
{
	if (UserLevel(u) < NS_ULEVEL_OPER) {
		prefmsg(u->nick, s_SecureServ, "Permission Denied");
		chanalert(s_SecureServ, "%s tried to list status, but Permission was denied", u->nick);
		return -1;
	}			
	prefmsg(u->nick, s_SecureServ, "SecureServ Status:");
	prefmsg(u->nick, s_SecureServ, "==================");
	prefmsg(u->nick, s_SecureServ, "Virus Patterns Loaded: %d", ViriCount());
	prefmsg(u->nick, s_SecureServ, "CTCP Version Messages Scanned: %d", SecureServ.trigcounts[DET_CTCP]);
	prefmsg(u->nick, s_SecureServ, "CTCP Messages Acted On: %d", SecureServ.actioncounts[DET_CTCP]);
	prefmsg(u->nick, s_SecureServ, "CTCP Definitions: %d", SecureServ.definitions[DET_CTCP]);
	prefmsg(u->nick, s_SecureServ, "Private Messages Received: %d", SecureServ.trigcounts[DET_MSG]);
	prefmsg(u->nick, s_SecureServ, "Private Messages Acted on: %d", SecureServ.actioncounts[DET_MSG]);
	prefmsg(u->nick, s_SecureServ, "Private Message Definitions: %d", SecureServ.definitions[DET_MSG]);
	prefmsg(u->nick, s_SecureServ, "NickNames Checked: %d", SecureServ.trigcounts[DET_NICK]);
	prefmsg(u->nick, s_SecureServ, "NickName Acted on: %d", SecureServ.actioncounts[DET_NICK]);
	prefmsg(u->nick, s_SecureServ, "NickName Definitions: %d", SecureServ.definitions[DET_NICK]);
	prefmsg(u->nick, s_SecureServ, "Ident's Checked: %d", SecureServ.trigcounts[DET_IDENT]);
	prefmsg(u->nick, s_SecureServ, "Ident's Acted on: %d", SecureServ.actioncounts[DET_IDENT]);
	prefmsg(u->nick, s_SecureServ, "Ident Definitions: %d", SecureServ.definitions[DET_IDENT]);
	prefmsg(u->nick, s_SecureServ, "RealNames Checked: %d", SecureServ.trigcounts[DET_REALNAME]);
	prefmsg(u->nick, s_SecureServ, "RealNames Acted on: %d", SecureServ.actioncounts[DET_REALNAME]);
	prefmsg(u->nick, s_SecureServ, "RealName Definitions: %d", SecureServ.definitions[DET_REALNAME]);
	prefmsg(u->nick, s_SecureServ, "ChannelNames Checked: %d", SecureServ.trigcounts[DET_CHAN]);
	prefmsg(u->nick, s_SecureServ, "ChannelNames Acted on: %d", SecureServ.actioncounts[DET_CHAN]);
	prefmsg(u->nick, s_SecureServ, "ChannelName Definitions: %d", SecureServ.definitions[DET_CHAN]);
	prefmsg(u->nick, s_SecureServ, "Built-In Checks Run: %d", SecureServ.actioncounts[DET_BUILTIN]);
	prefmsg(u->nick, s_SecureServ, "Built-In Checks Acted on: %d", SecureServ.actioncounts[DET_BUILTIN]);
	prefmsg(u->nick, s_SecureServ, "Built-In Functions: %d", SecureServ.definitions[DET_BUILTIN]);
	prefmsg(u->nick, s_SecureServ, "AV Channel Helpers Logged in: %d", SecureServ.helpcount);
	prefmsg(u->nick, s_SecureServ, "Current Top AJPP: %d (in %d Seconds): %s", SecureServ.MaxAJPP, SecureServ.sampletime, SecureServ.MaxAJPPChan);
	if (strlen(SecureServ.lastchan) > 0) 
		prefmsg(u->nick, s_SecureServ, "Currently Checking %s with %s", SecureServ.lastchan, SecureServ.lastnick);
	prefmsg(u->nick, s_SecureServ, "End of List.");
	
	return 1;
}

static int Online(char **av, int ac) 
{
	SET_SEGV_LOCATION();
	if (init_bot(s_SecureServ,"ts",me.name,"Trojan Scanning Bot", services_bot_modes, __module_info.module_name) == -1 ) {
		/* Nick was in use!!!! */
		strlcat(s_SecureServ, "_", MAXNICK);
		init_bot(s_SecureServ,"ts",me.name,"Trojan Scanning Bot", services_bot_modes, __module_info.module_name);
	}
	LoadMonChans();
	Helpers_init();
	if (SecureServ.verbose) {
		chanalert(s_SecureServ, "%d Trojans Patterns loaded", ViriCount());
	}
	srand(hash_count(ch));
	/* kick of the autojoin timer */
	add_mod_timer("JoinNewChan", "RandomJoinChannel", __module_info.module_name, SecureServ.stayinchantime);
	/* start cleaning the nickflood list now */
	/* every sixty seconds should keep the list small, and not put *too* much load on NeoStats */
	add_mod_timer("CleanNickFlood", "CleanNickFlood", __module_info.module_name, 60);
	add_mod_timer("CheckLockChan", "CheckLockedChans", __module_info.module_name, 10);
	dns_lookup(HTTPHOST,  adns_r_a, GotHTTPAddress, "SecureServ Update Server");
	SecureServ.inited = 1;

	return 1;
};

void LoadConfig(void) 
{
	char *tmp;

	SET_SEGV_LOCATION();

	if(GetConf((void *)&SecureServ.FloodProt, CFGINT, "DoFloodProt") <= 0) {
		/* not configured, then enable */
		SecureServ.FloodProt = 1;
	} 
	if(GetConf((void *)&SecureServ.closechantime, CFGINT, "ChanLockTime") <= 0) {
		/* not configured, default to 30 seconds*/
		SecureServ.closechantime = 30;
	} 
	if (GetConf((void *)&tmp, CFGSTR, "ChanKey") <= 0) {
		strlcpy(SecureServ.ChanKey, "Eeeek", CHANLEN);
	} else {
		strlcpy(SecureServ.ChanKey, tmp, CHANLEN);
		free(tmp);
	}
	if(GetConf((void *)&SecureServ.doscan, CFGINT, "DoVersionScan") <= 0) {
		/* not configured, don't scan */
		SecureServ.doscan = 0;
	} 
	if(GetConf((void *)&SecureServ.doprivchan, CFGINT, "DoPrivChan") <= 0) {
		/* not configured, do scan */
		SecureServ.doprivchan = 1;
	} 
	if (GetConf((void *)&SecureServ.timedif, CFGINT, "SplitTime") <= 0) {
		/* use Default */
		SecureServ.timedif = 300;
	}
	if (GetConf((void *)&SecureServ.signoutaway, CFGINT, "DoAwaySignOut") <= 0) {
		/* yes */
		SecureServ.signoutaway = 1;
	}
	if (GetConf((void *)&SecureServ.report, CFGINT, "DoReport") <= 0) {
		/* yes */
		SecureServ.report = 1;
	}
	if (GetConf((void *)&SecureServ.joinhelpchan, CFGINT, "DoJoinHelpChan") <= 0) {
		/* yes */
		SecureServ.joinhelpchan = 1;
	}
	if (GetConf((void *)&SecureServ.verbose, CFGINT, "Verbose") <= 0){
		/* yes */
		SecureServ.verbose = 1;
	}
	if (GetConf((void *)&SecureServ.stayinchantime, CFGINT, "CycleTime") <= 0) {
		/* 60 seconds */
		SecureServ.stayinchantime = 60;
	}
	if (GetConf((void *)&SecureServ.nfcount, CFGINT, "NFCount") <= 0) {
		/* 5 in 10 seconds */
		SecureServ.nfcount = 5;
	}
	if (GetConf((void *)&SecureServ.autoupgrade, CFGINT, "AutoUpdate") <= 0) {
		/* disable autoupgrade is the default */
		SecureServ.autoupgrade = 0;
	}
	if (GetConf((void *)&tmp, CFGSTR, "UpdateUname") <= 0) {
		/* disable autoupgrade if its set */
		SecureServ.autoupgrade = 0;
		SecureServ.updateuname[0] = 0;
	} else {
		strlcpy(SecureServ.updateuname, tmp, MAXNICK);
		free(tmp);
	}
	if (GetConf((void *)&tmp, CFGSTR, "UpdatePassword") <= 0) {
		/* disable autoupgrade if its set */
		SecureServ.autoupgrade = 0;
		SecureServ.updatepw[0] = 0;
	} else {
		strlcpy(SecureServ.updatepw, tmp, MAXNICK);
		free(tmp);
	}
	if (GetConf((void *)&SecureServ.dofizzer, CFGINT, "FizzerCheck") <= 0) {
		/* scan for fizzer is the default */
		SecureServ.dofizzer = 1;
	}
	if (GetConf((void *)&SecureServ.breakorcont, CFGINT, "MultiCheck") <= 0) {
		/* break is the default is the default */
		SecureServ.breakorcont = 1;
	}
	if (GetConf((void *)&SecureServ.DoOnJoin, CFGINT, "DoOnJoin") <= 0) {
		/* yes is the default is the default */
		SecureServ.DoOnJoin = 1;
	}
	if (GetConf((void *)&SecureServ.BotEcho, CFGINT, "BotEcho") <= 0) {
		/* yes is the default is the default */
		SecureServ.BotEcho = 0;
	}	
	if (GetConf((void *)&SecureServ.doakill, CFGINT, "DoAkill") <= 0) {
		/* we akill is the default */
		SecureServ.doakill = 1;
	}
	if (GetConf((void *)&SecureServ.akilltime, CFGINT, "AkillTime") <= 0) {
		/* 1 hour is the default */
		SecureServ.akilltime = 3600;
	}
	if (GetConf((void *)&SecureServ.dosvsjoin, CFGINT, "DoSvsJoin") <= 0) {
		/* scan for fizzer is the default */
		SecureServ.dosvsjoin = 1;
	}
	if (GetConf((void *)&SecureServ.sampletime, CFGINT, "SampleTime") <= 0) {
		/* 5 secondsis the default */
		SecureServ.dosvsjoin = 5;
	}
	if (GetConf((void *)&SecureServ.JoinThreshold, CFGINT, "JoinThreshold") <= 0) {
		/* 5 joins is the default */
		SecureServ.JoinThreshold = 5;
	}
	if (GetConf((void *)&tmp, CFGSTR, "SignOnMsg") <= 0) {
		ircsnprintf(SecureServ.signonscanmsg, BUFSIZE, "Your IRC client is being checked for Trojans. Please dis-regard VERSION messages from %s", s_SecureServ);
	} else {
		strlcpy(SecureServ.signonscanmsg, tmp, BUFSIZE);
		free(tmp);
	}
	if (GetConf((void *)&tmp, CFGSTR, "NoHelpMsg") <= 0) {
		strlcpy(SecureServ.nohelp, "No Helpers are online at the moment, so you have been Akilled from this network. Please visit http://www.nohack.org for Trojan/Virus Info", BUFSIZE);
	} else {
		strlcpy(SecureServ.nohelp, tmp, BUFSIZE);
		free(tmp);
	}
	if (GetConf((void *)&tmp, CFGSTR, "AkillMsg") <= 0) {
		strlcpy(SecureServ.akillinfo, "You have been Akilled from this network. Please get a virus scanner and check your PC", BUFSIZE);
	} else {
		strlcpy(SecureServ.akillinfo, tmp, BUFSIZE);
		free(tmp);
	}
	if (GetConf((void *)&tmp, CFGSTR, "HelpChan") <= 0) {
		strlcpy(SecureServ.HelpChan, "#nohack", CHANLEN);
	} else {
		strlcpy(SecureServ.HelpChan, tmp, CHANLEN);
		free(tmp);
	}
	
	load_exempts();
	OnJoinBotConf();
	load_dat();
}

EventFnList __module_events[] = {
	{ EVENT_ONLINE, 	Online},
	{ EVENT_SIGNON, 	ScanNick},
	{ EVENT_SIGNOFF, 	DelNick},
	{ EVENT_KILL, 		DelNick},
	{ EVENT_JOINCHAN, 	ss_join_chan},
	{ EVENT_DELCHAN,	ss_del_chan},
	{ EVENT_NICKCHANGE, CheckNick},
	{ EVENT_KICK,		ss_kick_chan},
	{ EVENT_AWAY, 		Helpers_away},
	{ NULL, 			NULL}
};

static int DelNick(char **av, int ac) 
{
	NickFloodSignoff(av[0]);
	/* u->moddata is free'd in helpers_signoff */
	Helpers_signoff(finduser(av[0]));
	return 1;
}

/* scan nickname changes */
static int CheckNick(char **av, int ac) 
{
	User *u;
	
	if (!SecureServ.inited) {
		return 1;
	}
	
	u = finduser(av[1]);
	if (!u) {
		nlog(LOG_WARNING, LOG_MOD, "Cant Find user %s", av[1]);
		return 1;
	}
	u->moddata[SecureServ.modnum] = NULL;
	if (IsUserExempt(u) > 0) {
		nlog(LOG_DEBUG1, LOG_MOD, "Bye, I'm Exempt %s", u->nick);
		return -1;
	}
	/* is it a nickflood? */
	CheckNickFlood(u);

	/* check the nickname */
	return (ScanUser(u, SCAN_NICK));
}

/* scan someone connecting */
static int ScanNick(char **av, int ac) 
{
	User *u;

	SET_SEGV_LOCATION();
	/* don't do anything if NeoStats hasn't told us we are online yet */
	if (!SecureServ.inited)
		return 0;
							
	u = finduser(av[0]);
	if (!u) {
		nlog(LOG_WARNING, LOG_MOD, "Ehhh, Can't find user %s", av[0]);
		return -1;
	}
	
	if (IsUserExempt(u) > 0) {
		return -1;
	}

	/* fizzer scan */
	if (SecureServ.dofizzer == 1) {
		if(ScanFizzer(u)) {
			return 1;
		}
	}
	/* check the nickname, ident, realname */
	if(ScanUser(u, SCAN_NICK|SCAN_IDENT|SCAN_REALNAME)) {
		return 1;
	}

	if (SecureServ.doscan == 0) 
		return -1;

	if (time(NULL) - u->TS > SecureServ.timedif) {
		nlog(LOG_DEBUG1, LOG_MOD, "Netsplit Nick %s, Not Scanning %d > %d", av[0], (int)(time(NULL) - u->TS), SecureServ.timedif);
		return -1;
	}
	
	prefmsg(u->nick, s_SecureServ, SecureServ.signonscanmsg);
	privmsg(u->nick, s_SecureServ, "\1VERSION\1");
	return 1;
}

int check_version_reply(char *origin, char **av, int ac) 
{
	char *buf;
	int positive = 0;
	char **av1;
	int ac1 = 0;
	static int versioncount = 0;
	User* u;

	u = finduser(origin);
	if(!u) {
		return 0;
	}
	
	/* if its not a ctcp message, it is probably a notice for the ONJOIN bots */
	if (av[1][0] != '\1') {
		OnJoinBotMsg(u, av, ac);
		return 0;
	}
	if (!strcasecmp(av[1], "\1version")) {
		buf = joinbuf(av, ac, 2);
		/* send a Module_Event, so StatServ can pick up the version info !!! */
		/* nice little side effect isn't it? */
	
		AddStringToList(&av1, origin, &ac1);
		AddStringToList(&av1, buf, &ac1);	
 		Module_Event(EVENT_CLIENTVERSION, av1, ac1);
 		free(av1);
 		/* reset segvinmodule */
		SET_SEGV_INMODULE("SecureServ");
		
		if (SecureServ.verbose) {
			chanalert(s_SecureServ, "Got Version Reply from %s: %s", origin, buf);
		}
		positive = ScanCTCP(u, buf);
		versioncount++;
		/* why do we only change the version reply every 23 entries? Why not? */
		if ((positive == 0) && (versioncount > 23)) {
			strlcpy(SecureServ.sampleversion, buf, SS_BUF_SIZE);
			versioncount = 0;
		}
		free(buf);
	}				
	return 0;
}


int __ModInit(int modnum, int apiversion) {
	int i;
	
	if (apiversion < REQUIREDAPIVER) {
		nlog(LOG_CRITICAL, LOG_MOD, "Can't Load SecureServ. API Version MisMatch");
		return -1;
	}
	strlcpy(s_SecureServ, "SecureServ", MAXNICK);
	
	InitExempts();
	InitScanner();
	InitOnJoinBots();
	InitJoinFloodHash();
	InitNickFloodHash();
	
	SecureServ.inited = 0;			
	SecureServ.helpcount = 0;
	SecureServ.doUpdate = 0;
	SecureServ.MaxAJPP = 0;
	SecureServ.updateurl[0] = 0;
	
	for (i = 0; i > MAX_PATTERN_TYPES; i++) {
		SecureServ.trigcounts[i] = 0;
		SecureServ.actioncounts[i] = 0;
	}
	SecureServ.MaxAJPPChan[0] = 0;
	SecureServ.modnum = modnum;

	LoadConfig();
	return 1;
}

/* @brief this is the automatic dat file updater callback function. Checks whats on the website with 
** whats local, and if website is higher, either prompts for an upgrade, or does an automatic one :)
**
** NOTE: we can't call http_request from this function as its NOT recursive 
*/

void datver(HTTP_Response *response) {
	int myversion;
	/* check there was no error */
	if ((response->iError > 0) && (!strcasecmp(response->szHCode, "200"))) {
		myversion = atoi(response->pData);
		if (myversion <= 0) {
			nlog(LOG_NORMAL, LOG_MOD, "When Trying to Check Dat File Version, we got Permission Denied: %d", myversion);
			chanalert(s_SecureServ, "Permission Denied when trying to check Dat File Version: %d", myversion);
			return;
		}			
		nlog(LOG_DEBUG1, LOG_MOD, "LocalDat Version %d, WebSite %d", SecureServ.viriversion, myversion);
		if (myversion > SecureServ.viriversion) {
			if (SecureServ.autoupgrade > 0) {
				SecureServ.doUpdate = 1;
				add_mod_timer("DownLoadDat", "DownLoadNewDat", __module_info.module_name, 1);
			 } else
				chanalert(s_SecureServ, "A new DatFile Version %d is available. You should /msg %s update", myversion, s_SecureServ);
		}
	} else {
		nlog(LOG_DEBUG1, LOG_MOD, "Virus Definition check Failed. %s", response->szHCode);
		return;
	}
}
void DownLoadDat() 
{
	/* dont keep trying to download !*/
	if (SecureServ.doUpdate == 1) {
		del_mod_timer("DownLoadNewDat");
		SecureServ.doUpdate = 2;
		ircsnprintf(ss_buf, SS_BUF_SIZE, "http://%s%s?u=%s&p=%s", SecureServ.updateurl, DATFILE, SecureServ.updateuname, SecureServ.updatepw);
		http_request(ss_buf, 2, HFLAG_NONE, datdownload);
	} 
	return;
}


/* @brief this downloads a dat file and loads the new version into memory if required 
*/

void datdownload(HTTP_Response *response) {
	char tmpname[32];
	char *tmp, *tmp1;
	int i;
	
	/* if this is an automatic download, KILL the timer */
	if (SecureServ.doUpdate == 2) {
		/* clear this flag */
		SecureServ.doUpdate = 0;
	}
	if ((response->iError > 0) && (!strcasecmp(response->szHCode, "200"))) {

		/* check response code */
		tmp = malloc(response->lSize);
		strlcpy(tmp, response->pData, response->lSize);
		tmp1 = tmp;
		i = atoi(strtok(tmp, "\n"));
		free(tmp1);	
		if (i <= 0) {
			nlog(LOG_NORMAL, LOG_MOD, "When Trying to Download Dat File, we got Permission Denied: %d", i);
			chanalert(s_SecureServ, "Permission Denied when trying to Download Dat File : %d", i);
			return;
		}			
		
	
		/* make a temp file and write the contents to it */
		strlcpy(tmpname, "viriXXXXXX", 32);
		i = mkstemp(tmpname);
		write(i, response->pData, response->lSize);
		close(i);
		/* rename the file to the datfile */
		rename(tmpname, VIRI_DAT_NAME);
		/* reload the dat file */
		load_dat();
		nlog(LOG_NOTICE, LOG_MOD, "Successfully Downloaded DatFile Version %d", SecureServ.viriversion);
		chanalert(s_SecureServ, "DatFile Version %d has been downloaded and installed", SecureServ.viriversion);
	} else {
		nlog(LOG_DEBUG1, LOG_MOD, "Virus Definition Download Failed. %s", response->szHCode);
		chanalert(s_SecureServ, "Virus Definition Download Failed. %s", response->szHCode);
		return;
	}
	
}
	
		
void __ModFini() {

};


static void GotHTTPAddress(char *data, adns_answer *a) {
        char *url;
        int i, len, ri;

	adns_rr_info(a->type, 0, 0, &len, 0, 0);
        for(i = 0; i < a->nrrs;  i++) {
        	ri = adns_rr_info(a->type, 0, 0, 0, a->rrs.bytes +i*len, &url);
                if (!ri) {
			/* ok, we got a valid answer, lets maybe kick of the update check.*/
			SecureServ.sendtohost.sin_addr.s_addr = inet_addr(url);
			
			SecureServ.sendtohost.sin_port = htons(2334);
			SecureServ.sendtohost.sin_family = AF_INET;
			SecureServ.sendtosock = socket(AF_INET, SOCK_DGRAM, 0);

			strlcpy(SecureServ.updateurl, url, SS_BUF_SIZE);
			nlog(LOG_NORMAL, LOG_MOD, "Got DNS for Update Server: %s", url);
			if ((SecureServ.updateuname[0] != 0) && SecureServ.updatepw[0] != 0) {
				ircsnprintf(ss_buf, SS_BUF_SIZE, "http://%s%s?u=%s&p=%s", url, DATFILEVER, SecureServ.updateuname, SecureServ.updatepw);
				http_request(ss_buf, 2, HFLAG_NONE, datver); 
				/* add a timer for autoupdate. If its disabled, doesn't do anything anyway */
				add_mod_timer("AutoUpdate", "AutoUpdateDat", __module_info.module_name, 86400);
			} else {
				if (SecureServ.verbose) chanalert(s_SecureServ, "No Valid Username/Password configured for update Checking. Aborting Update Check");
			}
                } else {
	                chanalert(s_SecureServ, "DNS error Checking for Updates: %s", adns_strerror(ri));
	        }
	        free(url);
	}
	if (a->nrrs < 1) {
	        chanalert(s_SecureServ,  "DNS Error checking for Updates");
	}
}

int AutoUpdate(void) 
{
	if ((SecureServ.autoupgrade > 0) && SecureServ.updateuname[0] != 0 && SecureServ.updatepw[0] != 0 ) {
		ircsnprintf(ss_buf, SS_BUF_SIZE, "http://%s%s?u=%s&p=%s", SecureServ.updateurl, DATFILEVER, SecureServ.updateuname, SecureServ.updatepw);
		http_request(ss_buf, 2, HFLAG_NONE, datver); 
	}
	return 0;
}	

int do_reload(User *u, char **av, int ac)
{
	if (UserLevel(u) < NS_ULEVEL_OPER) {
		prefmsg(u->nick, s_SecureServ, "Permission Denied");
		chanalert(s_SecureServ, "%s tried to reload, but Permission was denied", u->nick);
		return -1;
	}			
	prefmsg(u->nick, s_SecureServ, "Reloading virus definition files");
    chanalert(s_SecureServ, "Reloading virus definition files at request of %s", u->nick);
	load_dat();
	return 1;
}

int do_update(User *u, char **av, int ac)
{
	if (UserLevel(u) < NS_ULEVEL_ADMIN) {
		prefmsg(u->nick, s_SecureServ, "Permission Denied");
		chanalert(s_SecureServ, "%s tried to update, but Permission was denied", u->nick);
		return -1;
	}
	ircsnprintf(ss_buf, SS_BUF_SIZE, "http://%s%s?u=%s&p=%s", SecureServ.updateurl, DATFILE, SecureServ.updateuname, SecureServ.updatepw);
	http_request(ss_buf, 2, HFLAG_NONE, datdownload);
	prefmsg(u->nick, s_SecureServ, "Requesting New Dat File. Please Monitor the Services Channel for Success/Failure");
	chanalert(s_SecureServ, "%s requested an update to the Dat file", u->nick);
	return 1;
}
