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

static int ScanNick(char **av, int ac);
static int LoadConfig(void);
static int check_version_reply(User* u, char **av, int ac);
static int ss_notice(char *origin, char **av, int ac);
static int do_set(User *u, char **av, int ac);
static int do_status(User *u, char **av, int ac);
static int NickChange(char **av, int ac);
static int DelNick(char **av, int ac);
static int ss_kick_chan(char **argv, int ac);

char s_SecureServ[MAXNICK];

ModuleInfo __module_info = {
	"SecureServ",
	"A Trojan Scanning Bot",
	"1.2",
	__DATE__,
	__TIME__
};

static int new_m_version(char *origin, char **av, int ac) 
{
	snumeric_cmd(RPL_VERSION,origin, "Module SecureServ Loaded, Version: %s %s %s Dat: %d",__module_info.module_version,__module_info.module_build_date,__module_info.module_build_time, SecureServ.viriversion);
	return 0;
}

Functions __module_functions[] = {
	{ MSG_VERSION,	new_m_version,	1 },
#ifdef GOTTOKENSUPPORT
	{ TOK_VERSION,	new_m_version,	1 },
#endif
	{ MSG_NOTICE,   ss_notice, 1},
#ifdef GOTTOKENSUPPORT
	{ TOK_NOTICE,   ss_notice, 1},
#endif
	{ NULL,		NULL,		0 }
};

int __BotMessage(char *origin, char **argv, int argc)
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
			} else if (!strcasecmp(argv[2], "chpass")) {
				privmsg_list(u->nick, s_SecureServ, ts_help_chpass);
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
		HelpersLogin(u, argv, argc);
		return 1;		
 	} else if (!strcasecmp(argv[1], "logout")) {
		HelpersLogout(u, argv, argc);
 		return 1;
	} else if (!strcasecmp(argv[1], "chpass")) {
		HelpersChpass(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[1], "helpers")) {
		do_helpers(u, argv, argc);
 		return 1;
	} else if (!strcasecmp(argv[1], "list")) {
		do_list(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[1], "ASSIST")) {
		HelpersAssist(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[1], "EXCLUDE")) {
		SS_do_exempt(u, argv, argc);
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
	} else if (!strcasecmp(argv[1], "version")) {
		/* leave this command un-documented. Its only for checking applications */
		prefmsg(u->nick, s_SecureServ, "%d", SecureServ.viriversion);
	} else {
		prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help", s_SecureServ);
	}
	return 1;
}

int __ChanMessage(char *origin, char **argv, int argc) {
	char *buf;
	User *u;
	
	/* first, if its the services channel, just ignore it */
	if (!strcasecmp(argv[0], me.chan)) {
		return -1;
	}
	/* otherwise, just pass it to the ScanMsg function */
	u = finduser(origin);
	if (u) {
		buf = joinbuf(argv, argc, 1);
		ScanMsg(u, buf, 1);
		free(buf);
	}
	return 1;

}
static int do_set(User *u, char **av, int ac) 
{
	int i, j;
	char *buf;
	
	SET_SEGV_LOCATION();
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
	} else if (!strcasecmp(av[2], "TREATCHANMSGASPM")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "\2Warning:\2");
			prefmsg(u->nick, s_SecureServ, "This option can consume a \2LOT\2 of CPU");
			prefmsg(u->nick, s_SecureServ, "When a Onjoin bot or MonBot is on large channel with lots of chatter");
			prefmsg(u->nick, s_SecureServ, "Its not a recomended configuration.");
			prefmsg(u->nick, s_SecureServ, "If you really want to enable this, type \2/msg %s SET TREATCHANMSGASPM IGOTLOTSOFCPU\2 to really enable this", s_SecureServ);
			return 1;
		} else if (!strcasecmp(av[3], "IGOTLOTSOFCPU")) {
			prefmsg(u->nick, s_SecureServ, "Channel Messages are now treated as PM Messages. You did read the help didn't you?");
			chanalert(s_SecureServ, "%s has configured %s to treat Channels messages as PM messages", u->nick, s_SecureServ);
			SetConf((void *)1, CFGINT, "ChanMsgAsPM");
			SecureServ.treatchanmsgaspm = 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Version Checking is now Disabled");
			chanalert(s_SecureServ, "%s has disabled Version Checking", u->nick);
			SetConf((void *)0, CFGINT, "ChanMsgAsPM");
			SecureServ.treatchanmsgaspm = 0;
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
	} else if (!strcasecmp(av[2], "MONCHANCYCLE")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Monitor Channel Cycle is now enabled");
			chanalert(s_SecureServ, "%s enabled Monitor Channel Cycle", u->nick);
			SetConf((void *)1, CFGINT, "MonChanCycle");
			SecureServ.monchancycle = 1;
			return 1;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Monitor Channel Cycle is now disabled");
			chanalert(s_SecureServ, "%s disabled Monitor Channel Cycle", u->nick);
			SetConf((void *)0, CFGINT, "MonChanCycle");
			SecureServ.monchancycle = 0;
			return 1;
		}
	} else if (!strcasecmp(av[2], "MONCHANCYCLETIME")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}			
		i = atoi(av[3]);	
		if ((i <= 0) || (i > 10000)) {
			prefmsg(u->nick, s_SecureServ, "Value out of Range.");
			return 1;
		}
		/* if we get here, all is ok */
		SecureServ.monchancycletime = i;
		change_mod_timer_interval ("MonitorBotCycle", i);
		prefmsg(u->nick, s_SecureServ, "Monitor Channel Cycle Time is set to %d Seconds", i);
		chanalert(s_SecureServ, "%s Set Monitor Channel Cycle Time to %d Seconds",u->nick,  i);
		SetConf((void *)i, CFGINT, "MonCycleTime");
		return 1;
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
	} else if (!strcasecmp(av[2], "BOTQUITMSG")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return 1;
		}
		buf = joinbuf(av, ac, 3);			
		strlcpy(SecureServ.botquitmsg, buf, BUFSIZE);
		prefmsg(u->nick, s_SecureServ, "Bot quit message is now set to %s", buf);
		chanalert(s_SecureServ, "%s set the bot quit message to %s", u->nick, buf);
		SetConf((void *)buf, CFGSTR, "BotQuitMsg");
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
		prefmsg(u->nick, s_SecureServ, "CHECKFIZZER:  %s", SecureServ.dofizzer ? "Enabled" : "Disabled");
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
		prefmsg(u->nick, s_SecureServ, "MONCHANCYCLE: %s", SecureServ.monchancycle ? "Enabled" : "Disabled");
		if (SecureServ.monchancycle) {
			prefmsg(u->nick, s_SecureServ, "MONCHANCYCLETIME: %d", SecureServ.monchancycletime);
		}
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
		prefmsg(u->nick, s_SecureServ, "BOTQUITMSG:   %s", SecureServ.botquitmsg);
		prefmsg(u->nick, s_SecureServ, "SIGNONMSG:    %s", SecureServ.signonscanmsg);
		prefmsg(u->nick, s_SecureServ, "AKILLMSG:     %s", SecureServ.akillinfo);
		prefmsg(u->nick, s_SecureServ, "NOHELPMSG:    %s", SecureServ.nohelp);
		prefmsg(u->nick, s_SecureServ, "HELPCHAN:     %s", SecureServ.HelpChan);
		prefmsg(u->nick, s_SecureServ, "TREATCHANMSGASPM:");
		prefmsg(u->nick, s_SecureServ, "              %s", SecureServ.treatchanmsgaspm ? "Enabled (Warning Read Help)" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "End Of List");
		prefmsg(u->nick, s_SecureServ, "Type /msg %s HELP SET for more information on these settings", s_SecureServ);
		return 1;
	} else {
		prefmsg(u->nick, s_SecureServ, "Unknown Set option %s. try /msg %s help set", av[2], s_SecureServ);
		return 1;
	}		
	return 1;
}

static int do_status(User *u, char **av, int ac)
{
	SET_SEGV_LOCATION();
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
	prefmsg(u->nick, s_SecureServ, "Channel Messages Checked: %d", SecureServ.trigcounts[DET_CHANMSG]);
	prefmsg(u->nick, s_SecureServ, "Channel Messages Acted on: %d", SecureServ.actioncounts[DET_CHANMSG]);
	prefmsg(u->nick, s_SecureServ, "Channel Messages Definitions: %d", SecureServ.definitions[DET_CHANMSG]);
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
	Chans *c;
	User *u;
	lnode_t *lnode;
	hnode_t *hnode;
	hscan_t hs;
	
	SET_SEGV_LOCATION();
	if (init_bot(s_SecureServ, SecureServ.user, SecureServ.host, SecureServ.rname, services_bot_modes, __module_info.module_name) == -1 ) {
		/* Nick was in use!!!! */
		strlcat(s_SecureServ, "_", MAXNICK);
		init_bot(s_SecureServ, SecureServ.user, SecureServ.host, SecureServ.rname, services_bot_modes, __module_info.module_name);
	}
	HelpersInit();
	if (SecureServ.verbose) {
		chanalert(s_SecureServ, "%d Trojans Patterns loaded", ViriCount());
	}
	srand(hash_count(ch));
	/* kick of the autojoin timer */
	add_mod_timer("JoinNewChan", "RandomJoinChannel", __module_info.module_name, SecureServ.stayinchantime);
	add_mod_timer("MonBotCycle", "MonitorBotCycle", __module_info.module_name, SecureServ.monchancycletime);
	/* start cleaning the nickflood list now */
	/* every sixty seconds should keep the list small, and not put *too* much load on NeoStats */
	add_mod_timer("CleanNickFlood", "CleanNickFlood", __module_info.module_name, 60);
	add_mod_timer("CheckLockChan", "CheckLockedChans", __module_info.module_name, 60);
	dns_lookup("secure.irc-chat.net",  adns_r_a, GotHTTPAddress, "SecureServ Update Server");
	SecureServ.isonline = 1;
	LoadMonChans();

	/* here, we run though the channel lists, as when we were booting, we were not checking. */
	hash_scan_begin(&hs, ch);
	while ((hnode = hash_scan_next(&hs)) != NULL) {
		c = hnode_get(hnode);
		if (!c)
			continue;

		/* now scan channel members */
		lnode = list_first(c->chanmembers);
		while (lnode) {
			u = finduser(lnode_get(lnode));
			if (SS_IsUserExempt(u) > 0) {
				lnode = list_next(c->chanmembers, lnode);
				continue;
			}
			if (u && ScanChan(u, c) == 0) {
				break;
			}
			lnode = list_next(c->chanmembers, lnode);
		}
	}

	return 1;
};

static int LoadConfig(void) 
{
	char *tmp;

	SET_SEGV_LOCATION();

	if (GetConf((void *) &tmp, CFGSTR, "Nick") < 0) {
		strlcpy(s_SecureServ, "SecureServ", MAXNICK);
	} else {
		strlcpy(s_SecureServ, tmp, MAXNICK);
		free(tmp);
	}
	if (GetConf((void *) &tmp, CFGSTR, "User") < 0) {
		strlcpy(SecureServ.user, "TS", MAXUSER);
	} else {
		strlcpy(SecureServ.user, tmp, MAXUSER);
		free(tmp);
	}
	if (GetConf((void *) &tmp, CFGSTR, "Host") < 0) {
		strlcpy(SecureServ.host, me.name, MAXHOST);
	} else {
		strlcpy(SecureServ.host, tmp, MAXHOST);
		free(tmp);
	}
	if (GetConf((void *) &tmp, CFGSTR, "Rname") < 0) {
		ircsnprintf(SecureServ.rname, MAXREALNAME, "Trojan Scanning Bot");
	} else {
		strlcpy(SecureServ.rname, tmp, MAXREALNAME);
		free(tmp);
	}
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
	if (GetConf((void *)&SecureServ.monchancycle, CFGINT, "MonChanCycle") <= 0){
		/* yes */
		SecureServ.monchancycle = 1;
	}
	if (GetConf((void *)&SecureServ.stayinchantime, CFGINT, "CycleTime") <= 0) {
		/* 60 seconds */
		SecureServ.stayinchantime = 60;
	}
	if (GetConf((void *)&SecureServ.monchancycletime, CFGINT, "MonCycleTime") <= 0) {
		/* 30 min cycle time */
		SecureServ.monchancycletime = 1800;
	}
	if (GetConf((void *)&SecureServ.nfcount, CFGINT, "NFCount") <= 0) {
		/* 5 in 10 seconds */
		SecureServ.nfcount = 5;
	}
	if (GetConf((void *)&SecureServ.autoupgrade, CFGINT, "AutoUpdate") <= 0) {
		/* disable autoupgrade is the default */
		SecureServ.autoupgrade = 0;
	}
	if (GetConf((void *)&SecureServ.treatchanmsgaspm, CFGINT, "ChanMsgAsPM") <= 0) {
		/* disable is the default */
		SecureServ.treatchanmsgaspm = 0;
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
		SecureServ.sampletime = 5;
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
	if (GetConf((void *)&tmp, CFGSTR, "BotQuitMsg") <= 0) {
		ircsnprintf(SecureServ.botquitmsg, BUFSIZE, "Client quit");
	} else {
		strlcpy(SecureServ.botquitmsg, tmp, BUFSIZE);
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
	return 1;
}
int ss_new_chan(char **av, int ac)
{
	Chans* c;
	ChannelDetail *cd;

	SET_SEGV_LOCATION();
	/* find the chan in the Core */
	c = findchan(av[0]);
	if (!c) {
		nlog(LOG_WARNING, LOG_MOD, "newchan: Can't Find Channel %s", av[0]);
		return -1;
	}
	cd = malloc(sizeof(ChannelDetail));
	cd->scanned = 0;
	c->moddata[SecureServ.modnum] = cd;
	return 1;
}

int ss_join_chan(char **av, int ac)
{
	Chans* c;
	User* u;
	ChannelDetail *cd;

	SET_SEGV_LOCATION();
	/* if we are not online, exit this */
	if (!SecureServ.isonline) {
		return -1;
	}

	/* find the chan in the Core */
	c = findchan(av[0]);
	if (!c) {
		nlog(LOG_WARNING, LOG_MOD, "joinchan: Can't Find Channel %s", av[0]);
		return -1;
	}
	
	/* is it exempt? */
	if (SS_IsChanExempt(c) > 0) {
		return -1;
	}

	u = finduser(av[1]);
	if (!u) {
		nlog(LOG_WARNING, LOG_MOD, "Can't find nick %s", av[1]);
		return -1;
	}
	
	/* check if its a monchan and we are not in place */
	if (c->cur_users == 1) 
		MonJoin(c);
	
	/* how about the user, is he exempt? */
	if (SS_IsUserExempt(u) > 0) {
		return -1;
	}
	
	/* first, check if this is a *bad* channel only if its the first person to join.*/
	/* NOTE: if its a monchan, c->cur_users will be 2 here, as our MonBot would have joined above 
	 * but we only check for 1 users. Why? Easy, because chances are, a MonChan is not going to trigger a 
	 * Signature is it? So this has the side effect of reducing our cpu consuption
	 * and the reason we only check if there is one user, is that we only need to check
	 * a channel name once, not everytime someone joins the channel. 
	 * -Fish
	 */
	 
	 /* this is actually pretty screwed up. You know why? because if a exempt user joins a bad channel 
	  * such as a IRCop, then the usercount will be screwed up next time someone joins it and really should 
	  * be killed 
	  */
	cd = c->moddata[SecureServ.modnum];
	/* if cd doesn't exist, soemthing major is wrong */
	if(cd && cd->scanned == 0) {
		ScanChan(u, c);
		cd->scanned = 1;
	}
	if(JoinFloodJoinChan(u, c))
		return 1;

	
	return 1;
}
int ss_part_chan(char **av, int ac) 
{
	Chans *c;
	
	SET_SEGV_LOCATION();
	c = findchan(av[0]);
	if (!c) {
		return -1;
	}
	MonBotDelChan(c);
	return 1;
}

int ss_del_chan(char **av, int ac) 
{
	Chans* c;
	ChannelDetail *cd;

	SET_SEGV_LOCATION();
	c = findchan(av[0]);
	if (!c) {
		nlog(LOG_WARNING, LOG_MOD, "Can't find Channel %s", av[0]);
		return -1;
	}
	cd = c->moddata[SecureServ.modnum];
	free(cd);
	c->moddata[SecureServ.modnum] = NULL;

	JoinFloodDelChan(c);

	return 1;
}

int ss_user_away(char **av, int ac)
{
	SET_SEGV_LOCATION();
	HelpersAway(av, ac);
	/* TODO: scan away messages for spam */
	return 1;
}
/* this is a future s->flags define that we dont use yet */
#ifndef NS_FLAGS_NETJOIN
/* @brief we allocate the moduledata struct for the server so we can check for TS problems with servers */

int ss_new_server(char **av, int ac)
{
	Server *s;
	ServerDetail *sd;
	s = findserver(av[0]);
	if (s) {
		sd = malloc(sizeof(ServerDetail));
		sd->tsoutcount = 0;
		s->moddata[SecureServ.modnum] = sd;
	}
	return 1;
}

/* @brief We de-allocate the serverdetail struct for the server */

int ss_quit_server(char **av, int ac)
{
	Server *s;
	s = findserver(av[0]);
	if (s) {
			free(s->moddata[SecureServ.modnum]);
	}
	return 1;
}

#endif

EventFnList __module_events[] = {
	{ EVENT_ONLINE, 	Online},
	{ EVENT_SIGNON, 	ScanNick},
	{ EVENT_SIGNOFF, 	DelNick},
	{ EVENT_KILL, 		DelNick},
	{ EVENT_JOINCHAN, 	ss_join_chan},
	{ EVENT_DELCHAN,	ss_del_chan},
	{ EVENT_PARTCHAN,	ss_part_chan},
	{ EVENT_NICKCHANGE, NickChange},
	{ EVENT_KICK,		ss_kick_chan},
	{ EVENT_AWAY, 		ss_user_away},
	{ EVENT_NEWCHAN,	ss_new_chan},
#ifndef NS_FLAGS_NETJOIN
	{ EVENT_SERVER,		ss_new_server},
	{ EVENT_SQUIT,		ss_quit_server},
#endif
	{ NULL, 			NULL}
};

static int DelNick(char **av, int ac) 
{
	User *u;

	SET_SEGV_LOCATION();
	u = finduser(av[0]);
	NickFloodSignOff(av[0]);
	/* u->moddata is free'd in helpers_signoff */
	if(u) {
		HelpersSignoff(u);
	}
	return 1;
}

/* scan nickname changes */
static int NickChange(char **av, int ac) 
{
	User *u;
	
	SET_SEGV_LOCATION();
	if (!SecureServ.isonline) {
		return 1;
	}
	
	u = finduser(av[1]);
	if (!u) {
		nlog(LOG_WARNING, LOG_MOD, "Cant Find user %s", av[1]);
		return 1;
	}
	
	/* Possible memory leak here if a helper changes nick? */
	u->moddata[SecureServ.modnum] = NULL;
	
	if (SS_IsUserExempt(u) > 0) {
		nlog(LOG_DEBUG1, LOG_MOD, "Bye, I'm Exempt %s", u->nick);
		return -1;
	}
	/* is it a nickflood? */
	CheckNickFlood(u);

	/* check the nickname */
	if(ScanUser(u, SCAN_NICK)) {
		return 1;
	}

	return 1;
}

/* scan someone connecting */
static int ScanNick(char **av, int ac) 
{
	User *u;
#ifndef NS_FLAGS_NETJOIN
	ServerDetail *sd;
#endif

	SET_SEGV_LOCATION();
	/* don't do anything if NeoStats hasn't told us we are online yet */
	if (!SecureServ.isonline)
		return 0;
							
	u = finduser(av[0]);
	if (!u) {
		nlog(LOG_WARNING, LOG_MOD, "Ehhh, Can't find user %s", av[0]);
		return -1;
	}
	
	if (SS_IsUserExempt(u) > 0) {
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
#ifndef NS_FLAGS_NETJOIN
	sd = u->server->moddata[SecureServ.modnum];

	if (time(NULL) - u->TS > SecureServ.timedif) {
		if (sd) {
			sd->tsoutcount++;
			if (sd->tsoutcount >= 10) {
				chanalert(s_SecureServ, "Hrm. Is the time on %s correct? There are a lot of Netsplit Nicks", u->server->name);
				globops(s_SecureServ, "Hrm. TS on %s seems to be incorrect. You should fix this ASAP.", u->server->name);
				/* reset so we don't blast all the time */
				sd->tsoutcount = 0;
			}
		}
		nlog(LOG_DEBUG1, LOG_MOD, "Netsplit Nick %s, Not Scanning %d > %d", av[0], (int)(time(NULL) - u->TS), SecureServ.timedif);
		return -1;
	} else {
		if (sd) sd->tsoutcount = 0;
	}
#else
	if (u->flags && NS_FLAGS_NETJOIN)
		return -1;
#endif
	prefmsg(u->nick, s_SecureServ, SecureServ.signonscanmsg);
	privmsg(u->nick, s_SecureServ, "\1VERSION\1");
	return 1;
}

static int check_version_reply(User* u, char **av, int ac) 
{
	char *buf;
	int positive = 0;
	char **av1;
	int ac1 = 0;
	static int versioncount = 0;

	SET_SEGV_LOCATION();
	buf = joinbuf(av, ac, 2);
	/* send a Module_Event, so StatServ can pick up the version info !!! */
	/* nice little side effect isn't it? */

	AddStringToList(&av1, u->nick, &ac1);
	AddStringToList(&av1, buf, &ac1);	
 	ModuleEvent(EVENT_CLIENTVERSION, av1, ac1);
 	free(av1);
 	/* reset segvinmodule */
	SET_SEGV_INMODULE("SecureServ");
	
	if (SecureServ.verbose) {
		chanalert(s_SecureServ, "Got Version Reply from %s: %s", u->nick, buf);
	}
	positive = ScanCTCP(u, buf);
	versioncount++;
	/* why do we only change the version reply every 23 entries? Why not? */
	if ((positive == 0) && (versioncount > 23)) {
		strlcpy(SecureServ.sampleversion, buf, SS_BUF_SIZE);
		versioncount = 0;
	}
	free(buf);
	return 0;
}

static int ss_notice(char *origin, char **av, int ac) 
{
	User* u;

	SET_SEGV_LOCATION();
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
		check_version_reply(u, av, ac);
	}				
	return 0;
}

int __ModInit(int modnum, int apiversion) 
{
	int i;
	
	SET_SEGV_LOCATION();
#ifdef NS_ERR_VERSION /* Forward port version checks */
	/* Check that our compiled version if compatible with the calling version of NeoStats */
	if(	ircstrncasecmp (me.version, NEOSTATS_VERSION, VERSIONSIZE) !=0) {
		return NS_ERR_VERSION;
	}
#endif 
	if (apiversion < REQUIREDAPIVER) {
		nlog(LOG_CRITICAL, LOG_MOD, "Can't Load SecureServ. API Version MisMatch");
		return -1;
	}
	strlcpy(s_SecureServ, "SecureServ", MAXNICK);
	
	SecureServ.isonline = 0;			
	SecureServ.helpcount = 0;
	SecureServ.doUpdate = 0;
	SecureServ.MaxAJPP = 0;
	SecureServ.updateurl[0] = 0;
	SecureServ.monchancycle = 1;
	for (i = 0; i > MAX_PATTERN_TYPES; i++) {
		SecureServ.trigcounts[i] = 0;
		SecureServ.actioncounts[i] = 0;
	}
	SecureServ.MaxAJPPChan[0] = 0;
	SecureServ.modnum = modnum;

	LoadConfig();
	SS_InitExempts();
	InitScanner();
	InitOnJoinBots();
	InitJoinFlood();
	InitNickFlood();

	return 1;
}

void __ModFini() 
{
	SET_SEGV_LOCATION();
	ExitOnJoinBots();
};

static int ss_kick_chan(char **argv, int ac) 
{
	SET_SEGV_LOCATION();
	if(CheckOnjoinBotKick(argv, ac)) {
		return 1;
	}
	/* Can we use this event for anything else e.g. channel takeover checks? */
	return 1;
}
