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
** $Id: SecureServ.c,v 1.15 2003/05/24 06:04:56 fishwaldo Exp $
*/


#include <stdio.h>
#include <fnmatch.h>
#include <pcre.h>
#include "dl.h"
#include "log.h"
#include "stats.h"
#include "conf.h"
#include "SecureServ.h"
#include "http.h"

const char tsversion_date[] = __DATE__;
const char tsversion_time[] = __TIME__;




extern const char *ts_help[];
static int ScanNick(char **av, int ac);
void LoadTSConf();
int check_version_reply(char *origin, char **av, int ac);
void gotpositive(User *u, virientry *ve, int type);
void do_set(User *u, char **av, int ac);
void do_list(User *u);
void do_status(User *u);
void datver(HTTP_Response *response);
void datdownload(HTTP_Response *response);
void load_dat();
int is_exempt(User *u);
static int CheckNick(char **av, int ac);
static void GotHTTPAddress(char *data, adns_answer *a);
static void save_exempts();


Module_Info my_info[] = { {
	"SecureServ",
	"A Trojan Scanning Bot",
	"0.9"
} };


int new_m_version(char *origin, char **av, int ac) {
	snumeric_cmd(351,origin, "Module SecureServ Loaded, Version: %s %s %s",my_info[0].module_version,tsversion_date,tsversion_time);
	return 0;
}

Functions my_fn_list[] = {
	{ MSG_VERSION,	new_m_version,	1 },
#ifdef HAVE_TOKEN_SUP
	{ TOK_VERSION,	new_m_version,	1 },
#endif
	{ MSG_NOTICE,   check_version_reply, 1},
#ifdef HAVE_TOKEN_SUB
	{ TOK_NOTICE,   check_version_reply, 1},
#endif
	{ NULL,		NULL,		0 }
};



int __Bot_Message(char *origin, char **argv, int argc)
{
	User *u;
	char url[255];
	lnode_t *node;
	exemptinfo *exempts = NULL;
	int i;
	char *buf;

	strcpy(segv_location, "TS:Bot_Message");
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
			if (UserLevel(u) >= 40) {
				privmsg_list(u->nick, s_SecureServ, ts_help_oper);
			}
		} else if (argc == 3) {
			if ((!strcasecmp(argv[2], "set")) && (UserLevel(u) >= 185)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_set);
			} else if (!strcasecmp(argv[2], "login")) {
				privmsg_list(u->nick, s_SecureServ, ts_help_login);
			} else if (!strcasecmp(argv[2], "logout")) {
				privmsg_list(u->nick, s_SecureServ, ts_help_logout);
			} else if ((!strcasecmp(argv[2], "list")) && (UserLevel(u) >= 40)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_list);
			} else if ((!strcasecmp(argv[2], "exclude")) && (UserLevel(u) >= 50)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_exclude);
			} else if ((!strcasecmp(argv[2], "checkchan")) && (UserLevel(u) >= 40)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_checkchan);
			} else if ((!strcasecmp(argv[2], "cycle")) && (UserLevel(u) >= 40)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_cycle);
			} else if ((!strcasecmp(argv[2], "update")) && (UserLevel(u) >= 185)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_update);
			} else if ((!strcasecmp(argv[2], "status")) && (UserLevel(u) >= 40)) {
				privmsg_list(u->nick, s_SecureServ, ts_help_status);
			} else {
				prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help for more info", s_SecureServ);
			}
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help for more info", s_SecureServ);
		}
		return 1;
	} else if ((!strcasecmp(argv[1], "login")) || (!strcasecmp(argv[1], "logout"))) {
		prefmsg(u->nick, s_SecureServ, "Hey, this is a Beta version, you dont expect everything to work do you?");
		return 1;		
	} else if (!strcasecmp(argv[1], "list")) {
		if (UserLevel(u) < 40) {
			prefmsg(u->nick, s_SecureServ, "Permission Denied");
			chanalert(s_SecureServ, "%s tried to list, but Permission was denied", u->nick);
			return -1;
		}			
		do_list(u);
		return 1;
	} else if (!strcasecmp(argv[1], "EXCLUDE")) {
		if (UserLevel(u) < 50) {
			prefmsg(u->nick, s_SecureServ, "Access Denied");
			chanalert(s_SecureServ, "%s tried to use exclude, but is not a operator", u->nick);
			return 1;
		}
		if (argc < 3) {
			prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help exclude", s_SecureServ);
			return 0;
		}
		if (!strcasecmp(argv[2], "LIST")) {
			node = list_first(exempt);
			i = 1;
			prefmsg(u->nick, s_SecureServ, "Exception List:");
			while (node) {
				exempts = lnode_get(node);
				switch (exempts->server) {
					case 0:
						strncpy(url, "HostName", 255);
						break;
					case 1:
						strncpy(url, "Server", 255);
						break;
					case 2:
						strncpy(url, "Channel", 255);
						break;
					default:
						strncpy(url, "Unknown", 255);
						break;
				}
				prefmsg(u->nick, s_SecureServ, "%d) %s (%s) Added by %s for %s", i, exempts->host, url, exempts->who, exempts->reason);
				++i;
				node = list_next(exempt, node);
			}
			prefmsg(u->nick, s_SecureServ, "End of List.");
			chanalert(s_SecureServ, "%s requested Exception List", u->nick);
		} else if (!strcasecmp(argv[2], "ADD")) {
			if (argc < 6) {
				prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help exclude", s_SecureServ);
				return 0;
			}
			if (list_isfull(exempt)) {
				prefmsg(u->nick, s_SecureServ, "Error, Exception list is full", s_SecureServ);
				return 0;
			}
			if (atoi(argv[4]) != 2) {
				if (!index(argv[3], '.')) {
					prefmsg(u->nick, s_SecureServ, "Host field does not contain a vaild host"); 
					return 0;
				}
			} else {
				if (!index(argv[3], '#')) {
					prefmsg(u->nick, s_SecureServ, "Channel Field is not valid");
					return 0;
				}
			}
			exempts = malloc(sizeof(exemptinfo));
			snprintf(exempts->host, MAXHOST, "%s", argv[3]);
			exempts->server = atoi(argv[4]);
			snprintf(exempts->who, MAXNICK, "%s", u->nick);
			buf = joinbuf(argv, argc, 5);
			snprintf(exempts->reason, MAXHOST, "%s", buf);
			free(buf);
			node = lnode_create(exempts);
			list_append(exempt, node);
			switch (exempts->server) {
				case 0:
					strncpy(url, "HostName", 255);
					break;
				case 1:
					strncpy(url, "Server", 255);
					break;
				case 2:
					strncpy(url, "Channel", 255);
					break;
				default:
					strncpy(url, "Unknown", 255);
					break;
			}
			prefmsg(u->nick, s_SecureServ, "Added %s (%s) exception to list", exempts->host, url);
			chanalert(s_SecureServ, "%s added %s (%s) exception to list", u->nick, exempts->host, url);
			save_exempts();
			return 1;
		} else if (!strcasecmp(argv[2], "DEL")) {
			if (argc < 3) {
				prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help exclude", s_SecureServ);
				return 0;
			}
			if (atoi(argv[3]) != 0) {
				node = list_first(exempt);
				i = 1;
				while (node) {
					if (i == atoi(argv[3])) {
						/* delete the entry */
						exempts = lnode_get(node);
						list_delete(exempt, node);
						switch (exempts->server) {
							case 0:
								strncpy(url, "HostName", 255);
								break;
							case 1:
								strncpy(url, "Server", 255);
								break;
							case 2:
								strncpy(url, "Channel", 255);
								break;
							default:
								strncpy(url, "Unknown", 255);
								break;
						}
						prefmsg(u->nick, s_SecureServ, "Deleted %s %s out of exception list", exempts->host, url);
						chanalert(s_SecureServ, "%s deleted %s %s out of exception list", u->nick, exempts->host, url);
						free(exempts);
						save_exempts();
						return 1;
					}
					++i;
					node = list_next(exempt, node);
				}		
				/* if we get here, then we can't find the entry */
				prefmsg(u->nick, s_SecureServ, "Error, Can't find entry %d. /msg %s exclude list", atoi(argv[3]), s_SecureServ);
				return 0;
			} else {
				prefmsg(u->nick, s_SecureServ, "Error, Out of Range");
				return 0;
			}
		} else {
			prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help exclude", s_SecureServ);
			return 0;
		}
	} else if (!strcasecmp(argv[1], "checkchan")) {
		if (UserLevel(u) < 40) {
			prefmsg(u->nick, s_SecureServ, "Permission Denied");
			chanalert(s_SecureServ, "%s tried to cycle, but Permission was denied", u->nick);
			return -1;
		}			
		if (argc < 3) {
			prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help checkchan", s_SecureServ);
			return -1;
		}
		CheckChan(u, argv[2]);
		return 1;
	} else if (!strcasecmp(argv[1], "cycle")) {
		if (UserLevel(u) < 40) {
			prefmsg(u->nick, s_SecureServ, "Permission Denied");
			chanalert(s_SecureServ, "%s tried to cycle, but Permission was denied", u->nick);
			return -1;
		}			
		JoinNewChan();
		return 1;
	} else if (!strcasecmp(argv[1], "set")) {
		if (UserLevel(u) < 185) {
			prefmsg(u->nick, s_SecureServ, "Permission is denied", u->nick);
			chanalert(s_SecureServ, "%s tried to use SET, but Permission was denied", u->nick);
			return -1;
		}
		do_set(u, argv, argc);
		return 1;		
	} else if (!strcasecmp(argv[1], "status")) {
		if (UserLevel(u) < 40) {
			prefmsg(u->nick, s_SecureServ, "Permission Denied");
			chanalert(s_SecureServ, "%s tried to list status, but Permission was denied", u->nick);
			return -1;
		}			
		do_status(u);
		return 1;
	
	} else if (!strcasecmp(argv[1], "update")) {
		if (UserLevel(u) < 185) {
			prefmsg(u->nick, s_SecureServ, "Permission Denied");
			chanalert(s_SecureServ, "%s tried to update, but Permission was denied", u->nick);
			return -1;
		}
		snprintf(url, 255, "http://%s%s?u=%s&p=%s", SecureServ.updateurl, DATFILE, SecureServ.updateuname, SecureServ.updatepw);
		http_request(url, 2, HFLAG_NONE, datdownload);
		prefmsg(u->nick, s_SecureServ, "Requesting New Dat File. Please Monitor the Services Channel for Success/Failure");
		chanalert(s_SecureServ, "%s requested a update to the Dat file", u->nick);
	} else {
		prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help", s_SecureServ);
	}
	return 1;
}



void do_set(User *u, char **av, int ac) {
	int i, j;
	char *buf;
	if (ac < 3 ) {
		prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
		return;
	}
	if (!strcasecmp(av[2], "SPLITTIME")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		i = atoi(av[3]);	
		if ((i <= 0) || (i > 1000)) {
			prefmsg(u->nick, s_SecureServ, "Value out of Range.");
			return;
		}
		/* if we get here, all is ok */
		SecureServ.timedif = i;
		prefmsg(u->nick, s_SecureServ, "Signon Split Time is set to %d", i);
		chanalert(s_SecureServ, "%s Set Signon Split Time to %d", u->nick, i);
		SetConf((void *)i, CFGINT, "SplitTime");
		return;
	} else if (!strcasecmp(av[2], "UPDATEINFO")) {
		if (ac < 5) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set", s_SecureServ);
			return;
		}
		SetConf((void *)av[3], CFGSTR, "UpdateUname");
		SetConf((void *)av[4], CFGSTR, "UpdatePassword");
		strncpy(SecureServ.updateuname, av[3], 255);
		strncpy(SecureServ.updatepw, av[4], 255);
		chanalert(s_SecureServ, "%s changed the Update Username and Password", u->nick);
		prefmsg(u->nick, s_SecureServ, "Update Username and Password has been updated to %s and %s", SecureServ.updateuname, SecureServ.updatepw);
		return;
	} else if (!strcasecmp(av[2], "VERSION")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Version Checking is now enabled");
			chanalert(s_SecureServ, "%s has enabled Version Checking");
			SetConf((void *)1, CFGINT, "DoVersionScan");
			SecureServ.doscan = 1;
			return;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Version Checking is now Disabled");
			chanalert(s_SecureServ, "%s has disabled Version Checking");
			SetConf((void *)0, CFGINT, "DoVersionScan");
			SecureServ.doscan = 0;
			return;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
	} else if (!strcasecmp(av[2], "CHECKFIZZER")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Fizzer Virus Checking is now enabled");
			chanalert(s_SecureServ, "%s enabled Fizzer Virus Checking", u->nick);
			SetConf((void *)1, CFGINT, "FizzerCheck");
			SecureServ.dofizzer = 1;
			return;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Fizzer Checking is now disabled");
			chanalert(s_SecureServ, "%s disabled Fizzer Checking", u->nick);
			SetConf((void *)0, CFGINT, "FizzerCheck");
			SecureServ.dofizzer = 0;
			return;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
	} else if (!strcasecmp(av[2], "MULTICHECK")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Complete Version Checking is now enabled");
			chanalert(s_SecureServ, "%s enabled Complete Version Checking", u->nick);
			SetConf((void *)1, CFGINT, "MultiCheck");
			SecureServ.breakorcont = 1;
			return;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Complete Version Checking is now disabled");
			chanalert(s_SecureServ, "%s disabled Complete Version Checking", u->nick);
			SetConf((void *)0, CFGINT, "MultiCheck");
			SecureServ.breakorcont = 0;
			return;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
	} else if (!strcasecmp(av[2], "AKILL")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Akill'ing is now enabled");
			chanalert(s_SecureServ, "%s enabled Akill", u->nick);
			SetConf((void *)1, CFGINT, "DoAkill");
			SecureServ.doakill = 1;
			return;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Akill'ing is now disabled");
			chanalert(s_SecureServ, "%s disabled Akill", u->nick);
			SetConf((void *)0, CFGINT, "DoAkill");
			SecureServ.doakill = 0;
			return;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
	} else if (!strcasecmp(av[2], "AKILLTIME")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		i = atoi(av[3]);	
		if ((i <= 0) || (i > 100000)) {
			prefmsg(u->nick, s_SecureServ, "Value out of Range.");
			return;
		}
		/* if we get here, all is ok */
		SecureServ.akilltime = i;
		prefmsg(u->nick, s_SecureServ, "Akill Time is set to %d Seconds", i);
		chanalert(s_SecureServ, "%s Set Akill Time to %d Seconds", u->nick, i);
		SetConf((void *)i, CFGINT, "AkillTime");
		return;
	} else if (!strcasecmp(av[2], "DOJOIN")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "SVSJOINing is now enabled");
			chanalert(s_SecureServ, "%s enabled SVSJOINing", u->nick);
			SetConf((void *)1, CFGINT, "DoSvsJoin");
			SecureServ.dosvsjoin = 1;
			return;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "SVSJOINing is now disabled");
			chanalert(s_SecureServ, "%s disabled SVSJOINing", u->nick);
			SetConf((void *)0, CFGINT, "DoSvsJoin");
			SecureServ.dosvsjoin = 0;
			return;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
	} else if (!strcasecmp(av[2], "VERBOSE")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Verbose Mode is now enabled");
			chanalert(s_SecureServ, "%s enabled Verbose Mode", u->nick);
			SetConf((void *)1, CFGINT, "Verbose");
			SecureServ.verbose = 1;
			return;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Verbose Mode is now disabled");
			chanalert(s_SecureServ, "%s disabled Verbose Mode", u->nick);
			SetConf((void *)0, CFGINT, "Verbose");
			SecureServ.verbose = 0;
			return;
		}
	} else if (!strcasecmp(av[2], "CYCLETIME")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		i = atoi(av[3]);	
		if ((i <= 0) || (i > 1000)) {
			prefmsg(u->nick, s_SecureServ, "Value out of Range.");
			return;
		}
		/* if we get here, all is ok */
		SecureServ.stayinchantime = i;
		prefmsg(u->nick, s_SecureServ, "Cycle Time is set to %d Seconds (Restart Required)", i);
		chanalert(s_SecureServ, "%s Set Cycle Time to %d Seconds (Restart Required)",u->nick,  i);
		SetConf((void *)i, CFGINT, "CycleTime");
		return;
	} else if (!strcasecmp(av[2], "AUTOUPDATE")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			if ((strlen(SecureServ.updateuname) > 0) && (strlen(SecureServ.updatepw) > 0)) {
				prefmsg(u->nick, s_SecureServ, "AutoUpdate Mode is now enabled");
				chanalert(s_SecureServ, "%s enabled AutoUpdate Mode", u->nick);
				SetConf((void *)1, CFGINT, "AutoUpdate");
				SecureServ.autoupgrade = 1;
				return;
			} else {
				prefmsg(u->nick, s_SecureServ, "You can not enable AutoUpdate, as you have not set a username and password");
				return;
			}
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "AutoUpdate Mode is now disabled");
			chanalert(s_SecureServ, "%s disabled AutoUpdate Mode", u->nick);
			SetConf((void *)0, CFGINT, "AutoUpdate");
			SecureServ.autoupgrade = 0;
			return;
		}
	} else if (!strcasecmp(av[2], "SAMPLETIME")) {
		if (ac < 5) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		i = atoi(av[3]);
		j = atoi(av[4]);	
		if ((i <= 0) || (i > 1000)) {
			prefmsg(u->nick, s_SecureServ, "SampleTime Value out of Range.");
			return;
		}
		if ((j <= 0) || (i > 1000)) {
			prefmsg(u->nick, s_SecureServ, "Threshold Value is out of Range");
			return;
		}
		/* if we get here, all is ok */
		SecureServ.sampletime = i;
		SecureServ.JoinThreshold = j;
		prefmsg(u->nick, s_SecureServ, "Flood Protection is now enabled at %d joins in %d Seconds", j, i);
		chanalert(s_SecureServ, "%s Set Flood Protection to %d joins in %d Seconds", u->nick, j, i);
		SetConf((void *)i, CFGINT, "SampleTime");
		SetConf((void *)j, CFGINT, "JoinThreshold");
		return;
	} else if (!strcasecmp(av[2], "SIGNONMSG")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
		buf = joinbuf(av, ac, 3);			
		strncpy(SecureServ.signonscanmsg, buf, 512);
		prefmsg(u->nick, s_SecureServ, "Signon Message is now set to %s", buf);
		chanalert(s_SecureServ, "%s set the Signon Message to %s", u->nick, buf);
		SetConf((void *)buf, CFGSTR, "SignOnMsg");
		free(buf);
	} else if (!strcasecmp(av[2], "AKILLMSG")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
		buf = joinbuf(av, ac, 3);			
		strncpy(SecureServ.akillinfo, buf, 512);
		prefmsg(u->nick, s_SecureServ, "Akill Message is now set to %s", buf);
		chanalert(s_SecureServ, "%s set the Akill Message to %s", u->nick, buf);
		SetConf((void *)buf, CFGSTR, "AkillMsg");
		free(buf);
	} else if (!strcasecmp(av[2], "NOHELPMSG")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
		buf = joinbuf(av, ac, 3);			
		strncpy(SecureServ.nohelp, buf, 512);
		prefmsg(u->nick, s_SecureServ, "No Help Message is now set to %s", buf);
		chanalert(s_SecureServ, "%s set the No Help Message to %s", u->nick, buf);
		SetConf((void *)buf, CFGSTR, "NoHelpMsg");
		free(buf);
	} else if (!strcasecmp(av[2], "HELPCHAN")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
		if (av[3][0] != '#') {
			prefmsg(u->nick, s_SecureServ, "Invalid Channel %s", av[3]);
			return;
		}
		strncpy(SecureServ.HelpChan, av[3], CHANLEN);
		prefmsg(u->nick, s_SecureServ, "Help Channel is now set to %s", av[3]);
		chanalert(s_SecureServ, "%s set the Help Channel to %s", u->nick, av[3]);
		SetConf((void *)av[3], CFGSTR, "HelpChan");
	} else if (!strcasecmp(av[2], "LIST")) {
		prefmsg(u->nick, s_SecureServ, "Current SecureServ Settings:");
		prefmsg(u->nick, s_SecureServ, "SplitTime: %d", SecureServ.timedif);
		prefmsg(u->nick, s_SecureServ, "Version Checking: %s", SecureServ.doscan ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "Multi Checking: %s", SecureServ.breakorcont ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "Akill Action: %s", SecureServ.doakill ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "Akill Time: %d", SecureServ.akilltime);
		prefmsg(u->nick, s_SecureServ, "Join Action: %s", SecureServ.dosvsjoin ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "Verbose Reporting: %s", SecureServ.verbose ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "Cycle Time: %d", SecureServ.stayinchantime);
		prefmsg(u->nick, s_SecureServ, "Update Username and Passware are: %s", strlen(SecureServ.updateuname) > 0 ? "Set" : "Not Set");
		if (UserLevel(u) > 185) 
			prefmsg(u->nick, s_SecureServ, "Update Username is %s, Password is %s", SecureServ.updateuname, SecureServ.updatepw);
		prefmsg(u->nick, s_SecureServ, "AutoUpdate: %s", SecureServ.autoupgrade ? "Enabled" : "Disabled");
		prefmsg(u->nick, s_SecureServ, "Sample Threshold: %d/%d Seconds", SecureServ.JoinThreshold, SecureServ.sampletime);
		prefmsg(u->nick, s_SecureServ, "Signon Message: %s", SecureServ.signonscanmsg);
		prefmsg(u->nick, s_SecureServ, "Akill Information Message: %s", SecureServ.akillinfo);
		prefmsg(u->nick, s_SecureServ, "No Help Available Message: %s", SecureServ.nohelp);
		prefmsg(u->nick, s_SecureServ, "Virus Help Channel: %s", SecureServ.HelpChan);
		prefmsg(u->nick, s_SecureServ, "End Of List");
		return;
	} else {
		prefmsg(u->nick, s_SecureServ, "Unknown Set option %s. try /msg %s help set", av[2], s_SecureServ);
		return;
	}		


}
void do_status(User *u) {
	
	prefmsg(u->nick, s_SecureServ, "SecureServ Status:");
	prefmsg(u->nick, s_SecureServ, "==================");
	prefmsg(u->nick, s_SecureServ, "Virus Patterns Loaded: %d", list_count(viri));
	prefmsg(u->nick, s_SecureServ, "CTCP Version Messages Scanned: %d", SecureServ.trigcounts[DET_CTCP]);
	prefmsg(u->nick, s_SecureServ, "CTCP Messages Acted On: %d", SecureServ.actioncounts[DET_CTCP]);
	prefmsg(u->nick, s_SecureServ, "CTCP Definitions: %d", SecureServ.definitions[DET_CTCP]);
	prefmsg(u->nick, s_SecureServ, "Private Messages Recieved: %d", SecureServ.trigcounts[DET_MSG]);
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
	
}


void do_list(User *u) {
	lnode_t *node;
	virientry *ve;
	char type[MAXHOST];
	char action[MAXHOST];
	int i;

	i = 0;
	node = list_first(viri);
	prefmsg(u->nick, s_SecureServ, "Virus List:");
	prefmsg(u->nick, s_SecureServ, "===========");
	do {
		ve = lnode_get(node);
		i++;
		switch (ve->dettype) {
			case DET_CTCP:
				snprintf(type, MAXHOST, "Version");
				break;
			case DET_MSG:
				snprintf(type, MAXHOST, "PM");
				break;
			case DET_NICK:
				snprintf(type, MAXHOST, "Nick");
				break;
			case DET_IDENT:
				snprintf(type, MAXHOST, "Ident");
				break;
			case DET_REALNAME:
				snprintf(type, MAXHOST, "RealName");
				break;
			case DET_CHAN:
				snprintf(type, MAXHOST, "Chan");
				break;
			case DET_BUILTIN:
				snprintf(type, MAXHOST, "Built-In");
				break;
			default:
				snprintf(type, MAXHOST, "Unknown(%d)", ve->dettype);
		}
		switch (ve->action) {
			case ACT_SVSJOIN:
				snprintf(action, MAXHOST, "SVSjoin");
				break;
			case ACT_AKILL:
				snprintf(action, MAXHOST, "Akill");
				break;
			case ACT_WARN:
				snprintf(action, MAXHOST, "OpersWarn");
				break;
			default:
				snprintf(action, MAXHOST, "ClientWarn");
		}
		prefmsg(u->nick, s_SecureServ, "%d) Virus: %s. Detection: %s. Action: %s Hits: %d", i, ve->name, type, action, ve->nofound);
	} while ((node = list_next(viri, node)) != NULL);
	prefmsg(u->nick, s_SecureServ, "End of List.");
}

int Online(char **av, int ac) {

	strcpy(segv_location, "TS:Online");
	if (init_bot(s_SecureServ,"ts",me.name,"Trojan Scanning Bot", "+S", my_info[0].module_name) == -1 ) {
		/* Nick was in use!!!! */
		s_SecureServ = strcat(s_SecureServ, "_");
		init_bot(s_SecureServ,"ts",me.name,"Trojan Scanning Bot", "+S", my_info[0].module_name);
	}
	LoadTSConf();
	chanalert(s_SecureServ, "%d Trojans Patterns loaded", list_count(viri));
	srand(hash_count(ch));
	/* kick of the autojoin timer */
	add_mod_timer("JoinNewChan", "RandomJoinChannel", my_info[0].module_name, SecureServ.stayinchantime);


	dns_lookup(HTTPHOST,  adns_r_a, GotHTTPAddress, "SecureServ Update Server");

	return 1;
};
void save_exempts() {
	lnode_t *node;
	exemptinfo *exempts = NULL;
	char path[255];
	int i;

	node = list_first(exempt);
	i = 1;
	while (node) {
		exempts = lnode_get(node);
		nlog(LOG_DEBUG1, LOG_MOD, "Saving Exempt List %s", exempts->host);
		snprintf(path, 255, "Exempt/%s/Who", exempts->host);
		SetConf((void *)exempts->who, CFGSTR, path);
		snprintf(path, 255, "Exempt/%s/Reason", exempts->host);
		SetConf((void *)exempts->reason, CFGSTR, path);
		snprintf(path, 255, "Exempt/%s/Server", exempts->host);
		SetConf((void *)exempts->server, CFGINT, path);
		node = list_next(exempt, node);
	}
}



void LoadTSConf() {
	lnode_t *node;
	exemptinfo *exempts = NULL;
	randomnicks *rnicks;
	char **data;
	int i;
	char *tmp;
	char datapath[MAXHOST];
	strcpy(segv_location, "TS:loadTSConf");

	
	if(GetConf((void *)&SecureServ.doscan, CFGINT, "DoVersionScan") <= 0) {
		/* not configured, don't scan */
		SecureServ.doscan = 0;
	} 
	if (GetConf((void *)&SecureServ.timedif, CFGINT, "SplitTime") <= 0) {
		/* use Default */
		SecureServ.timedif = 300;
	}
	if (GetConf((void *)&SecureServ.verbose, CFGINT, "Verbose") <= 0){
		/* yes */
		SecureServ.verbose = 1;
	}
	if (GetConf((void *)&SecureServ.stayinchantime, CFGINT, "CycleTime") <= 0) {
		/* 60 seconds */
		SecureServ.stayinchantime = 60;
	}
	if (GetConf((void *)&SecureServ.autoupgrade, CFGINT, "AutoUpdate") <= 0) {
		/* disable autoupgrade is the default */
		SecureServ.autoupgrade = 0;
	}
	if (GetConf((void *)&tmp, CFGSTR, "UpdateUname") <= 0) {
		/* disable autoupgrade if its set */
		SecureServ.autoupgrade = 0;
	} else {
		strncpy(SecureServ.updateuname, tmp, 255);
		free(tmp);
	}
	if (GetConf((void *)&tmp, CFGSTR, "UpdatePassword") <= 0) {
		/* disable autoupgrade if its set */
		SecureServ.autoupgrade = 0;
	} else {
		strncpy(SecureServ.updatepw, tmp, 255);
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
	if (GetConf((void *)&SecureServ.signonscanmsg, CFGSTR, "SignOnMsg") <= 0) {
		snprintf(SecureServ.signonscanmsg, 512, "Your IRC client is being checked for Trojans. Please dis-regard VERSION messages from %s", s_SecureServ);
	}
	if (GetConf((void *)&SecureServ.nohelp, CFGSTR, "NoHelpMsg") <= 0) {
		snprintf(SecureServ.nohelp, 512, "No Helpers are online at the moment, so you have been Akilled from this network. Please visit http://www.nohack.org for Trojan/Virus Info");
	}
	if (GetConf((void *)&SecureServ.akillinfo, CFGSTR, "AkillMsg") <= 0) {
		snprintf(SecureServ.akillinfo, 512, "You have been Akilled from this network. Please get a virus scanner and check your PC");
	}
	if (GetConf((void *)&SecureServ.HelpChan, CFGSTR, "HelpChan") <= 0) {
		snprintf(SecureServ.HelpChan, CHANLEN, "#nohack");
	}
	
	if (GetDir("Exempt", &data) > 0) {
		/* try */
		for (i = 0; data[i] != NULL; i++) {
			exempts = malloc(sizeof(exemptinfo));
			strncpy(exempts->host, data[i], MAXHOST);
	
			snprintf(datapath, MAXHOST, "Exempt/%s/Who", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, datapath) <= 0) {
				free(exempts);
				continue;
			} else {
				strncpy(exempts->who, tmp, MAXNICK);
				free(tmp);
			}
			snprintf(datapath, MAXHOST, "Exempt/%s/Reason", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, datapath) <= 0) {
				free(exempts);
				continue;
			} else {
				strncpy(exempts->reason, tmp, MAXHOST);
				free(tmp);
			}
			snprintf(datapath, MAXHOST, "Exempt/%s/Server", data[i]);
			if (GetConf((void *)&exempts->server, CFGINT, datapath) <= 0) {
				free(exempts);
				continue;
			}			
			nlog(LOG_DEBUG2, LOG_MOD, "Adding %s (%d) Set by %s for %s to Exempt List", exempts->host, exempts->server, exempts->who, exempts->reason);
			node = lnode_create(exempts);
			list_prepend(exempt, node);			
		}
	}
	free(data);
	/* get Random Nicknames */
	if (GetDir("RandomNicks", &data) > 0) {
		/* try */
		for (i = 0; data[i] != NULL; i++) {
			rnicks = malloc(sizeof(randomnicks));
			strncpy(rnicks->nick, data[i], MAXNICK);
	
			snprintf(datapath, MAXHOST, "RandomNicks/%s/User", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, datapath) <= 0) {
				free(rnicks);
				continue;
			} else {
				strncpy(rnicks->user, tmp, MAXUSER);
				free(tmp);
			}
			snprintf(datapath, MAXHOST, "RandomNicks/%s/Host", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, datapath) <= 0) {
				free(rnicks);
				continue;
			} else {
				strncpy(rnicks->host, tmp, MAXHOST);
				free(tmp);
			}
			snprintf(datapath, MAXHOST, "RandomNicks/%s/RealName", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, datapath) <= 0) {
				free(exempts);
				continue;
			} else {
				strncpy(rnicks->rname, tmp, MAXHOST);
				free(tmp);
			}			
			nlog(LOG_DEBUG2, LOG_MOD, "Adding Random Nick %s!%s@%s with RealName %s", rnicks->nick, rnicks->user, rnicks->host, rnicks->rname);
			node = lnode_create(rnicks);
			list_prepend(nicks, node);			
		}
	}
	free(data);
	load_dat();
	SecureServ.inited = 1;

}

void load_dat() {
	FILE *fp;
	char buf[512];
	virientry *viridet;
	lnode_t *node;
	const char *error;
	int errofset;
	pcre *re;
	int rc;
	int ovector[24];
	const char **subs;
	/* if the list isn't empty, make it empty */
	if (!list_isempty(viri)) {
		node = list_first(viri);
		do {
			viridet = lnode_get(node);
			nlog(LOG_DEBUG1, LOG_MOD, "Deleting %s out of List", viridet->name);
#if 0
			list_delete(viri, node);
			lnode_destroy(node);
#endif
			free(viridet);
		} while ((node = list_next(viri, node)) != NULL);
		list_destroy_nodes(viri);
	}
	
	for (rc = 0; rc > 20; rc++) {
		SecureServ.definitions[rc] = 0;
	}	

	/* first, add the dat for Fizzer (even if its not enabled!) */
	viridet = malloc(sizeof(virientry));
	snprintf(viridet->name, MAXHOST, "FizzerBot");
	viridet->dettype = DET_BUILTIN;
	viridet->var1 = 0;
	viridet->var2 = 0;
	snprintf(viridet->recvmsg, MAXHOST, "UserName is RealName Reversed");
	snprintf(viridet->sendmsg, MAXHOST, "Your Infected with the Fizzer Virus");
	viridet->action = ACT_AKILL;
	viridet->nofound = 0;
	SecureServ.definitions[DET_BUILTIN]++;
	node = lnode_create(viridet);
	list_prepend(viri, node);
	nlog(LOG_DEBUG1, LOG_MOD, "loaded %s (Detection %d, with %s, send %s and do %d", viridet->name, viridet->dettype, viridet->recvmsg, viridet->sendmsg, viridet->action);
	
	
	fp = fopen("data/viri.dat", "r");
	if (!fp) {
		nlog(LOG_WARNING, LOG_MOD, "TS: Error, No viri.dat file found. %s is disabled", s_SecureServ);
		chanalert(s_SecureServ, "Error not viri.dat file found, %s is disabled", s_SecureServ);
		return;
	} else {
		re = pcre_compile("^([a-zA-Z0-9]*) ([0-9]*) ([0-9]*) ([0-9]*) \"(.*)\" \"(.*)\" ([0-9]*).*" , 0, &error, &errofset, NULL);
		if (re == NULL) {
			nlog(LOG_CRITICAL, LOG_MOD, "PCRE_COMPILE of dat file format failed bigtime! %s at %d", error, errofset);		
			return;
		}
		/* first fgets always returns the version number */
		fgets(buf, 512, fp);
		SecureServ.viriversion = atoi(buf);
		while (fgets(buf, 512, fp)) {
			if (list_isfull(viri))
				break;
			viridet = malloc(sizeof(virientry));
			rc = pcre_exec(re, NULL, buf, strlen(buf), 0, 0, ovector, 24);
			if (rc <= 0) {
				nlog(LOG_WARNING, LOG_MOD, "PCRE_EXEC didn't have enough space!");
				free(viridet);
				continue;
			} else if (rc != 8) {
				nlog(LOG_WARNING, LOG_MOD, "Didn't get required number of Subs (%d)", rc);
				continue;
			}
			
			pcre_get_substring_list(buf, ovector, rc, &subs);		
			snprintf(viridet->name, MAXHOST, "%s", subs[1]);
			viridet->dettype = atoi(subs[2]);
			viridet->var1 = atoi(subs[3]);
			viridet->var2 = atoi(subs[4]);
			snprintf(viridet->recvmsg, MAXHOST, "%s", subs[5]);
			snprintf(viridet->sendmsg, MAXHOST, "%s", subs[6]);
			viridet->action = atoi(subs[7]);
			viridet->nofound = 0;
			viridet->pattern = pcre_compile(viridet->recvmsg, 0, &error, &errofset, NULL);
			if (viridet->pattern == NULL) {
				/* it failed for some reason */
				nlog(LOG_WARNING, LOG_MOD, "Regular Expression Compile of %s Failed: %s at %d", viridet->name, error, errofset);
				free(subs);
				free(viridet);
				continue;
			}	
			viridet->patternextra = pcre_study(viridet->pattern, 0, &error);
			if (error != NULL) {
				nlog(LOG_WARNING, LOG_MOD, "Regular Expression Study for %s failed: %s", viridet->name, error);
				/* don't exit */
			}
			SecureServ.definitions[viridet->dettype]++;
			node = lnode_create(viridet);
			list_prepend(viri, node);
			nlog(LOG_DEBUG1, LOG_MOD, "loaded %s (Detection %d, with %s, send %s and do %d", viridet->name, viridet->dettype, viridet->recvmsg, viridet->sendmsg, viridet->action);
			free(subs);
		}
	}

	
}


EventFnList my_event_list[] = {
	{ "ONLINE", 	Online},
	{ "SIGNON", 	ScanNick},
	{ "NEWCHAN",	ss_new_chan},
	{ "JOINCHAN", 	ss_join_chan},
	{ "DELCHAN",	ss_del_chan},
	{ "NICK_CHANGE", CheckNick},
	{ NULL, 	NULL}
};



Module_Info *__module_get_info() {
	return my_info;
};

Functions *__module_get_functions() {
	return my_fn_list;
};

EventFnList *__module_get_events() {
	return my_event_list;
};

int is_exempt(User *u) {
	lnode_t *node;
	exemptinfo *exempts;

	if (!strcasecmp(u->server->name, me.name)) {
		nlog(LOG_DEBUG1, LOG_MOD, "SecureServ: User %s Exempt. its Me!", u->nick);
		return 1;
	}

	/* don't scan users from a server that is excluded */
	node = list_first(exempt);
	while (node) {
		exempts = lnode_get(node);
		if (exempts->server == 1) {
			/* match a server */
			if (fnmatch(exempts->host, u->server->name, 0) == 0) {
				nlog(LOG_DEBUG1, LOG_MOD, "TS: User %s exempt. Matched server entry %s in Exemptions", u->nick, exempts->host);
				return 1;
			}
		} else if (exempts->server == 0) {
			/* match a hostname */
			if (fnmatch(exempts->host, u->hostname, 0) == 0) {
				nlog(LOG_DEBUG1, LOG_MOD, "SecureServ: User %s is exempt. Matched Host Entry %s in Exceptions", u->nick, exempts->host);
				return 1;
			}
		}				
		node = list_next(exempt, node);
	}
	return -1;
}
int Chan_Exempt(Chans *c) {

	lnode_t *node;
	exemptinfo *exempts;

	
	if (!strcasecmp(c->name, me.chan)) {
		nlog(LOG_DEBUG1, LOG_MOD, "SecureServ: Channel %s Exempt. its Mine!", c->name);
		return 1;
	}

	/* don't scan users from a server that is excluded */
	node = list_first(exempt);
	while (node) {
		exempts = lnode_get(node);
		if (exempts->server == 2) {
			/* match a channel */
			if (fnmatch(exempts->host, c->name, 0) == 0) {
				nlog(LOG_DEBUG1, LOG_MOD, "SecureServ: Channel %s exempt. Matched Channel entry %s in Exemptions", c->name, exempts->host);
				return 1;
			}
		}				
		node = list_next(exempt, node);
	}
	return -1;
}
/* scan nickname changes */
static int CheckNick(char **av, int ac) {
	User *u;
	lnode_t *node;
	virientry *viridetails;
	int rc;

	u = finduser(av[1]);
	if (!u) {
		nlog(LOG_WARNING, LOG_MOD, "Cant Find user %s", av[1]);
		return 1;
	}
	if (is_exempt(u) > 0) {
		nlog(LOG_DEBUG1, LOG_MOD, "Bye, I'm Exempt %s", u->nick);
		return -1;
	}

	/* check the nickname, ident, realname */
	node = list_first(viri);
	do {
		viridetails = lnode_get(node);
		if (viridetails->dettype == DET_NICK) {
			SecureServ.trigcounts[DET_NICK]++;
			nlog(LOG_DEBUG1, LOG_MOD, "TS: Checking Nick %s against %s", u->nick, viridetails->recvmsg);
			rc = pcre_exec(viridetails->pattern, viridetails->patternextra, u->nick, strlen(u->nick), 0, 0, NULL, 0);
			if (rc < -1) {
				nlog(LOG_WARNING, LOG_MOD, "PatternMatch Nick Failed: (%d)", rc);
				continue;
			}
			if (rc > -1) {					
				gotpositive(u, viridetails, DET_NICK);
				if (SecureServ.breakorcont == 0)
					continue;
				else 
					return 1;
			}
		} 
	} while ((node = list_next(viri, node)) != NULL);
	return -1;
}

/* scan someone connecting */
static int ScanNick(char **av, int ac) {
	User *u;
	lnode_t *node;
	virientry *viridetails;
	char username[11];
	char *s1, *s2, *user;
	int rc;

	strcpy(segv_location, "TS:ScanNick");
	/* don't do anything if NeoStats hasn't told us we are online yet */
	if (!SecureServ.inited)
		return 0;
							
	u = finduser(av[0]);
	if (!u) {
		nlog(LOG_WARNING, LOG_MOD, "TS: Ehhh, Can't find user %s", av[0]);
		return -1;
	}
	
	if (is_exempt(u) > 0) {
		return -1;
	}

	/* fizzer requires realname info, which we don't store yet. */
	if (SecureServ.dofizzer == 1) {
		user = malloc(MAXREALNAME);
		strncpy(user, u->realname, MAXREALNAME);
		s1 = strtok(user, " ");
		s2 = strtok(NULL, "");
		snprintf(username, 11, "%s%s%s", u->username[0] == '~' ? "~" : "",  s2, s1);
		free(user);
		nlog(LOG_DEBUG2, LOG_MOD, "Fizzer RealName Check %s -> %s", username, u->username);
		SecureServ.trigcounts[DET_BUILTIN]++;
		if (!strcmp(username, u->username)) {
			nlog(LOG_NOTICE, LOG_MOD, "Fizzer Bot Detected: %s (%s -> %s)", u->nick, u->username, u->realname);
			/* do kill */
			node = list_first(viri);
			do {
				viridetails = lnode_get(node);
				if (!strcasecmp(viridetails->name, "FizzerBot")) {
					gotpositive(u, viridetails, DET_BUILTIN);
					return 1;
				}
			} while ((node = list_next(viri, node)) != NULL);
			return 1;
		}
	}							
	/* check the nickname, ident, realname */
	node = list_first(viri);
	do {
		viridetails = lnode_get(node);
		if (viridetails->dettype == DET_NICK) {
			SecureServ.trigcounts[DET_NICK]++;
			nlog(LOG_DEBUG1, LOG_MOD, "TS: Checking Nick %s against %s", u->nick, viridetails->recvmsg);
			rc = pcre_exec(viridetails->pattern, viridetails->patternextra, u->nick, strlen(u->nick), 0, 0, NULL, 0);
			if (rc < -1) {
				nlog(LOG_WARNING, LOG_MOD, "PatternMatch Nick Failed: (%d)", rc);
				continue;
			}
			if (rc > -1) {					
				gotpositive(u, viridetails, DET_NICK);
				if (SecureServ.breakorcont == 0)
					continue;
				else 
					return 1;
			}
		} else if (viridetails->dettype == DET_IDENT) {
			SecureServ.trigcounts[DET_IDENT]++;
			nlog(LOG_DEBUG1, LOG_MOD, "TS: Checking ident %s against %s", u->username, viridetails->recvmsg);
			rc = pcre_exec(viridetails->pattern, viridetails->patternextra, u->username, strlen(u->username), 0, 0, NULL, 0);
			if (rc < -1) {
				nlog(LOG_WARNING, LOG_MOD, "PatternMatch UserName Failed: (%d)", rc);
				continue;
			}
			if (rc > -1) {					
				gotpositive(u, viridetails, DET_IDENT);
				if (SecureServ.breakorcont == 0)
					continue;
				else 
					return 1;
			}
		} else if (viridetails->dettype == DET_REALNAME) {
			SecureServ.trigcounts[DET_REALNAME]++;
			nlog(LOG_DEBUG1, LOG_MOD, "TS: Checking Realname %s against %s", u->realname, viridetails->recvmsg);
			rc = pcre_exec(viridetails->pattern, viridetails->patternextra, u->realname, strlen(u->realname), 0, 0, NULL, 0);
			if (rc < -1) {
				nlog(LOG_WARNING, LOG_MOD, "PatternMatch RealName Failed: (%d)", rc);
				continue;
			}
			if (rc > -1) {					
				gotpositive(u, viridetails, DET_REALNAME);
				if (SecureServ.breakorcont == 0)
					continue;
				else 
					return 1;
			}
		}
	} while ((node = list_next(viri, node)) != NULL);



	if (time(NULL) - u->TS > SecureServ.timedif) {
		nlog(LOG_DEBUG1, LOG_MOD, "Netsplit Nick %s, Not Scanning", av[0]);
		return -1;
	}
	prefmsg(u->nick, s_SecureServ, SecureServ.signonscanmsg);
	privmsg(u->nick, s_SecureServ, "\1VERSION\1");
	return 1;
}

int check_version_reply(char *origin, char **av, int ac) {
	char *buf;
	lnode_t *node;
	virientry *viridetails;
	int rc;
	char **av1;
	int ac1 = 0;
	
	/* if its not a ctcp message, forget it */
	if (av[1][0] != '\1') 
		return 0;
	
	if (!strcasecmp(av[1], "\1version")) {
		buf = joinbuf(av, ac, 2);
		/* send a Module_Event, so StatServ can pick up the version info !!! */
		/* nice little side effect isn't it? */
	
		AddStringToList(&av1, origin, &ac1);
		AddStringToList(&av1, buf, &ac1);	
 		Module_Event("CLIENTVERSION", av1, ac1);
 		free(av1);
 		/* reset segvinmodule */
 		strcpy(segvinmodule, "SecureServ");
		
		if (SecureServ.verbose) chanalert(s_SecureServ, "Got Version Reply from %s: %s", origin, buf);
		node = list_first(viri);
		do {
			viridetails = lnode_get(node);
			if ((viridetails->dettype == DET_CTCP) || (viridetails->dettype > 20)) {
				SecureServ.trigcounts[DET_CTCP]++;
				nlog(LOG_DEBUG1, LOG_MOD, "TS: Checking Version %s against %s", buf, viridetails->recvmsg);
				rc = pcre_exec(viridetails->pattern, viridetails->patternextra, buf, strlen(buf), 0, 0, NULL, 0);
				if (rc < -1) {
					nlog(LOG_WARNING, LOG_MOD, "PatternMatch CTCP Version Failed: (%d)", rc);
					continue;
				}
				if (rc > -1) {					
					gotpositive(finduser(origin), viridetails, DET_CTCP);
					if (SecureServ.breakorcont == 0)
						continue;
					else 
						break;
				}
		
			}
		} while ((node = list_next(viri, node)) != NULL);
		free(buf);
	}				
	return 0;
}


void gotpositive(User *u, virientry *ve, int type) {

	prefmsg(u->nick, s_SecureServ, "%s has detected that your client is a Trojan/Infected IRC client/Vulnerble Script called %s", s_SecureServ, ve->name);
	prefmsg(u->nick, s_SecureServ, ve->sendmsg);
	prefmsg(u->nick, s_SecureServ, "For More Information Please Visit http://secure.irc-chat.net/info.php?viri=%s", ve->name);
	ve->nofound++;
	SecureServ.actioncounts[type]++;
	switch (ve->action) {
		case ACT_AKILL:
			if (SecureServ.doakill > 0) {
				prefmsg(u->nick, s_SecureServ, SecureServ.akillinfo);
				chanalert(s_SecureServ, "Akilling %s for Virus %s", u->nick, ve->name);
				sakill_cmd(u->hostname, u->username, s_SecureServ, SecureServ.akilltime, "SecureServ: %s", ve->name);
				break;
			}
		case ACT_SVSJOIN:
			if (SecureServ.dosvsjoin > 0) {
				if (SecureServ.helpcount > 0) {		
					chanalert(s_SecureServ, "SVSJoining %s Nick to avchan for Virus %s", u->nick, ve->name);
					ssvsjoin_cmd(u->nick, SecureServ.HelpChan);
					break;
				} else {
					prefmsg(u->nick, s_SecureServ, SecureServ.nohelp);
					chanalert(s_SecureServ, "Akilling %s for Virus %s (No Helpers Logged in)", u->nick, ve->name);
					globops(s_SecureServ, "Akilling %s for Virus %s (No Helpers Logged in)", u->nick, ve->name);
					sakill_cmd(u->hostname, u->username, s_SecureServ, SecureServ.akilltime, "SecureServ(SVSJOIN): %s", ve->name);
					break;
				}
			}
		case ACT_WARN:
			chanalert(s_SecureServ, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken", u->nick, ve->name);
			globops(s_SecureServ, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken", u->nick, ve->name);
			break;
		case ACT_NOTHING:
			if (SecureServ.verbose) chanalert(s_SecureServ, "SecureServ warned %s about %s Bot/Trojan/Virus", u->nick, ve->name);
			break;
	}
}



void _init() {
	int i;
	s_SecureServ = "SecureServ";
	strcpy(segvinmodule, "SecureServ");
	/* init the exemptions list */
	exempt = list_create(MAX_EXEMPTS);
	/* init the virus lists */
	viri = list_create(MAX_VIRI);
	/* init the random nicks list */
	nicks = list_create(MAX_NICKS);
	/* init the channel tracking hash */
	ss_init_chan_hash();
	
	/* set some defaults */
	SecureServ.inited = 0;			
	SecureServ.timedif = 300;	
	SecureServ.doscan = 1;
	snprintf(SecureServ.signonscanmsg, 512, "Your IRC client is being checked for Trojans. Please dis-regard VERSION messages from %s", s_SecureServ);
	snprintf(SecureServ.akillinfo, 512, "You have been Akilled from this network. Please get a virus scanner and check your PC");
	snprintf(SecureServ.nohelp, 512, "No Helpers are online at the moment, so you have been Akilled from this network. Please visit http://www.nohack.org for Trojan/Virus Info");
	snprintf(SecureServ.HelpChan, CHANLEN, "#nohack");
	SecureServ.breakorcont = 1;
	SecureServ.doakill = 1;
	SecureServ.dosvsjoin = 1;
	SecureServ.helpcount = 0;
	SecureServ.akilltime = 3600;
	SecureServ.sampletime = 5;
	SecureServ.JoinThreshold = 5;
	SecureServ.autoupgrade = 0;	
	SecureServ.doUpdate = 0;
	SecureServ.dofizzer = 1;
	SecureServ.MaxAJPP = 0;
	strncpy(SecureServ.updateurl, "", 255);
	strncpy(SecureServ.updateuname, "", 255);
	strncpy(SecureServ.updatepw, "", 255);
	for (i = 0; i > 20; i++) {
		SecureServ.trigcounts[i] = 0;
		SecureServ.actioncounts[i] = 0;
	}
	strncpy(SecureServ.MaxAJPPChan, "", CHANLEN);
}

/* @brief this is the automatic dat file updater callback function. Checks whats on the website with 
** whats local, and if website is higher, either prompts for a upgrade, or does a automatic one :)
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
			chanalert(s_SecureServ, "Permission Denied when trying to check Dat File Version:", myversion);
			return;
		}			
		nlog(LOG_DEBUG1, LOG_MOD, "LocalDat Version %d, WebSite %d", SecureServ.viriversion, myversion);
		if (myversion > SecureServ.viriversion) {
			if (SecureServ.autoupgrade > 0) {
				SecureServ.doUpdate = 1;
				add_mod_timer("DownLoadDat", "DownLoadNewDat", my_info[0].module_name, 1);
			 } else
				chanalert(s_SecureServ, "A new DatFile Version %d is available. You should /msg %s update", myversion, s_SecureServ);
		}
	} else {
		nlog(LOG_DEBUG1, LOG_MOD, "Virus Definition check Failed. %s", response->szHCode);
		return;
	}
}
void DownLoadDat() {
	char url[255];
	/* dont keep trying to download !*/
	if (SecureServ.doUpdate == 1) {
		del_mod_timer("DownLoadNewDat");
		SecureServ.doUpdate = 2;
		snprintf(url, 255, "http://%s%s?u=%s&p=%s", SecureServ.updateurl, DATFILE, SecureServ.updateuname, SecureServ.updatepw);
		http_request(url, 2, HFLAG_NONE, datdownload);
	} 
	return;
}


/* @brief this downloads a dat file and loads the new version into memory if required 
*/

void datdownload(HTTP_Response *response) {
	char tmpname[255];
	char *tmp, *tmp1;
	int i;
	
	/* if this is a automatic download, KILL the timer */
	if (SecureServ.doUpdate == 2) {
		/* clear this flag */
		SecureServ.doUpdate = 0;
	}
	if ((response->iError > 0) && (!strcasecmp(response->szHCode, "200"))) {

		/* check response code */
		tmp = malloc(response->lSize);
		strncpy(tmp, response->pData, response->lSize);
		tmp1 = tmp;
		i = atoi(strtok(tmp, "\n"));
		free(tmp1);	
		if (i <= 0) {
			nlog(LOG_NORMAL, LOG_MOD, "When Trying to Download Dat File, we got Permission Denied: %d", i);
			chanalert(s_SecureServ, "Permission Denied when trying to Download Dat File : %d", i);
			return;
		}			
		
	
		/* make a temp file and write the contents to it */
		snprintf(tmpname, 255, "viriXXXXXX");
		i = mkstemp(tmpname);
		write(i, response->pData, response->lSize);
		close(i);
		/* rename the file to the datfile */
		rename(tmpname, "data/viri.dat");
		/* reload the dat file */
		load_dat();
		nlog(LOG_NOTICE, LOG_MOD, "Successfully Downloaded DatFile Version %d", SecureServ.viriversion);
		chanalert(s_SecureServ, "DatFile Version %d has been downloaded and installed", SecureServ.viriversion);
	} else {
		nlog(LOG_DEBUG1, LOG_MOD, "Virus Definition Download Failed. %s", response->szHCode);
		return;
	}
	
}
	
		
void _fini() {

};


static void GotHTTPAddress(char *data, adns_answer *a) {
        char *show;
        int i, len, ri;
	char url[255];
	char url2[255];                

	adns_rr_info(a->type, 0, 0, &len, 0, 0);
        for(i = 0; i < a->nrrs;  i++) {
        	ri = adns_rr_info(a->type, 0, 0, 0, a->rrs.bytes +i*len, &show);
                if (!ri) {
			/* ok, we got a valid answer, lets maybe kick of the update check.*/
			snprintf(url, 255, "%s", show);
			strncpy(SecureServ.updateurl, url, 255);
			nlog(LOG_NORMAL, LOG_MOD, "Got DNS for Update Server: %s", url);
			if ((strlen(SecureServ.updateuname) > 0) && strlen(SecureServ.updatepw) > 0) {
				snprintf(url2, 255, "http://%s%s?u=%s&p=%s", url, DATFILEVER, SecureServ.updateuname, SecureServ.updatepw);
				http_request(url2, 2, HFLAG_NONE, datver); 
			} else {
				chanalert(s_SecureServ, "No Valid Username/Password configured for update Checking. Aborting Update Check");
			}
                } else {
	                chanalert(s_SecureServ, "DNS error Checking for Updates: %s", adns_strerror(ri));
	        }
	        free(show);
	}
	if (a->nrrs < 1) {
	        chanalert(s_SecureServ,  "DNS Error checking for Updates");
	}
}
