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
** $Id: SecureServ.c,v 1.10 2003/05/14 13:53:17 fishwaldo Exp $
*/


#include <stdio.h>
#include <fnmatch.h>
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
void datver(HTTP_Response *response);
void datdownload(HTTP_Response *response);
void load_dat();
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
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help for more info", s_SecureServ);
		}
		return 1;
	} else if (!strcasecmp(argv[1], "list")) {
		do_list(u);
		return 1;
	} else if (!strcasecmp(argv[1], "cycle")) {
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
			prefmsg(u->nick, s_SecureServ, "AutoUpdate Mode is now enabled");
			chanalert(s_SecureServ, "%s enabled AutoUpdate Mode", u->nick);
			SetConf((void *)1, CFGINT, "AutoUpdate");
			SecureServ.autoupgrade = 1;
			return;
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
	} else if (!strcasecmp(av[2], "NOHELPMSG")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
		if (av[3][0] != '#') {
			prefmsg(u->nick, s_SecureServ, "Invalid Channel %s", av[3]);
			return;
		}
		strncpy(SecureServ.HelpChan, av[3], CHANLEN);
		prefmsg(u->nick, s_SecureServ, "Help Channel is now set to %s", buf);
		chanalert(s_SecureServ, "%s set the Help Channel to %s", u->nick, buf);
		SetConf((void *)buf, CFGSTR, "HelpChan");
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
				snprintf(type, MAXHOST, "CTCP Version Check");
				break;
			case DET_MSG:
				snprintf(type, MAXHOST, "OnJoin Receive Message");
				break;
			default:
				snprintf(type, MAXHOST, "Any Recieved Message");
		}
		switch (ve->action) {
			case ACT_SVSJOIN:
				snprintf(action, MAXHOST, "SVSjoin to AV channel");
				break;
			case ACT_AKILL:
				snprintf(action, MAXHOST, "Akill Client");
				break;
			case ACT_WARN:
				snprintf(action, MAXHOST, "Warn Opers");
				break;
			default:
				snprintf(action, MAXHOST, "Warn Client Only");
		}
		prefmsg(u->nick, s_SecureServ, "%d) Virus: %s. Detection Via: %s. Action: %s", i, ve->name, type, action);
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

	http_request(DATFILEVER, 2, HFLAG_NONE, datver);

	return 1;
};


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
	if (GetConf((void *)&SecureServ.timedif, CFGINT, "NetSplitTime") <= 0) {
		/* use Default */
		SecureServ.timedif = 300;
	}
	if (GetConf((void *)&SecureServ.verbose, CFGINT, "Verbose") <= 0){
		/* yes */
		SecureServ.verbose = 1;
	}
	if (GetConf((void *)&SecureServ.stayinchantime, CFGINT, "StayInChanTime") <= 0) {
		/* 60 seconds */
		SecureServ.stayinchantime = 60;
	}
	if (GetConf((void *)&SecureServ.autoupgrade, CFGINT, "AutoUpgrade") <= 0) {
		/* autoupgrade is the default */
		SecureServ.autoupgrade = 0;
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
			if (GetConf((void *)&exempts->server, CFGBOOL, datapath) <= 0) {
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


	/* if the list isn't empty, make it empty */
	if (!list_isempty(viri)) {
		node = list_first(viri);
		do {
			viridet = lnode_get(node);
			list_delete(viri, node);
			lnode_destroy(node);
			free(viridet);
		} while ((node = list_next(viri, node)) != NULL);
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
	node = lnode_create(viridet);
	list_prepend(viri, node);
	nlog(LOG_DEBUG1, LOG_MOD, "loaded %s (Detection %d, with %s, send %s and do %d", viridet->name, viridet->dettype, viridet->recvmsg, viridet->sendmsg, viridet->action);
	
	
	fp = fopen("data/viri.dat", "r");
	if (!fp) {
		nlog(LOG_WARNING, LOG_MOD, "TS: Error, No viri.dat file found. %s is disabled", s_SecureServ);
		chanalert(s_SecureServ, "Error not viri.dat file found, %s is disabled", s_SecureServ);
		return;
	} else {
		fgets(buf, 512, fp);
		SecureServ.viriversion = atoi(buf);
		while (fgets(buf, 512, fp)) {
			if (list_isfull(viri))
				break;
			viridet = malloc(sizeof(virientry));
			snprintf(viridet->name, MAXHOST, "%s", strtok(buf, " "));
			viridet->dettype = atoi(strtok(NULL, " "));
			viridet->var1 = atoi(strtok(NULL, " "));
			viridet->var2 = atoi(strtok(NULL, " "));
			snprintf(viridet->recvmsg, MAXHOST, "%s", strtok(NULL, "\""));
			strtok(NULL, "\"");
			snprintf(viridet->sendmsg, MAXHOST, "%s", strtok(NULL, "\""));
			viridet->action = atoi(strtok(NULL, ""));
			viridet->nofound = 0;
			node = lnode_create(viridet);
			list_prepend(viri, node);
			nlog(LOG_DEBUG1, LOG_MOD, "loaded %s (Detection %d, with %s, send %s and do %d", viridet->name, viridet->dettype, viridet->recvmsg, viridet->sendmsg, viridet->action);
		}
	}

	
}


EventFnList my_event_list[] = {
	{ "ONLINE", 	Online},
	{ "SIGNON", 	ScanNick},
	{ "NEWCHAN",	ss_new_chan},
	{ "JOINCHAN", 	ss_join_chan},
	{ "DELCHAN",	ss_del_chan},
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


/* scan the nickname */
static int ScanNick(char **av, int ac) {
	User *u;
	lnode_t *node;
	virientry *viridetails;
	exemptinfo *exempts;
	char username[11];
	char *s1, *s2, *user;

	strcpy(segv_location, "TS:ScanNick");
	/* don't do anything if NeoStats hasn't told us we are online yet */
	if (!SecureServ.inited)
		return 0;
							
	u = finduser(av[0]);
	if (!u) {
		nlog(LOG_WARNING, LOG_MOD, "TS: Ehhh, Can't find user %s", av[0]);
		return -1;
	}
	
	/* don't scan users from my own server */
	if (!strcasecmp(u->server->name, me.name)) {
		return -1;
	}

	/* don't scan users from a server that is excluded */
	node = list_first(exempt);
	while (node) {
		exempts = lnode_get(node);
		if (exempts->server == 1) {
			/* match a server */
			if (fnmatch(exempts->host, u->server->name, 0) == 0) {
				nlog(LOG_DEBUG1, LOG_MOD, "TS: User %s exempt. Matched server entry %s in Exemptions", u->nick, exempts->host);
				return -1;
			}
		}
		node = list_next(exempt, node);
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
	
	/* if its not a ctcp message, forget it */
	if (av[1][0] != '\1') 
		return 0;
	
	if (!strcasecmp(av[1], "\1version")) {
		buf = joinbuf(av, ac, 2);
		if (SecureServ.verbose) chanalert(s_SecureServ, "Got Version Reply from %s: %s", origin, buf);
		node = list_first(viri);
		do {
			viridetails = lnode_get(node);
			if ((viridetails->dettype == DET_CTCP) || (viridetails->dettype > 20)) {
				nlog(LOG_DEBUG1, LOG_MOD, "TS: Checking Version %s against %s", buf, viridetails->recvmsg);
				if (fnmatch(viridetails->recvmsg, buf, 0) == 0) {
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
	ve->nofound++;
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
		nlog(LOG_DEBUG1, LOG_MOD, "LocalDat Version %d, WebSite %d", SecureServ.viriversion, myversion);
		if (myversion > SecureServ.viriversion) {
			if (SecureServ.autoupgrade > 0) {
				SecureServ.doUpdate = 1;
				add_mod_timer("DownLoadDat", "DownLoadNewDat", my_info[0].module_name, 1);
			 } else
				chanalert(s_SecureServ, "A new DatFile Version %d is available. You should /msg %s update", myversion, s_SecureServ);
		}
	} else {
		nlog(LOG_DEBUG1, LOG_MOD, "Virus Definition check Failed. %s", response->pError);
		return;
	}
}
void DownLoadDat() {
	/* dont keep trying to download !*/
	if (SecureServ.doUpdate == 1) {
		del_mod_timer("DownLoadNewDat");
		SecureServ.doUpdate = 2;
		http_request(DATFILE, 2, HFLAG_NONE, datdownload);
	} 
	return;
}


/* @brief this downloads a dat file and loads the new version into memory if required 
*/

void datdownload(HTTP_Response *response) {
	char tmpname[255];
	int i;
	
	/* if this is a automatic download, KILL the timer */
	if (SecureServ.doUpdate == 2) {
		/* clear this flag */
		SecureServ.doUpdate = 0;
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
}
	
		
void _fini() {

};
