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
** $Id: SecureServ.c,v 1.3 2003/04/19 07:52:15 fishwaldo Exp $
*/


#include <stdio.h>
#include <fnmatch.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <fnmatch.h>
#include "dl.h"
#include "log.h"
#include "stats.h"
#include "conf.h"
#include "SecureServ.h"

const char tsversion_date[] = __DATE__;
const char tsversion_time[] = __TIME__;




extern const char *ts_help[];
static int ScanNick(char **av, int ac);
void LoadTSConf();
int check_version_reply(char *origin, char **av, int ac);
void gotpositive(User *u, virientry *ve, int type);
void do_list(User *u);

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
	} else {
		prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help", s_SecureServ);
	}
	return 1;
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
	while ((node = list_next(viri, node)) != NULL) {
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
	}
	prefmsg(u->nick, s_SecureServ, "End of List.");
}

int Online(char **av, int ac) {

	strcpy(segv_location, "TS:Online");
	if (init_bot(s_SecureServ,"ts",me.name,"Trojan Scanning Bot", "+xd", my_info[0].module_name) == -1 ) {
		/* Nick was in use!!!! */
		s_SecureServ = strcat(s_SecureServ, "_");
		init_bot(s_SecureServ,"ts",me.name,"Trojan Scanning Bot", "+xd", my_info[0].module_name);
	}
	LoadTSConf();
	chanalert(s_SecureServ, "%d Trojans Patterns loaded", list_count(viri));
	srand(hash_count(ch));
	/* kick of the autojoin timer */
	add_mod_timer("JoinNewChan", "RandomJoinChannel", my_info[0].module_name, SecureServ.stayinchantime);
	return 1;
};


void LoadTSConf() {
	lnode_t *node;
	exemptinfo *exempts = NULL;
	randomnicks *rnicks;
	virientry *viridet;
	char buf[512];
	char **data;
	int i;
	FILE *fp;
	char *tmp;
	char datapath[MAXHOST];
	strcpy(segv_location, "TS:loadTSConf");

	
	if(GetConf((void *)SecureServ.doscan, CFGBOOL, "DoVersionScan") <= 0) {
		/* not configured, don't scan */
		SecureServ.doscan = 0;
	}
		
	if (GetConf((void *)SecureServ.timedif, CFGINT, "NetSplitTime") <= 0) {
		/* use Default */
		SecureServ.timedif = 300;
	}
	if (GetConf((void *)SecureServ.verbose, CFGINT, "Verbose") <= 0){
		/* yes */
		SecureServ.verbose = 1;
	}
	if (GetConf((void *)SecureServ.stayinchantime, CFGINT, "StayInChanTime") <= 0) {
		/* 60 seconds */
		SecureServ.stayinchantime = 60;
	}
	
	
	GetDir("g/SecureServ:/Exempt", &data);
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

	/* get Random Nicknames */
	GetDir("g/SecureServ:/RandomNicks", &data);
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

	free(data);
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
			node = lnode_create(viridet);
			list_prepend(viri, node);
			nlog(LOG_DEBUG1, LOG_MOD, "loaded %s (Detection %d, with %s, send %s and do %d", viridet->name, viridet->dettype, viridet->recvmsg, viridet->sendmsg, viridet->action);
		}
	}
	SecureServ.inited = 1;

	
}


EventFnList my_event_list[] = {
	{ "ONLINE", 	Online},
	{ "SIGNON", 	ScanNick},
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
	exemptinfo *exempts;

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
		node = list_first(viri);
		while ((node = list_next(viri, node)) != NULL) {
			viridetails = lnode_get(node);
			if ((viridetails->dettype == DET_CTCP) || (viridetails->dettype > 1)) {
				nlog(LOG_DEBUG1, LOG_MOD, "TS: Checking Version %s against %s", buf, viridetails->recvmsg);
				if (fnmatch(viridetails->recvmsg, buf, 0) == 0) {
					gotpositive(finduser(origin), viridetails, DET_CTCP);
					if (SecureServ.breakorcont == 0)
						continue;
					else 
						break;
				}
		
			}
		}
	}				
	return 0;
}


void gotpositive(User *u, virientry *ve, int type) {

	prefmsg(u->nick, s_SecureServ, "%s has detected that your client is a Trojan/Infected IRC client/Vulnerble Script called %s", s_SecureServ, ve->name);
	prefmsg(u->nick, s_SecureServ, ve->sendmsg);
	switch (ve->action) {
		case ACT_AKILL:
			if (SecureServ.doakill > 0) {
				prefmsg(u->nick, s_SecureServ, SecureServ.akillinfo);
				chanalert(s_SecureServ, "Akilling %s for Virus %s", u->nick, ve->name);
				break;
			}
		case ACT_SVSJOIN:
			if (SecureServ.dosvsjoin > 0) {
				if (SecureServ.helpcount > 0) {		
					chanalert(s_SecureServ, "SVSJoining %s Nick to avchan for Virus %s", u->nick, ve->name);
					break;
				} else {
					prefmsg(u->nick, s_SecureServ, SecureServ.nohelp);
					chanalert(s_SecureServ, "Akilling %s for Virus %s (No Helpers Logged in)", u->nick, ve->name);
					globops(s_SecureServ, "Akilling %s for Virus %s (No Helpers Logged in)", u->nick, ve->name);
					break;
				}
			}
		case ACT_WARN:
			chanalert(s_SecureServ, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken", u->nick, ve->name);
			globops(s_SecureServ, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken", u->nick, ve->name);
			break;
	}
}



void _init() {

	s_SecureServ = "SecureServ";
	strcpy(segvinmodule, "SecureServ");
	exempt = list_create(MAX_EXEMPTS);
	viri = list_create(MAX_VIRI);
	nicks = list_create(MAX_NICKS);
	SecureServ.inited = 0;			
	SecureServ.timedif = 300;	
	SecureServ.doscan = 1;
	snprintf(SecureServ.signonscanmsg, 512, "Your IRC client is being checked for Trojans. Please dis-regard VERSION messages from %s", s_SecureServ);
	snprintf(SecureServ.akillinfo, 512, "You have been Akilled from this network. Please get a virus scanner and check your PC");
	snprintf(SecureServ.nohelp, 512, "No Helpers are online at the moment, so you have been Akilled from this network. Please visit http://www.nohack.org for Trojan/Virus Info");
	SecureServ.breakorcont = 1;
	SecureServ.doakill = 1;
	SecureServ.dosvsjoin = 1;
	SecureServ.helpcount = 0;

	
}


void _fini() {

};
