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

extern const char *ts_help[];
static int ScanNick(char **av, int ac);
void LoadTSConf();
int check_version_reply(char *origin, char **av, int ac);
void gotpositive(User *u, virientry *ve, int type);
void do_set(User *u, char **av, int ac);
void do_list(User *u);
void do_status(User *u);
void do_reload(User *u);
void datver(HTTP_Response *response);
void datdownload(HTTP_Response *response);
static void load_dat();
int is_exempt(User *u);
static int CheckNick(char **av, int ac);
static int DelNick(char **av, int ac);
static void GotHTTPAddress(char *data, adns_answer *a);
static void save_exempts();
int AutoUpdate();
int CleanNickFlood();

static char ss_buf[SS_BUF_SIZE];

ModuleInfo __module_info = {
	"SecureServ",
	"A Trojan Scanning Bot",
	"1.0",
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
	lnode_t *node;
	exemptinfo *exempts = NULL;
	randomnicks *bots;
	int i;
	char *buf, *buf2;
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
		if (argc < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help login for more info", s_SecureServ);
			return -1;
		}
		Helpers_Login(u, argv, argc);
		return 1;		
 	} else if (!strcasecmp(argv[1], "logout")) {
		Helpers_Logout(u);
 		return 1;
	} else if (!strcasecmp(argv[1], "helpers")) {
		if (UserLevel(u) < NS_ULEVEL_ADMIN) {
			prefmsg(u->nick, s_SecureServ, "Permission Denied");
			chanalert(s_SecureServ, "%s tried to use Helpers, but Permission was denied", u->nick);
			return -1;
		}			
		if (argc < 3) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help helpers for more info", s_SecureServ);
			return -1;
		}
		if (!strcasecmp(argv[2], "add")) {
			Helpers_add(u, argv, argc);
			return 1;
		} else if (!strcasecmp(argv[2], "del")) {
			if (argc == 4) {
				Helpers_del(u, argv[3]);
				return 1;
			} else {
				prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help helpers for more info", s_SecureServ);
				return -1;
			}
		} else if (!strcasecmp(argv[2], "list")) {
			Helpers_list(u);
			return 1;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help helpers for more info", s_SecureServ);
			return -1;
		}

	} else if (!strcasecmp(argv[1], "list")) {
		if (UserLevel(u) < NS_ULEVEL_OPER) {
			prefmsg(u->nick, s_SecureServ, "Permission Denied");
			chanalert(s_SecureServ, "%s tried to list, but Permission was denied", u->nick);
			return -1;
		}			
		do_list(u);
		return 1;
	} else if (!strcasecmp(argv[1], "ASSIST")) {
		if (argc < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help assist", s_SecureServ);
			return -1;
		}
		Helpers_Assist(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[1], "EXCLUDE")) {
		if (UserLevel(u) < 50) {
			prefmsg(u->nick, s_SecureServ, "Access Denied");
			chanalert(s_SecureServ, "%s tried to use exclude, but is not an operator", u->nick);
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
						strlcpy(ss_buf, "HostName", SS_BUF_SIZE);
						break;
					case 1:
						strlcpy(ss_buf, "Server", SS_BUF_SIZE);
						break;
					case 2:
						strlcpy(ss_buf, "Channel", SS_BUF_SIZE);
						break;
					default:
						strlcpy(ss_buf, "Unknown", SS_BUF_SIZE);
						break;
				}
				prefmsg(u->nick, s_SecureServ, "%d) %s (%s) Added by %s for %s", i, exempts->host, ss_buf, exempts->who, exempts->reason);
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
			strlcpy(exempts->host, argv[3], MAXHOST);
			exempts->server = atoi(argv[4]);
			strlcpy(exempts->who, u->nick, MAXNICK);
			buf = joinbuf(argv, argc, 5);
			strlcpy(exempts->reason, buf, MAXHOST);
			free(buf);
			node = lnode_create(exempts);
			list_append(exempt, node);
			switch (exempts->server) {
				case 0:
					strlcpy(ss_buf, "HostName", SS_BUF_SIZE);
					break;
				case 1:
					strlcpy(ss_buf, "Server", SS_BUF_SIZE);
					break;
				case 2:
					strlcpy(ss_buf, "Channel", SS_BUF_SIZE);
					break;
				default:
					strlcpy(ss_buf, "Unknown", SS_BUF_SIZE);
					break;
			}
			prefmsg(u->nick, s_SecureServ, "Added %s (%s) exception to list", exempts->host, ss_buf);
			chanalert(s_SecureServ, "%s added %s (%s) exception to list", u->nick, exempts->host, ss_buf);
			save_exempts();
			return 1;
		} else if (!strcasecmp(argv[2], "DEL")) {
			if (argc < 4) {
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
								strlcpy(ss_buf, "HostName", SS_BUF_SIZE);
								break;
							case 1:
								strlcpy(ss_buf, "Server", SS_BUF_SIZE);
								break;
							case 2:
								strlcpy(ss_buf, "Channel", SS_BUF_SIZE);
								break;
							default:
								strlcpy(ss_buf, "Unknown", SS_BUF_SIZE);
								break;
						}
						prefmsg(u->nick, s_SecureServ, "Deleted %s %s out of exception list", exempts->host, ss_buf);
						chanalert(s_SecureServ, "%s deleted %s %s out of exception list", u->nick, exempts->host, ss_buf);
						buf = malloc(255);
						ircsnprintf(buf, 255, "Exempt/%s", exempts->host);
						DelConf(buf);
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
	} else if (!strcasecmp(argv[1], "BOTS")) {
		if (UserLevel(u) < 100) {
			prefmsg(u->nick, s_SecureServ, "Access Denied");
			chanalert(s_SecureServ, "%s tried to use BOTS, but is not an operator", u->nick);
			return 1;
		}
		if (argc < 3) {
			prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help bots", s_SecureServ);
			return 0;
		}
		if (!strcasecmp(argv[2], "LIST")) {
			node = list_first(nicks);
			i = 1;
			prefmsg(u->nick, s_SecureServ, "Bot List:");
			while (node) {
				bots = lnode_get(node);
				prefmsg(u->nick, s_SecureServ, "%d) %s (%s@%s) - %s", i, bots->nick, bots->user, bots->host, bots->rname);
				++i;
 				node = list_next(nicks, node);
			}
			prefmsg(u->nick, s_SecureServ, "End of List.");
			chanalert(s_SecureServ, "%s requested Bot List", u->nick);
		} else if (!strcasecmp(argv[2], "ADD")) {
			if (argc < 7) {
				prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help bots", s_SecureServ);
				return 0;
			}
			if (list_isfull(nicks)) {
				prefmsg(u->nick, s_SecureServ, "Error, Bot list is full", s_SecureServ);
				return 0;
			}
			buf = malloc(MAXHOST+1);
			ircsnprintf(buf, MAXHOST, "RandomNicks/%s/User", argv[3]);
			SetConf((void *)argv[4], CFGSTR, buf);
			ircsnprintf(buf, MAXHOST, "RandomNicks/%s/Host", argv[3]);
			SetConf((void *)argv[5], CFGSTR, buf);
			ircsnprintf(buf, MAXHOST, "RandomNicks/%s/RealName", argv[3]);
			buf2 = joinbuf(argv, argc, 6);			
			SetConf((void *)buf2, CFGSTR, buf);
			free(buf);
			bots = malloc(sizeof(randomnicks));
			strlcpy(bots->nick, argv[3], MAXNICK);
			strlcpy(bots->user, argv[4], MAXUSER);
			strlcpy(bots->host, argv[5], MAXHOST);
			strlcpy(bots->rname, buf2, MAXREALNAME);
			free(buf2);
			node = lnode_create(bots);
			list_append(nicks, node);
			prefmsg(u->nick, s_SecureServ, "Added %s (%s@%s - %s) Bot to Bot list", bots->nick, bots->user, bots->host, bots->rname);
			chanalert(s_SecureServ, "%s added %s (%s@%s - %s) Bot to Bot list", u->nick, bots->nick, bots->user, bots->host, bots->rname);
			return 1;
		} else if (!strcasecmp(argv[2], "DEL")) {
			if (argc < 4) {
				prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help bots", s_SecureServ);
				return 0;
			}
			if (atoi(argv[3]) != 0) {
				node = list_first(nicks);
				i = 1;
				while (node) {
					if (i == atoi(argv[3])) {
						/* delete the entry */
						bots = lnode_get(node);
						/* dont delete the bot if its setup as the monbot */
						if (!strcasecmp(bots->nick, SecureServ.monbot)) {
							prefmsg(u->nick, s_SecureServ, "Cant delete %s from botlist as its set as the monitor Bot", bots->nick);
							return -1;
						}
						/* don't delete the bot if its online! */
						if (findbot(bots->nick)) {
							prefmsg(u->nick, s_SecureServ, "Can't delete %s from botlist as its online at the moment", bots->nick);
							return -1;
						}
						list_delete(nicks, node);
						buf = malloc(MAXHOST+1);
						ircsnprintf(buf, MAXHOST, "RandomNicks/%s", bots->nick);
						DelConf(buf);
						free(buf);
						prefmsg(u->nick, s_SecureServ, "Deleted %s out of Bot list", bots->nick);
						chanalert(s_SecureServ, "%s deleted %s out of bot list", u->nick, bots->nick);
						lnode_destroy(node);
						free(bots);
						return 1;
					}
					++i;
					node = list_next(nicks, node);
				}		
				/* if we get here, then we can't find the entry */
				prefmsg(u->nick, s_SecureServ, "Error, Can't find entry %d. /msg %s bots list", atoi(argv[3]), s_SecureServ);
				return 0;
			} else {
				prefmsg(u->nick, s_SecureServ, "Error, Out of Range");
				return 0;
			}
		} else {
			prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help bots", s_SecureServ);
			return 0;
		}
	} else if (!strcasecmp(argv[1], "checkchan")) {
		if (UserLevel(u) < NS_ULEVEL_OPER) {
			prefmsg(u->nick, s_SecureServ, "Permission Denied");
			chanalert(s_SecureServ, "%s tried to checkchan, but Permission was denied", u->nick);
			return -1;
		}			
		if (argc < 3) {
			prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help checkchan", s_SecureServ);
			return -1;
		}
		CheckChan(u, argv[2]);
		return 1;
	} else if (!strcasecmp(argv[1], "monchan")) {
		if (UserLevel(u) < NS_ULEVEL_OPER) {
			prefmsg(u->nick, s_SecureServ, "Permission Denied");
			chanalert(s_SecureServ, "%s tried to monchan, but Permission was denied", u->nick);
			return -1;
		}			
		if (argc < 3) {
			prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help monchan", s_SecureServ);
			return -1;
		}
		if (!strcasecmp(argv[2], "ADD")) {
			if (argc < 4) {
				prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help monchan", s_SecureServ);
				return -1;
			}
			MonChan(u, argv[3]);
		} else if (!strcasecmp(argv[2], "DEL")) {
			if (argc < 4) {
				prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help monchan", s_SecureServ);
				return -1;
			}
			StopMon(u, argv[3]);
		} else if (!strcasecmp(argv[2], "LIST")) {
			ListMonChan(u);
		} else {
			prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help monchan", s_SecureServ);
		}
		return 1;
	} else if (!strcasecmp(argv[1], "cycle")) {
		if (UserLevel(u) < NS_ULEVEL_OPER) {
			prefmsg(u->nick, s_SecureServ, "Permission Denied");
			chanalert(s_SecureServ, "%s tried to cycle, but Permission was denied", u->nick);
			return -1;
		}			
		JoinNewChan();
		return 1;
	} else if (!strcasecmp(argv[1], "set")) {
		if (UserLevel(u) < NS_ULEVEL_ADMIN) {
			prefmsg(u->nick, s_SecureServ, "Permission is denied", u->nick);
			chanalert(s_SecureServ, "%s tried to use SET, but Permission was denied", u->nick);
			return -1;
		}
		do_set(u, argv, argc);
		return 1;		
	} else if (!strcasecmp(argv[1], "status")) {
		if (UserLevel(u) < NS_ULEVEL_OPER) {
			prefmsg(u->nick, s_SecureServ, "Permission Denied");
			chanalert(s_SecureServ, "%s tried to list status, but Permission was denied", u->nick);
			return -1;
		}			
		do_status(u);
		return 1;
	
	} else if (!strcasecmp(argv[1], "update")) {
		if (UserLevel(u) < NS_ULEVEL_ADMIN) {
			prefmsg(u->nick, s_SecureServ, "Permission Denied");
			chanalert(s_SecureServ, "%s tried to update, but Permission was denied", u->nick);
			return -1;
		}
		ircsnprintf(ss_buf, SS_BUF_SIZE, "http://%s%s?u=%s&p=%s", SecureServ.updateurl, DATFILE, SecureServ.updateuname, SecureServ.updatepw);
		http_request(ss_buf, 2, HFLAG_NONE, datdownload);
		prefmsg(u->nick, s_SecureServ, "Requesting New Dat File. Please Monitor the Services Channel for Success/Failure");
		chanalert(s_SecureServ, "%s requested an update to the Dat file", u->nick);
	} else if (!strcasecmp(argv[1], "reload")) {
		if (UserLevel(u) < NS_ULEVEL_OPER) {
			prefmsg(u->nick, s_SecureServ, "Permission Denied");
			chanalert(s_SecureServ, "%s tried to reload, but Permission was denied", u->nick);
			return -1;
		}			
		do_reload(u);
		return 1;
	
	} else {
		prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help", s_SecureServ);
	}
	return 1;
}



void do_set(User *u, char **av, int ac) {
	int i, j;
	char *buf;
	/* this is ok, its just to shut up fussy compilers */
	randomnicks *nickname = NULL;
	lnode_t *rnn;
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
		strlcpy(SecureServ.updateuname, av[3], MAXNICK);
		strlcpy(SecureServ.updatepw, av[4], MAXNICK);
		chanalert(s_SecureServ, "%s changed the Update Username and Password", u->nick);
		prefmsg(u->nick, s_SecureServ, "Update Username and Password has been updated to %s and %s", SecureServ.updateuname, SecureServ.updatepw);
		return;
	} else if (!strcasecmp(av[2], "CHANKEY")) {
		if ((ac < 4) || (strlen(av[3]) > CHANLEN)) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set", s_SecureServ);
			return;
		}
		SetConf((void *)av[3], CFGSTR, "ChanKey");
		strlcpy(SecureServ.ChanKey, av[3], CHANLEN);
		chanalert(s_SecureServ, "%s changed the Channel Flood Protection key to %s", u->nick, SecureServ.ChanKey);
		prefmsg(u->nick, s_SecureServ, "Channel Flood Protection Key has been updated to %s", SecureServ.ChanKey);
		return;
	} else if (!strcasecmp(av[2], "VERSION")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Version Checking is now enabled");
			chanalert(s_SecureServ, "%s has enabled Version Checking", u->nick);
			SetConf((void *)1, CFGINT, "DoVersionScan");
			SecureServ.doscan = 1;
			return;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Version Checking is now Disabled");
			chanalert(s_SecureServ, "%s has disabled Version Checking", u->nick);
			SetConf((void *)0, CFGINT, "DoVersionScan");
			SecureServ.doscan = 0;
			return;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
	} else if (!strcasecmp(av[2], "AUTOSIGNOUT")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Helper Away Auto logout is now enabled");
			chanalert(s_SecureServ, "%s has enabled Helper Away Auto Logout", u->nick);
			SetConf((void *)1, CFGINT, "DoAwaySignOut");
			SecureServ.signoutaway = 1;
			return;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Helper Away Auto logout is now Disabled");
			chanalert(s_SecureServ, "%s has disabled Helper Away Auto logout", u->nick);
			SetConf((void *)0, CFGINT, "DoAwaySignOut");
			SecureServ.signoutaway = 0;
			return;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
	} else if (!strcasecmp(av[2], "JOINHELPCHAN")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "SecureServ will join the Help Channel");
			chanalert(s_SecureServ, "%s has enabled SecureServ to join the HelpChannel", u->nick);
			SetConf((void *)1, CFGINT, "DoJoinHelpChan");
			SecureServ.joinhelpchan = 1;
			return;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "SecureServ will not join the Help Channel");
			chanalert(s_SecureServ, "%s has disabled SecureServ joining the Help Channel", u->nick);
			SetConf((void *)0, CFGINT, "DoJoinHelpChan");
			SecureServ.joinhelpchan = 0;
			return;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
	} else if (!strcasecmp(av[2], "REPORT")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Reporting is now enabled");
			chanalert(s_SecureServ, "%s has enabled Reporting", u->nick);
			SetConf((void *)1, CFGINT, "DoReport");
			SecureServ.report = 1;
			return;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Reporting is now Disabled");
			chanalert(s_SecureServ, "%s has disabled Reporting", u->nick);
			SetConf((void *)0, CFGINT, "DoReport");
			SecureServ.report = 0;
			return;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
	} else if (!strcasecmp(av[2], "FLOODPROT")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Channel Flood Protection is now enabled");
			chanalert(s_SecureServ, "%s has enabled Channel Flood Protection", u->nick);
			SetConf((void *)1, CFGINT, "DoFloodProt");
			SecureServ.FloodProt = 1;
			return;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Channel Flood Protection is now Disabled");
			chanalert(s_SecureServ, "%s has disabled Channel Flood Protection", u->nick);
			SetConf((void *)0, CFGINT, "DoFloodProt");
			SecureServ.FloodProt = 0;
			return;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
	} else if (!strcasecmp(av[2], "DOPRIVCHAN")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "Private Channel Checking is now enabled");
			chanalert(s_SecureServ, "%s has enabled Private Channel Checking", u->nick);
			SetConf((void *)1, CFGINT, "DoPrivChan");
			SecureServ.doprivchan = 1;
			return;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "Private Channel Checking is now Disabled");
			chanalert(s_SecureServ, "%s has disabled Private Channel Checking", u->nick);
			SetConf((void *)0, CFGINT, "DoPrivChan");
			SecureServ.doprivchan = 0;
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
		if (i <= 0) {
			prefmsg(u->nick, s_SecureServ, "Value out of Range.");
			return;
		}
		/* if we get here, all is ok */
		SecureServ.akilltime = i;
		prefmsg(u->nick, s_SecureServ, "Akill Time is set to %d Seconds", i);
		chanalert(s_SecureServ, "%s Set Akill Time to %d Seconds", u->nick, i);
		SetConf((void *)i, CFGINT, "AkillTime");
		return;
	} else if (!strcasecmp(av[2], "CHANLOCKTIME")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		i = atoi(av[3]);	
		if ((i <= 0) || (i > 600)) {
			prefmsg(u->nick, s_SecureServ, "Value out of Range.");
			return;
		}
		/* if we get here, all is ok */
		SecureServ.closechantime = i;
		prefmsg(u->nick, s_SecureServ, "Channel Flood Protection will be active for %d seconds", i);
		chanalert(s_SecureServ, "%s Set Channel Flood Protection time to %d seconds", u->nick, i);
		SetConf((void *)i, CFGINT, "ChanLockTime");
		return;
	} else if (!strcasecmp(av[2], "NFCOUNT")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		i = atoi(av[3]);	
		if ((i <= 0) || (i > 100)) {
			prefmsg(u->nick, s_SecureServ, "Value out of Range.");
			return;
		}
		/* if we get here, all is ok */
		SecureServ.nfcount = i;
		prefmsg(u->nick, s_SecureServ, "NickFlood Count is set to %d in 10 Seconds", i);
		chanalert(s_SecureServ, "%s Set NickFlood Count to %d Seconds in 10 Seconds", u->nick, i);
		SetConf((void *)i, CFGINT, "NFCount");
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
	} else if (!strcasecmp(av[2], "DOONJOIN")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "OnJoin Virus Checking is now enabled");
			chanalert(s_SecureServ, "%s enabled OnJoin Virus Checking", u->nick);
			SetConf((void *)1, CFGINT, "DoOnJoin");
			SecureServ.DoOnJoin = 1;
			return;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "OnJoin Virus Checking is now disabled");
			chanalert(s_SecureServ, "%s disabled OnJoin Virus Checking", u->nick);
			SetConf((void *)0, CFGINT, "DoOnJoin");
			SecureServ.DoOnJoin = 0;
			return;
		} else {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}
	} else if (!strcasecmp(av[2], "BOTECHO")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
			prefmsg(u->nick, s_SecureServ, "OnJoin Bot Echo is now enabled");
			chanalert(s_SecureServ, "%s enabled OnJoin Bot Echo", u->nick);
			SetConf((void *)1, CFGINT, "BotEcho");
			SecureServ.BotEcho= 1;
			return;
		} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
			prefmsg(u->nick, s_SecureServ, "OnJoin Bot Echo is now disabled");
			chanalert(s_SecureServ, "%s disabled OnJoin Bot Echo", u->nick);
			SetConf((void *)0, CFGINT, "BotEcho");
			SecureServ.BotEcho= 0;
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
		change_mod_timer_interval ("JoinNewChan", i);
		prefmsg(u->nick, s_SecureServ, "Cycle Time is set to %d Seconds", i);
		chanalert(s_SecureServ, "%s Set Cycle Time to %d Seconds",u->nick,  i);
		SetConf((void *)i, CFGINT, "CycleTime");
		return;
	} else if (!strcasecmp(av[2], "MONBOT")) {
		if (ac < 4) {
			prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
			return;
		}			
		rnn = list_first(nicks);
		while (rnn != NULL) {
			nickname = lnode_get(rnn);
			if (!strcasecmp(nickname->nick, av[3])) {
				/* ok, got the bot ! */
				break;
			}
			rnn = list_next(nicks, rnn);
		}
		if (rnn != NULL) {
			SetConf((void *)av[3], CFGSTR, "MonBot");
			strlcpy(SecureServ.monbot, nickname->nick, MAXNICK);
			prefmsg(u->nick, s_SecureServ, "Monitoring Bot set to %s", av[3]);
			chanalert(s_SecureServ, "%s set the Monitor bot to %s", u->nick, av[3]);
			return;
		} else {
			prefmsg(u->nick, s_SecureServ, "Can't find Bot %s in bot list. /msg %s bot list for Bot List", av[3], s_SecureServ);
			return;
		}
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
		strlcpy(SecureServ.signonscanmsg, buf, BUFSIZE);
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
		strlcpy(SecureServ.akillinfo, buf, BUFSIZE);
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
		strlcpy(SecureServ.nohelp, buf, BUFSIZE);
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
				strlcpy(type, "Version", MAXHOST);
				break;
			case DET_MSG:
				strlcpy(type, "PM", MAXHOST);
				break;
			case DET_NICK:
				strlcpy(type, "Nick", MAXHOST);
				break;
			case DET_IDENT:
				strlcpy(type, "Ident", MAXHOST);
				break;
			case DET_REALNAME:
				strlcpy(type, "RealName", MAXHOST);
				break;
			case DET_CHAN:
				strlcpy(type, "Chan", MAXHOST);
				break;
			case DET_BUILTIN:
				strlcpy(type, "Built-In", MAXHOST);
				break;
			default:
				ircsnprintf(type, MAXHOST, "Unknown(%d)", ve->dettype);
		}
		switch (ve->action) {
			case ACT_SVSJOIN:
				strlcpy(action, "SVSjoin", MAXHOST);
				break;
			case ACT_AKILL:
				strlcpy(action, "Akill", MAXHOST);
				break;
			case ACT_WARN:
				strlcpy(action, "OpersWarn", MAXHOST);
				break;
			default:
				strlcpy(action, "ClientWarn", MAXHOST);
		}
		prefmsg(u->nick, s_SecureServ, "%d) Virus: %s. Detection: %s. Action: %s Hits: %d", i, ve->name, type, action, ve->nofound);
	} while ((node = list_next(viri, node)) != NULL);
	prefmsg(u->nick, s_SecureServ, "End of List.");
}

int Online(char **av, int ac) {

	SET_SEGV_LOCATION();
	if (init_bot(s_SecureServ,"ts",me.name,"Trojan Scanning Bot", services_bot_modes, __module_info.module_name) == -1 ) {
		/* Nick was in use!!!! */
		s_SecureServ = strcat(s_SecureServ, "_");
		init_bot(s_SecureServ,"ts",me.name,"Trojan Scanning Bot", services_bot_modes, __module_info.module_name);
	}
	LoadMonChans();
	Helpers_init();
	if (SecureServ.verbose) chanalert(s_SecureServ, "%d Trojans Patterns loaded", list_count(viri));
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
void save_exempts() {
	lnode_t *node;
	exemptinfo *exempts = NULL;
	int i;

	node = list_first(exempt);
	i = 1;
	while (node) {
		exempts = lnode_get(node);
		nlog(LOG_DEBUG1, LOG_MOD, "Saving Exempt List %s", exempts->host);
		ircsnprintf(ss_buf, SS_BUF_SIZE, "Exempt/%s/Who", exempts->host);
		SetConf((void *)exempts->who, CFGSTR, ss_buf);
		ircsnprintf(ss_buf, SS_BUF_SIZE, "Exempt/%s/Reason", exempts->host);
		SetConf((void *)exempts->reason, CFGSTR, ss_buf);
		ircsnprintf(ss_buf, SS_BUF_SIZE, "Exempt/%s/Server", exempts->host);
		SetConf((void *)exempts->server, CFGINT, ss_buf);
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
	
	if (GetDir("Exempt", &data) > 0) {
		/* try */
		for (i = 0; data[i] != NULL; i++) {
			exempts = malloc(sizeof(exemptinfo));
			strlcpy(exempts->host, data[i], MAXHOST);
	
			ircsnprintf(datapath, MAXHOST, "Exempt/%s/Who", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, datapath) <= 0) {
				free(exempts);
				continue;
			} else {
				strlcpy(exempts->who, tmp, MAXNICK);
				free(tmp);
			}
			ircsnprintf(datapath, MAXHOST, "Exempt/%s/Reason", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, datapath) <= 0) {
				free(exempts);
				continue;
			} else {
				strlcpy(exempts->reason, tmp, MAXHOST);
				free(tmp);
			}
			ircsnprintf(datapath, MAXHOST, "Exempt/%s/Server", data[i]);
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
			strlcpy(rnicks->nick, data[i], MAXNICK);
	
			ircsnprintf(datapath, MAXHOST, "RandomNicks/%s/User", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, datapath) <= 0) {
				free(rnicks);
				continue;
			} else {
				strlcpy(rnicks->user, tmp, MAXUSER);
				free(tmp);
			}
			ircsnprintf(datapath, MAXHOST, "RandomNicks/%s/Host", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, datapath) <= 0) {
				free(rnicks);
				continue;
			} else {
				strlcpy(rnicks->host, tmp, MAXHOST);
				free(tmp);
			}
			ircsnprintf(datapath, MAXHOST, "RandomNicks/%s/RealName", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, datapath) <= 0) {
				free(exempts);
				continue;
			} else {
				strlcpy(rnicks->rname, tmp, MAXREALNAME);
				free(tmp);
			}			
			nlog(LOG_DEBUG2, LOG_MOD, "Adding Random Nick %s!%s@%s with RealName %s", rnicks->nick, rnicks->user, rnicks->host, rnicks->rname);
			node = lnode_create(rnicks);
			list_prepend(nicks, node);			
		}
	}
	if (GetConf((void *)&tmp, CFGSTR, "MonBot") <= 0) {
		SecureServ.monbot[0] = '\0';
	} else {
		node = list_first(nicks);
		while (node != NULL) {
			rnicks = lnode_get(node);
			if (!strcasecmp(rnicks->nick, tmp)) {
				/* ok, got the bot ! */
				break;
			}
			node = list_next(nicks, node);
		}
		if (node != NULL) {
			strlcpy(SecureServ.monbot, tmp, MAXNICK);
		} else {
			SecureServ.monbot[0] = '\0';
			nlog(LOG_DEBUG2, LOG_MOD, "Warning, Cant find nick %s in randmon bot list for monbot", tmp);
		}
		free(tmp);
	}
	free(data);
	load_dat();

}

/* List of local dat files that we will load and process
*/

const char* DatFiles[NUM_DAT_FILES]=
{
	VIRI_DAT_NAME,
	CUSTOM_DAT_NAME,
};

/* This function will not load viri.dat then try to load custom.dat 
   For custom entries, the lack of file is of no importance and a flag is set
   in the viri entry to indicate the custom nature of the definition for use
   by SecureServ.
*/

void load_dat() {
	int i;
	FILE *fp;
	char buf[BUFSIZE];
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
			if (viridet->pattern) free(viridet->pattern);
			if (viridet->patternextra) free(viridet->patternextra);
			free(viridet);
		} while ((node = list_next(viri, node)) != NULL);
		list_destroy_nodes(viri);
	}
	
	for (rc = 0; rc < MAX_PATTERN_TYPES; rc++) {
		SecureServ.definitions[rc] = 0;
	}	

	/* first, add the dat for Fizzer (even if its not enabled!) */
	viridet = malloc(sizeof(virientry));
	strlcpy(viridet->name, "FizzerBot", MAXHOST);
	viridet->dettype = DET_BUILTIN;
	viridet->var1 = 0;
	viridet->var2 = 0;
	strlcpy(viridet->recvmsg, "UserName is RealName Reversed", MAXHOST);
	strlcpy(viridet->sendmsg, "You're Infected with the Fizzer Virus", MAXHOST);
	viridet->action = ACT_AKILL;
	viridet->nofound = 0;
	SecureServ.definitions[DET_BUILTIN]++;
	node = lnode_create(viridet);
	list_prepend(viri, node);
	nlog(LOG_DEBUG1, LOG_MOD, "loaded %s (Detection %d, with %s, send %s and do %d", viridet->name, viridet->dettype, viridet->recvmsg, viridet->sendmsg, viridet->action);
	
	for(i = 0; i < NUM_DAT_FILES; i++)
	{
		fp = fopen(DatFiles[i], "r");
		if (!fp) {
			if(i)
			{
				/* We do not really care if the custom file is not present so don't report it except in debug */
				nlog(LOG_DEBUG1, LOG_MOD, "No custom.dat file found. %s is disabled", s_SecureServ);
			}
			else
			{
				nlog(LOG_WARNING, LOG_MOD, "TS: Error, No viri.dat file found. %s is disabled", s_SecureServ);
				chanalert(s_SecureServ, "Error not viri.dat file found, %s is disabled", s_SecureServ);
			}
			return;
		} else {
			re = pcre_compile("^([a-zA-Z0-9]*) ([0-9]*) ([0-9]*) ([0-9]*) \"(.*)\" \"(.*)\" ([0-9]*).*" , 0, &error, &errofset, NULL);
			if (re == NULL) {
				nlog(LOG_CRITICAL, LOG_MOD, "PCRE_COMPILE of dat file format failed bigtime! %s at %d", error, errofset);		
				return;
			}
			/* only set version for first file */
			if(i==0) 
			{
				/* first fgets always returns the version number */
				fgets(buf, BUFSIZE, fp);
				SecureServ.viriversion = atoi(buf);
			}
			while (fgets(buf, BUFSIZE, fp)) {
				if (list_isfull(viri))
					break;
				viridet = malloc(sizeof(virientry));
				rc = pcre_exec(re, NULL, buf, strlen(buf), 0, 0, ovector, 24);
				if (rc <= 0) {
					nlog(LOG_WARNING, LOG_MOD, "PCRE_EXEC didn't have enough space! %d", rc);
					nlog(LOG_WARNING, LOG_MOD, "Load Was: %s", buf);
					free(viridet);
					continue;
				} else if (rc != 8) {
					nlog(LOG_WARNING, LOG_MOD, "Didn't get required number of Subs (%d)", rc);
					free(viridet);
					continue;
				}
				
				pcre_get_substring_list(buf, ovector, rc, &subs);		
				strlcpy(viridet->name, subs[1], MAXHOST);
				viridet->dettype = atoi(subs[2]);
				viridet->var1 = atoi(subs[3]);
				viridet->var2 = atoi(subs[4]);
				strlcpy(viridet->recvmsg, subs[5], MAXHOST);
				strlcpy(viridet->sendmsg, subs[6], MAXHOST);
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
				viridet->iscustom=i;
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
			free(re);
			fclose(fp);
		}
	}	
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
static int DelNick(char **av, int ac) {
	hnode_t *nfnode;
	nicktrack *nick;
	nlog(LOG_DEBUG2, LOG_MOD, "DelNick: looking for %s\n", av[0]);
	nfnode = hash_lookup(nickflood, av[0]);
	if (nfnode) {
		nick = hnode_get(nfnode);
		hash_delete(nickflood, nfnode);
       		hnode_destroy(nfnode);
		free(nick);
	}
	nlog(LOG_DEBUG2, LOG_MOD, "DelNick: After nickflood Code");
	/* u->moddata is free'd in helpers_signoff */
	Helpers_signoff(finduser(av[0]));
	return 1;
}




/* scan nickname changes */
static int CheckNick(char **av, int ac) {
	User *u;
	lnode_t *node;
	hnode_t *nfnode;
	nicktrack *nick;
	virientry *viridetails;
	int rc;
	
	if (!SecureServ.inited) {
		return 1;
	}
	
	u = finduser(av[1]);
	if (!u) {
		nlog(LOG_WARNING, LOG_MOD, "Cant Find user %s", av[1]);
		return 1;
	}
	u->moddata[SecureServ.modnum] = NULL;
	if (is_exempt(u) > 0) {
		nlog(LOG_DEBUG1, LOG_MOD, "Bye, I'm Exempt %s", u->nick);
		return -1;
	}
	/* is it a nickflood? */
	nfnode = hash_lookup(nickflood, av[0]);
	
	if (nfnode) {
		/* its already there */
		nick = hnode_get(nfnode);
		/* first, remove it from the hash, as the nick has changed */
		hash_delete(nickflood, nfnode);
		/* increment the nflood count */
		nick->changes++;
		nlog(LOG_DEBUG2, LOG_MOD, "NickFlood Check: %d in 10", nick->changes);
		if ((nick->changes > SecureServ.nfcount) && ((time(NULL) - nick->when) <= 10)) {
			/* its a bad bad bad flood */
			chanalert(s_SecureServ, "NickFlood Detected on %s", u->nick);
			/* XXX Do Something bad !!!! */
			
			/* free the struct */
			hnode_destroy(nfnode);
			free(nick);
		} else if ((time(NULL) - nick->when) > 10) {
			nlog(LOG_DEBUG2, LOG_MOD, "Resetting NickFlood Count on %s", u->nick);
			strlcpy(nick->nick, u->nick, MAXNICK);
			nick->changes = 1;
			nick->when = time(NULL);
			hash_insert(nickflood, nfnode, nick->nick);
		} else {			
			/* re-insert it into the hash */
			strlcpy(nick->nick, u->nick, MAXNICK);
			hash_insert(nickflood, nfnode, nick->nick);
		}
	} else {
		/* this is because maybe we already have a record from a signoff etc */
		if (!hash_lookup(nickflood, u->nick)) {
			/* this is a first */
			nick = malloc(sizeof(nicktrack));
			strlcpy(nick->nick, u->nick, MAXNICK);
			nick->changes = 1;
			nick->when = time(NULL);
			nfnode = hnode_create(nick);
			hash_insert(nickflood, nfnode, nick->nick);
			nlog(LOG_DEBUG2, LOG_MOD, "NF: Created New Entry");
		} else {
			nlog(LOG_DEBUG2, LOG_MOD, "Already got a record for %s in NickFlood", u->nick);
		}
	}


	/* check the nickname */
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
				nlog(LOG_NOTICE, LOG_MOD, "Got positive nick %s for %s against %s", u->nick, viridetails->name, viridetails->recvmsg);
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

/* periodically clean up the nickflood hash so it doesn't grow to big */
int CleanNickFlood() {
	hscan_t nfscan;
	hnode_t *nfnode;
	nicktrack *nick;

        hash_scan_begin(&nfscan, nickflood);
        while ((nfnode = hash_scan_next(&nfscan)) != NULL) {
        	nick = hnode_get(nfnode);
        	if ((time(NULL) - nick->when) > 10) {
        		/* delete the nickname */
			nlog(LOG_DEBUG2, LOG_MOD, "Deleting %s out of NickFlood Hash", nick->nick);
        		hash_scan_delete(nickflood, nfnode);
        		free(nick);
        	}
        }
	return 1;
}       
	                



/* scan someone connecting */
static int ScanNick(char **av, int ac) {
	User *u;
	lnode_t *node;
	virientry *viridetails;
	char username[11];
	char *s1, *s2, *user;
	int rc;

	SET_SEGV_LOCATION();
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
		strlcpy(user, u->realname, MAXREALNAME);
		s1 = strtok(user, " ");
		s2 = strtok(NULL, "");
		ircsnprintf(username, 11, "%s%s%s", u->username[0] == '~' ? "~" : "",  s2, s1);
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
				nlog(LOG_NOTICE, LOG_MOD, "Got positive nick %s for %s against %s", u->nick, viridetails->name, viridetails->recvmsg);
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
				nlog(LOG_NOTICE, LOG_MOD, "Got positive ident %s for %s against %s", u->username, viridetails->name, viridetails->recvmsg);
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
				nlog(LOG_NOTICE, LOG_MOD, "Got positive realname %s for %s against %s", u->realname, viridetails->name, viridetails->recvmsg);
				gotpositive(u, viridetails, DET_REALNAME);
				if (SecureServ.breakorcont == 0)
					continue;
				else 
					return 1;
			}
		}
	} while ((node = list_next(viri, node)) != NULL);


	if (SecureServ.doscan == 0) 
		return -1;

	if (time(NULL) - u->TS > SecureServ.timedif) {
		nlog(LOG_DEBUG1, LOG_MOD, "Netsplit Nick %s, Not Scanning %d > %d", av[0], time(NULL) - u->TS, SecureServ.timedif);
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
	int rc, positive = 0;
	char **av1;
	int ac1 = 0;
	static int versioncount = 0;
	
	/* if its not a ctcp message, it is probably a notice for the ONJOIN bots */
	if (av[1][0] != '\1') {
		OnJoinBotMsg(finduser(origin), av, ac);
		return 0;
	}
	if (!strcasecmp(av[1], "\1version")) {
		buf = joinbuf(av, ac, 2);
		/* send a Module_Event, so StatServ can pick up the version info !!! */
		/* nice little side effect isn't it? */
	
		AddStringToList(&av1, origin, &ac1);
		AddStringToList(&av1, buf, &ac1);	
 		Module_Event("CLIENTVERSION", av1, ac1);
 		free(av1);
 		/* reset segvinmodule */
		SET_SEGV_INMODULE("SecureServ");
		
		if (SecureServ.verbose) chanalert(s_SecureServ, "Got Version Reply from %s: %s", origin, buf);
		node = list_first(viri);
		do {
			viridetails = lnode_get(node);
			if ((viridetails->dettype == DET_CTCP) || (viridetails->dettype > MAX_PATTERN_TYPES)) {
				SecureServ.trigcounts[DET_CTCP]++;
				nlog(LOG_DEBUG1, LOG_MOD, "TS: Checking Version %s against %s", buf, viridetails->recvmsg);
				rc = pcre_exec(viridetails->pattern, viridetails->patternextra, buf, strlen(buf), 0, 0, NULL, 0);
				if (rc < -1) {
					nlog(LOG_WARNING, LOG_MOD, "PatternMatch CTCP Version Failed: (%d)", rc);
					continue;
				}
				if (rc > -1) {					
					nlog(LOG_NOTICE, LOG_MOD, "Got positive CTCP %s for %s against %s", buf, viridetails->name, viridetails->recvmsg);
					gotpositive(finduser(origin), viridetails, DET_CTCP);
					positive = 1;
					if (SecureServ.breakorcont == 0)
						continue;
					else 
						break;
				}
		
			}
		} while ((node = list_next(viri, node)) != NULL);
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


void gotpositive(User *u, virientry *ve, int type) {
	char chan[CHANLEN];
	char buf[1400];
	char buf2[3];
	UserDetail *ud;
	int i;

	if (!u) /* User not found */
		return;
	/* Initial message is based on an assumption that the action determines the threat level */
	switch(ve->action) {
		case ACT_SVSJOIN:
			prefmsg(u->nick, s_SecureServ, "%s has detected that your client is an infected IRC client called %s", s_SecureServ, ve->name);
			break;
		case ACT_AKILL:
			prefmsg(u->nick, s_SecureServ, "%s has detected that your client is a Trojan or War Script called %s", s_SecureServ, ve->name);
			break;
		case ACT_WARN:
			prefmsg(u->nick, s_SecureServ, "%s has detected that you or your client is sending unsolicted messages to other users", s_SecureServ);
			break;
		case ACT_NOTHING:
			prefmsg(u->nick, s_SecureServ, "%s has detected that your client is a vulnerable script or client called %s", s_SecureServ, ve->name);
			break;
	} 		
	prefmsg(u->nick, s_SecureServ, ve->sendmsg);
	/* Do not generate a URL for local custom definitions since it will not exist*/
	if(!ve->iscustom)
		prefmsg(u->nick, s_SecureServ, "For More Information Please Visit http://secure.irc-chat.net/info.php?viri=%s", ve->name);
	ve->nofound++;
	SecureServ.actioncounts[type]++;
	switch (ve->action) {
		case ACT_SVSJOIN:
			if (SecureServ.dosvsjoin > 0) {
				if (SecureServ.helpcount > 0) {		
					ud = malloc(sizeof(UserDetail));
					ud->type = USER_INFECTED;
					ud->data = (void *)ve;
					u->moddata[SecureServ.modnum] = ud;					
					chanalert(s_SecureServ, "SVSJoining %s Nick to avchan for Virus %s", u->nick, ve->name);
					if(ve->iscustom) 
						globops(s_SecureServ, "SVSJoining %s for Virus %s", u->nick, ve->name);
					else
						globops(s_SecureServ, "SVSJoining %s for Virus %s (http://secure.irc-chat.net/info.php?viri=%s)", u->nick, ve->name, ve->name);
					if (!IsChanMember(findchan(SecureServ.HelpChan), u)) {
#if defined(GOTSVSJOIN)
						ssvsjoin_cmd(u->nick, SecureServ.HelpChan);
#else 
						sinvite(s_SecureServ, u->nick, SecureServ.HelpChan);
#endif
					}
					nlog(LOG_NOTICE, LOG_MOD, "SVSJoining %s Nick to avchan for Virus %s", u->nick, ve->name);
					ircsnprintf(chan, CHANLEN, "@%s", SecureServ.HelpChan);
					if(ve->iscustom) 
						prefmsg(chan, s_SecureServ, "%s is infected with %s.", u->nick, ve->name);
					else
						prefmsg(chan, s_SecureServ, "%s is infected with %s. More information at http://secure.irc-chat.net/info.php?viri=%s", u->nick, ve->name, ve->name);
#if !defined(GOTSVSJOIN)
						prefmsg(chan, s_SecureServ, "%s was invited to the Channel", u->nick);
#endif
					break;
				} else {
					prefmsg(u->nick, s_SecureServ, SecureServ.nohelp);
					chanalert(s_SecureServ, "Akilling %s!%s@%s for Virus %s (No Helpers Logged in)", u->nick, u->username, u->hostname, ve->name);
					if(ve->iscustom) 
						globops(s_SecureServ, "Akilling %s for Virus %s (No Helpers Logged in)", u->nick, ve->name);
					else
						globops(s_SecureServ, "Akilling %s for Virus %s (No Helpers Logged in) (http://secure.irc-chat.net/info.php?viri=%s)", u->nick, ve->name, ve->name);
					sakill_cmd(u->hostname, u->username, s_SecureServ, SecureServ.akilltime, "SecureServ(SVSJOIN): %s", ve->name);
					nlog(LOG_NOTICE, LOG_MOD, "Akilling %s!%s@%s for Virus %s (No Helpers Logged in)", u->nick, u->username, u->hostname, ve->name);
					break;
				}
			}
		case ACT_AKILL:
			if (SecureServ.doakill > 0) {
				prefmsg(u->nick, s_SecureServ, SecureServ.akillinfo);
				chanalert(s_SecureServ, "Akilling %s!%s@%s for Virus %s", u->nick, u->username, u->hostname, ve->name);
				if(ve->iscustom) 
					sakill_cmd(u->hostname, "*", s_SecureServ, SecureServ.akilltime, "Infected with: %s ", ve->name);
				else
					sakill_cmd(u->hostname, "*", s_SecureServ, SecureServ.akilltime, "Infected with: %s (See http://secure.irc-chat.net/info.php?viri=%s for more info)", ve->name, ve->name);
				nlog(LOG_NOTICE, LOG_MOD, "Akilling %s!%s@%s for Virus %s", u->nick, u->username, u->hostname, ve->name);
				break;
			}
		case ACT_WARN:
			chanalert(s_SecureServ, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken", u->nick, ve->name);
			if(ve->iscustom) 
				globops(s_SecureServ, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken ", u->nick, ve->name);
			else
				globops(s_SecureServ, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken (See http://secure.irc-chat.net/info.php?viri=%s for more info)", u->nick, ve->name, ve->name);
			if (SecureServ.helpcount > 0) {
				ircsnprintf(chan, CHANLEN, "@%s", SecureServ.HelpChan);
				if(ve->iscustom) 
					prefmsg(chan, s_SecureServ, "%s is infected with %s.", u->nick, ve->name);
				else
					prefmsg(chan, s_SecureServ, "%s is infected with %s. More information at http://secure.irc-chat.net/info.php?viri=%s", u->nick, ve->name, ve->name);
			}
			nlog(LOG_NOTICE, LOG_MOD, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken ", u->nick, ve->name);
			break;
		case ACT_NOTHING:
			if (SecureServ.verbose) chanalert(s_SecureServ, "SecureServ warned %s about %s Bot/Trojan/Virus", u->nick, ve->name);
			nlog(LOG_NOTICE, LOG_MOD, "SecureServ warned %s about %s Bot/Trojan/Virus", u->nick, ve->name);
			break;
	}
	/* send an update to secure.irc-chat.net */
	if ((SecureServ.sendtosock > 0) && (SecureServ.report == 1)) {
		ircsnprintf(buf2, 3, "%c%c", SecureServ.updateuname[0], SecureServ.updateuname[1]);
		ircsnprintf(buf, 1400, "%s\n%s\n%s\n%s\n%s\n%d\n", SecureServ.updateuname, crypt(SecureServ.updatepw, buf2), ve->name, u->hostname, __module_info.module_version, SecureServ.viriversion);
		i = sendto(SecureServ.sendtosock, buf, strlen(buf), 0,  (struct sockaddr *) &SecureServ.sendtohost, sizeof(SecureServ.sendtohost));
	}	


}



int __ModInit(int modnum, int apiversion) {
	int i;
	
	if (apiversion < REQUIREDAPIVER) {
		nlog(LOG_CRITICAL, LOG_MOD, "Can't Load SecureServ. API Version MisMatch");
		return -1;
	}
	s_SecureServ = "SecureServ";
	SET_SEGV_INMODULE("SecureServ");
	
	/* init the exemptions list */
	exempt = list_create(MAX_EXEMPTS);
	/* init the virus lists */
	viri = list_create(MAX_VIRI);
	/* init the random nicks list */
	nicks = list_create(MAX_NICKS);
	/* init the channel tracking hash */
	ss_init_chan_hash();

	/* init the nickflood hash */
	nickflood = hash_create(-1, 0, 0);
	
	SecureServ.inited = 0;			
	SecureServ.helpcount = 0;
	SecureServ.doUpdate = 0;
	SecureServ.MaxAJPP = 0;
	SecureServ.updateurl[0] = 0;
	strlcpy(SecureServ.sampleversion, "Visual IRC 2.0rc5 (English) - Fast. Powerful. Free. http://www.visualirc.net/beta.php", SS_BUF_SIZE);
	
	for (i = 0; i > MAX_PATTERN_TYPES; i++) {
		SecureServ.trigcounts[i] = 0;
		SecureServ.actioncounts[i] = 0;
	}
	SecureServ.MaxAJPPChan[0] = 0;
	SecureServ.modnum = modnum;

	LoadTSConf();
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
			chanalert(s_SecureServ, "Permission Denied when trying to check Dat File Version:", myversion);
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
				chanalert(s_SecureServ, "No Valid Username/Password configured for update Checking. Aborting Update Check");
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

int AutoUpdate() 
{
	if ((SecureServ.autoupgrade > 0) && SecureServ.updateuname[0] != 0 && SecureServ.updatepw[0] != 0 ) {
		ircsnprintf(ss_buf, SS_BUF_SIZE, "http://%s%s?u=%s&p=%s", SecureServ.updateurl, DATFILEVER, SecureServ.updateuname, SecureServ.updatepw);
		http_request(ss_buf, 2, HFLAG_NONE, datver); 
	}
	return 0;
}	

void do_reload(User *u) 
{
	prefmsg(u->nick, s_SecureServ, "Reloading virus definition files");
    chanalert(s_SecureServ, "Reloading virus definition files at request of %s", u->nick);
	load_dat();
}
