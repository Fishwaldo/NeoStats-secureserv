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

static char confbuf[CONFBUFSIZE];

void save_exempts() 
{
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

void load_exempts()
{
	exemptinfo *exempts = NULL;
	lnode_t *node;
	int i;
	char *tmp;
	char **data;

	if (GetDir("Exempt", &data) > 0) {
		/* try */
		for (i = 0; data[i] != NULL; i++) {
			exempts = malloc(sizeof(exemptinfo));
			strlcpy(exempts->host, data[i], MAXHOST);
	
			ircsnprintf(confbuf, CONFBUFSIZE, "Exempt/%s/Who", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, confbuf) <= 0) {
				free(exempts);
				continue;
			} else {
				strlcpy(exempts->who, tmp, MAXNICK);
				free(tmp);
			}
			ircsnprintf(confbuf, CONFBUFSIZE, "Exempt/%s/Reason", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, confbuf) <= 0) {
				free(exempts);
				continue;
			} else {
				strlcpy(exempts->reason, tmp, MAXREASON);
				free(tmp);
			}
			ircsnprintf(confbuf, CONFBUFSIZE, "Exempt/%s/Server", data[i]);
			if (GetConf((void *)&exempts->server, CFGINT, confbuf) <= 0) {
				free(exempts);
				continue;
			}			
			nlog(LOG_DEBUG2, LOG_MOD, "Adding %s (%d) Set by %s for %s to Exempt List", exempts->host, exempts->server, exempts->who, exempts->reason);
			node = lnode_create(exempts);
			list_prepend(exempt, node);			
		}
		free(data);
	}
}

int IsUserExempt(User *u) 
{
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
				nlog(LOG_DEBUG1, LOG_MOD, "User %s exempt. Matched server entry %s in Exemptions", u->nick, exempts->host);
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

int IsChanExempt(Chans *c) 
{
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

void do_exempt_list(User* u, char **argv, int argc)
{
	lnode_t *node;
	exemptinfo *exempts = NULL;

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
}

void do_exempt_add(User* u, char **argv, int argc)
{
	lnode_t *node;
	exemptinfo *exempts = NULL;

	if (argc < 6) {
		prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help exclude", s_SecureServ);
		return 0;
	}
	if (list_isfull(exempt)) {
		prefmsg(u->nick, s_SecureServ, "Error, Exception list is full");
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
	strlcpy(exempts->reason, buf, MAXREASON);
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
}

void do_exempt_del(User* u, char **argv, int argc)
{
	lnode_t *node;
	exemptinfo *exempts = NULL;

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
				buf = malloc(CONFBUFSIZE);
				ircsnprintf(buf, CONFBUFSIZE, "Exempt/%s", exempts->host);
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
}

int do_exempt(User* u, char **argv, int argc)
{
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
		do_exempt_list(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[2], "ADD")) {
		do_exempt_add(u, argv, argc);
		return 1;
	} else if (!strcasecmp(argv[2], "DEL")) {
		do_exempt_del(u, argv, argc);
		return 1;
	}
    prefmsg(u->nick, s_SecureServ, "Syntax Error. /msg %s help exclude", s_SecureServ);
	return 0;
}