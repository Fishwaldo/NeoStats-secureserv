/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2004 Adam Rutter, Justin Hammond, Mark Hetherington
** http://www.neostats.net/
**
**  This program is ns_free software; you can redistribute it and/or modify
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


#ifdef WIN32
#include "win32modconfig.h"
#else
#include "modconfig.h"
#endif

#include <stdio.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#include "neostats.h"
#include "SecureServ.h"

/* this is the size of the exempt list */
#define MAX_EXEMPTS	100

typedef struct exemptinfo {
	char host[MAXHOST];
	int server;
	char who[MAXNICK];
	char reason[MAXREASON];
}exemptinfo;

static char confbuf[CONFBUFSIZE];
static char ss_buf[SS_BUF_SIZE];
/* this is the list of exempted hosts/servers */
static list_t *exempt;

static void SS_load_exempts(void);

int SS_InitExempts(void)
{
	SET_SEGV_LOCATION();
	/* init the exemptions list */
	exempt = list_create(MAX_EXEMPTS);
	SS_load_exempts();
	return NS_SUCCESS;
}

static void SS_save_exempts() 
{
	lnode_t *node;
	exemptinfo *exempts = NULL;
	int i;

	SET_SEGV_LOCATION();
	node = list_first(exempt);
	i = 1;
	while (node) {
		exempts = lnode_get(node);
		dlog (DEBUG1, "Saving Exempt List %s", exempts->host);
		ircsnprintf(ss_buf, SS_BUF_SIZE, "Exempt/%s/Who", exempts->host);
		SetConf((void *)exempts->who, CFGSTR, ss_buf);
		ircsnprintf(ss_buf, SS_BUF_SIZE, "Exempt/%s/Reason", exempts->host);
		SetConf((void *)exempts->reason, CFGSTR, ss_buf);
		ircsnprintf(ss_buf, SS_BUF_SIZE, "Exempt/%s/Server", exempts->host);
		SetConf((void *)exempts->server, CFGINT, ss_buf);
		node = list_next(exempt, node);
	}
}

static void SS_load_exempts(void)
{
	exemptinfo *exempts = NULL;
	lnode_t *node;
	int i;
	char *tmp;
	char **data;

	SET_SEGV_LOCATION();
	if (GetDir("Exempt", &data) > 0) {
		/* try */
		for (i = 0; data[i] != NULL; i++) {
			exempts = ns_malloc (sizeof(exemptinfo));
			strlcpy(exempts->host, data[i], MAXHOST);
	
			ircsnprintf(confbuf, CONFBUFSIZE, "Exempt/%s/Who", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, confbuf) <= 0) {
				ns_free (exempts);
				continue;
			} else {
				strlcpy(exempts->who, tmp, MAXNICK);
				ns_free (tmp);
			}
			ircsnprintf(confbuf, CONFBUFSIZE, "Exempt/%s/Reason", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, confbuf) <= 0) {
				ns_free (exempts);
				continue;
			} else {
				strlcpy(exempts->reason, tmp, MAXREASON);
				ns_free (tmp);
			}
			ircsnprintf(confbuf, CONFBUFSIZE, "Exempt/%s/Server", data[i]);
			if (GetConf((void *)&exempts->server, CFGINT, confbuf) <= 0) {
				ns_free (exempts);
				continue;
			}			
			dlog (DEBUG2, "Adding %s (%d) Set by %s for %s to Exempt List", exempts->host, exempts->server, exempts->who, exempts->reason);
			node = lnode_create(exempts);
			list_prepend(exempt, node);			
		}
		ns_free (data);
	}
}

int SS_IsUserExempt(Client *u) 
{
	lnode_t *node;
	exemptinfo *exempts;

	SET_SEGV_LOCATION();
	if (!strcasecmp(u->uplink->name, me.name)) {
		dlog (DEBUG1, "SecureServ: User %s Exempt. its Me!", u->name);
		return NS_SUCCESS;
	}

	/* don't scan users from a server that is excluded */
	node = list_first(exempt);
	while (node) {
		exempts = lnode_get(node);
		if (exempts->server == 1) {
			/* match a server */
			if (match(exempts->host, u->uplink->name)) {
				dlog (DEBUG1, "User %s exempt. Matched server entry %s in Exemptions", u->name, exempts->host);
				return NS_SUCCESS;
			}
		} else if (exempts->server == 0) {
			/* match a hostname */
			if (match(exempts->host, u->user->hostname)) {
				dlog (DEBUG1, "SecureServ: User %s is exempt. Matched Host Entry %s in Exceptions", u->name, exempts->host);
				return NS_SUCCESS;
			}
		}				
		node = list_next(exempt, node);
	}
	return -1;
}

int SS_IsChanExempt(Channel *c) 
{
	lnode_t *node;
	exemptinfo *exempts;

	SET_SEGV_LOCATION();
	if (!strcasecmp(c->name, me.serviceschan)) {
		dlog (DEBUG1, "SecureServ: Channel %s Exempt. its Mine!", c->name);
		return NS_SUCCESS;
	}

	/* don't scan users from a server that is excluded */
	node = list_first(exempt);
	while (node) {
		exempts = lnode_get(node);
		if (exempts->server == 2) {
			/* match a channel */
			if (match(exempts->host, c->name)) {
				dlog (DEBUG1, "SecureServ: Channel %s exempt. Matched Channel entry %s in Exemptions", c->name, exempts->host);
				return NS_SUCCESS;
			}
		}				
		node = list_next(exempt, node);
	}
	return -1;
}

static int SS_do_exempt_list(CmdParams *cmdparams)
{
	lnode_t *node;
	exemptinfo *exempts = NULL;
	int i;

	SET_SEGV_LOCATION();
	node = list_first(exempt);
	i = 1;
	irc_prefmsg (ss_bot, cmdparams->source, "Exception List:");
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
		irc_prefmsg (ss_bot, cmdparams->source, "%d) %s (%s) Added by %s for %s", i, exempts->host, ss_buf, exempts->who, exempts->reason);
		++i;
		node = list_next(exempt, node);
	}
	irc_prefmsg (ss_bot, cmdparams->source, "End of List.");
	return NS_SUCCESS;
}

static int SS_do_exempt_add(CmdParams *cmdparams)
{
	char *buf;
	lnode_t *node;
	exemptinfo *exempts = NULL;

	SET_SEGV_LOCATION();
	if (cmdparams->ac < 6) {
		irc_prefmsg (ss_bot, cmdparams->source, "Syntax Error. /msg %s help exclude", ss_bot->name);
		return NS_SUCCESS;
	}
	if (list_isfull(exempt)) {
		irc_prefmsg (ss_bot, cmdparams->source, "Error, Exception list is full");
		return NS_SUCCESS;
	}
	if (atoi(cmdparams->av[2]) != 2) {
		if (!index(cmdparams->av[1], '.')) {
			irc_prefmsg (ss_bot, cmdparams->source, "Host field does not contain a vaild host"); 
			return NS_SUCCESS;
		}
	} else {
		if (!index(cmdparams->av[1], '#')) {
			irc_prefmsg (ss_bot, cmdparams->source, "Channel Field is not valid");
			return NS_SUCCESS;
		}
	}
	exempts = ns_malloc (sizeof(exemptinfo));
	strlcpy(exempts->host, cmdparams->av[1], MAXHOST);
	exempts->server = atoi(cmdparams->av[2]);
	strlcpy(exempts->who, cmdparams->source->name, MAXNICK);
	buf = joinbuf(cmdparams->av, cmdparams->ac, 3);
	strlcpy(exempts->reason, buf, MAXREASON);
	ns_free (buf);
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
	irc_prefmsg (ss_bot, cmdparams->source, "Added %s (%s) exception to list", exempts->host, ss_buf);
	irc_chanalert (ss_bot, "%s added %s (%s) exception to list", cmdparams->source->name, exempts->host, ss_buf);
	SS_save_exempts();
	return NS_SUCCESS;
}

static int SS_do_exempt_del(CmdParams *cmdparams)
{
	char *buf;
	lnode_t *node;
	exemptinfo *exempts = NULL;
	int i;

	SET_SEGV_LOCATION();
	if (cmdparams->ac < 4) {
		irc_prefmsg (ss_bot, cmdparams->source, "Syntax Error. /msg %s help exclude", ss_bot->name);
		return NS_SUCCESS;
	}
	if (atoi(cmdparams->av[1]) != 0) {
		node = list_first(exempt);
		i = 1;
		while (node) {
			if (i == atoi(cmdparams->av[1])) {
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
				irc_prefmsg (ss_bot, cmdparams->source, "Deleted %s %s out of exception list", exempts->host, ss_buf);
				irc_chanalert (ss_bot, "%s deleted %s %s out of exception list", cmdparams->source->name, exempts->host, ss_buf);
				buf = ns_malloc (CONFBUFSIZE);
				ircsnprintf(buf, CONFBUFSIZE, "Exempt/%s", exempts->host);
				DelConf(buf);
				ns_free (exempts);
				SS_save_exempts();
				return NS_SUCCESS;
			}
			++i;
			node = list_next(exempt, node);
		}		
		/* if we get here, then we can't find the entry */
		irc_prefmsg (ss_bot, cmdparams->source, "Error, Can't find entry %d. /msg %s exclude list", atoi(cmdparams->av[1]), ss_bot->name);
		return NS_SUCCESS;
	} else {
		irc_prefmsg (ss_bot, cmdparams->source, "Error, Out of Range");
		return NS_SUCCESS;
	}
	return NS_SUCCESS;
}

int SS_do_exempt(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	if (!strcasecmp(cmdparams->av[0], "LIST")) {
		SS_do_exempt_list(cmdparams);
		return NS_SUCCESS;
	} else if (!strcasecmp(cmdparams->av[0], "ADD")) {
		SS_do_exempt_add(cmdparams);
		return NS_SUCCESS;
	} else if (!strcasecmp(cmdparams->av[0], "DEL")) {
		SS_do_exempt_del(cmdparams);
		return NS_SUCCESS;
	}
    irc_prefmsg (ss_bot, cmdparams->source, "Syntax Error. /msg %s help exclude", ss_bot->name);
	return NS_SUCCESS;
}
