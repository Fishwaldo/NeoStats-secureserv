/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2004 Adam Rutter, Justin Hammond, Mark Hetherington
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
	NS_EXCLUDE type;
	char who[MAXNICK];
	char reason[MAXREASON];
}exemptinfo;

const char* ExcludeDesc[NS_EXCLUDE_MAX] = {
	"HostName",
	"Server",
	"Channel",
};

/* this is the list of exempted hosts/servers */
static list_t *exemptlist;

static void new_exempt (void *data)
{
	exemptinfo *exempts;

	exempts = malloc(sizeof(exemptinfo));
	os_memcpy (exempts, data, sizeof(exemptinfo));
	lnode_create_prepend(exemptlist, exempts);
	dlog (DEBUG2, "Adding %s (%d) Set by %s for %s to Exempt List", exempts->host, exempts->type, exempts->who, exempts->reason);
}

int SSInitExempts(void)
{
	SET_SEGV_LOCATION();
	/* init the exemptions list */
	exemptlist = list_create(MAX_EXEMPTS);
	DBAFetchRows ("Exempt", new_exempt);
	return NS_SUCCESS;
}

int SSIsUserExempt(Client *u) 
{
	lnode_t *node;
	exemptinfo *exempts;

	SET_SEGV_LOCATION();
	if (!strcasecmp(u->uplink->name, me.name)) {
		dlog (DEBUG1, "SecureServ: User %s Exempt. its Me!", u->name);
		return NS_TRUE;
	}
	/* don't scan users from a server that is excluded */
	node = list_first(exemptlist);
	while (node) {
		exempts = lnode_get(node);
		if (exempts->type == NS_EXCLUDE_SERVER) {
			/* match a server */
			if (match(exempts->host, u->uplink->name)) {
				dlog (DEBUG1, "User %s exempt. Matched server entry %s in Exemptions", u->name, exempts->host);
				return NS_TRUE;
			}
		} else if (exempts->type == NS_EXCLUDE_HOST) {
			/* match a hostname */
			if (match(exempts->host, u->user->hostname)) {
				dlog (DEBUG1, "SecureServ: User %s is exempt. Matched Host Entry %s in Exceptions", u->name, exempts->host);
				return NS_TRUE;
			}
		}				
		node = list_next(exemptlist, node);
	}
	return NS_FALSE;
}

int SSIsChanExempt(Channel *c) 
{
	lnode_t *node;
	exemptinfo *exempts;

	SET_SEGV_LOCATION();
	if (IsServicesChannel( c )) {
		dlog (DEBUG1, "Services channel %s is exempt.", c->name);
		return NS_TRUE;
	}
	/* don't scan users from a server that is excluded */
	node = list_first(exemptlist);
	while (node) {
		exempts = lnode_get(node);
		if (exempts->type == NS_EXCLUDE_CHANNEL) {
			/* match a channel */
			if (match(exempts->host, c->name)) {
				dlog (DEBUG1, "SecureServ: Channel %s exempt. Matched Channel entry %s in Exemptions", c->name, exempts->host);
				return NS_TRUE;
			}
		}				
		node = list_next(exemptlist, node);
	}
	return NS_FALSE;
}

static int ss_cmd_exempt_list(CmdParams *cmdparams)
{
	lnode_t *node;
	exemptinfo *exempts;

	SET_SEGV_LOCATION();
	node = list_first(exemptlist);
	irc_prefmsg (ss_bot, cmdparams->source, "Exception List:");
	while (node) {
		exempts = lnode_get(node);
		irc_prefmsg (ss_bot, cmdparams->source, "%s (%s) Added by %s for %s", exempts->host, ExcludeDesc[exempts->type], exempts->who, exempts->reason);
		node = list_next(exemptlist, node);
	}
	irc_prefmsg (ss_bot, cmdparams->source, "End of List.");
	return NS_SUCCESS;
}

static int ss_cmd_exempt_add(CmdParams *cmdparams)
{
	NS_EXCLUDE type;
	char *buf;
	exemptinfo *exempts;

	SET_SEGV_LOCATION();
	if (cmdparams->ac < 4) {
		return NS_ERR_NEED_MORE_PARAMS;
	}
	if (list_isfull(exemptlist)) {
		irc_prefmsg (ss_bot, cmdparams->source, "Error, Exception list is full");
		return NS_SUCCESS;
	}
	if (!ircstrcasecmp("HOST", cmdparams->av[1])) {
		if (!index(cmdparams->av[2], '.')) {
			irc_prefmsg (ss_bot, cmdparams->source, "Invalid host name");
			return NS_SUCCESS;
		}
		type = NS_EXCLUDE_HOST;
	} else if (!ircstrcasecmp("CHANNEL", cmdparams->av[1])) {
		if (cmdparams->av[2][0] != '#') {
			irc_prefmsg (ss_bot, cmdparams->source, "Invalid channel name");
			return NS_SUCCESS;
		}
		type = NS_EXCLUDE_CHANNEL;
	} else if (!ircstrcasecmp("SERVER", cmdparams->av[1])) {
		if (!index(cmdparams->av[2], '.')) {
			irc_prefmsg (ss_bot, cmdparams->source, "Invalid host name");
			return NS_SUCCESS;
		}
		type = NS_EXCLUDE_SERVER;
	} else {
		irc_prefmsg (ss_bot, cmdparams->source, "Invalid exclude type");
		return NS_SUCCESS;
	}
	exempts = ns_calloc (sizeof(exemptinfo));
	exempts->type = type;
	strlcpy(exempts->host, cmdparams->av[2], MAXHOST);
	strlcpy(exempts->who, cmdparams->source->name, MAXNICK);
	buf = joinbuf(cmdparams->av, cmdparams->ac, 3);
	strlcpy(exempts->reason, buf, MAXREASON);
	ns_free (buf);
	lnode_create_append (exemptlist, exempts);
	irc_prefmsg (ss_bot, cmdparams->source, "Added %s (%s) exception to list", exempts->host, ExcludeDesc[exempts->type]);
	irc_chanalert (ss_bot, "%s added %s (%s) exception to list", cmdparams->source->name, exempts->host, ExcludeDesc[exempts->type]);
	DBAStore ("Exempt", exempts->host, exempts, sizeof(exemptinfo));
	return NS_SUCCESS;
}

static int ss_cmd_exempt_del(CmdParams *cmdparams)
{
	lnode_t *node;
	exemptinfo *exempts = NULL;

	SET_SEGV_LOCATION();
	if (cmdparams->ac < 2) {
		return NS_ERR_NEED_MORE_PARAMS;
	}
	node = list_first(exemptlist);
	while (node) {
		exempts = lnode_get(node);
		if (ircstrcasecmp (cmdparams->av[1], exempts->host) == 0) {
			list_delete(exemptlist, node);
			irc_prefmsg (ss_bot, cmdparams->source, "Deleted %s %s out of exception list", exempts->host, ExcludeDesc[exempts->type]);
			irc_chanalert (ss_bot, "%s deleted %s %s out of exception list", cmdparams->source->name, exempts->host, ExcludeDesc[exempts->type]);
			DBADelete ("Exempt", exempts->host);
			ns_free (exempts);
			return NS_SUCCESS;
		}
		node = list_next(exemptlist, node);
	}		
	irc_prefmsg (ss_bot, cmdparams->source, "Error, Can't find entry %s.", cmdparams->av[1]);
	return NS_SUCCESS;
}

int ss_cmd_exempt(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	if (!strcasecmp(cmdparams->av[0], "LIST")) {
		return ss_cmd_exempt_list(cmdparams);
	} else if (!strcasecmp(cmdparams->av[0], "ADD")) {
		return ss_cmd_exempt_add(cmdparams);
	} else if (!strcasecmp(cmdparams->av[0], "DEL")) {
		return ss_cmd_exempt_del(cmdparams);
	}
	return NS_ERR_SYNTAX_ERROR;
}
