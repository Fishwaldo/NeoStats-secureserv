/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2004 Justin Hammond
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


#include <stdio.h>
#include "neostats.h"
#include "SecureServ.h"

static int HelpersAdd(CmdParams *cmdparams);
static int HelpersDel(CmdParams *cmdparams, char *nick);
static int HelpersList(CmdParams *cmdparams);


typedef struct SSHelpers{
	char nick[MAXNICK];
	char pass[MAXNICK];
	Client *u;
}SSHelpers;

static hash_t *helperhash;
static int IsHelpersInit = 0;
static char confpath[CONFBUFSIZE];

int HelpersInit(void) 
{
	char **data, *tmp;
	SSHelpers *helper;
	int i;
	hnode_t *node;
	
	SET_SEGV_LOCATION();
	helperhash = hash_create(-1, 0, 0);
	if (GetDir("Helper", &data) > 0) {
		for (i = 0; data[i] != NULL; i++) {	
			helper = ns_malloc (sizeof(SSHelpers));
			strlcpy(helper->nick, data[i], MAXNICK);
			ircsnprintf(confpath, CONFBUFSIZE, "Helper/%s/Pass", helper->nick);
			if (GetConf((void *)&tmp, CFGSTR, confpath) <= 0) {
				ns_free (helper);
			} else {
				strlcpy(helper->pass, tmp, MAXNICK);
				ns_free (tmp);
				helper->u = NULL;
				node = hnode_create(helper);
				hash_insert(helperhash, node, helper->nick);
			}
		}
		ns_free (data);
	}	
	IsHelpersInit = 1;
	return NS_SUCCESS;
}

static int HelpersAdd(CmdParams *cmdparams) 
{
	SSHelpers *helper;
	hnode_t *node;
	
	SET_SEGV_LOCATION();
	if (IsHelpersInit == 0) 
		return -1;
	
	if (cmdparams->ac < 5) {
		irc_prefmsg (ss_bot, cmdparams->source, "Invalid Syntax. /msg SecureServ help helpers");
		return -1;
	}
	if (hash_lookup(helperhash, cmdparams->av[1])) {
		irc_prefmsg (ss_bot, cmdparams->source, "A Helper with login %s already exists", cmdparams->av[1]);
		return -1;
	}

	helper = ns_malloc (sizeof(SSHelpers));
	strlcpy(helper->nick, cmdparams->av[1], MAXNICK);
	strlcpy(helper->pass, cmdparams->av[2], MAXNICK);
	helper->u = NULL;
	node = hnode_create(helper);
 	hash_insert(helperhash, node, helper->nick);

	/* ok, now save the helper */
	ircsnprintf(confpath, CONFBUFSIZE, "Helper/%s/Pass", helper->nick);
	SetConf((void *)helper->pass, CFGSTR, confpath);

	irc_prefmsg (ss_bot, cmdparams->source, "Successfully added Helper %s with Password %s to Helpers List", helper->nick, helper->pass);
	return NS_SUCCESS;
}

static int HelpersDel(CmdParams *cmdparams, char *nick) 
{
	hnode_t *node;

	SET_SEGV_LOCATION();
	if (IsHelpersInit == 0) 
		return -1;
	
	node = hash_lookup(helperhash, nick);
	if (node) {
		hash_delete(helperhash, node);
		ns_free (hnode_get(node));
		hnode_destroy(node);
		ircsnprintf(confpath, CONFBUFSIZE, "Helper/%s", nick);
		DelConf(confpath);
		irc_prefmsg (ss_bot, cmdparams->source, "Deleted %s from Helpers List", nick);
	} else {
		irc_prefmsg (ss_bot, cmdparams->source, "Error, Could not find %s in helpers list. /msg %s helpers list", nick, ss_bot->name);
	}
	return NS_SUCCESS;
}

static int HelpersList(CmdParams *cmdparams) 
{
	hscan_t hlps;
	hnode_t *node;
	SSHelpers *helper;

	SET_SEGV_LOCATION();
	if (IsHelpersInit == 0) 
		return -1;
	
	irc_prefmsg (ss_bot, cmdparams->source, "Helpers List (%d):", (int)hash_count(helperhash));
	hash_scan_begin(&hlps, helperhash);
	while ((node = hash_scan_next(&hlps)) != NULL) {
		helper = hnode_get(node);
		irc_prefmsg (ss_bot, cmdparams->source, "%s (%s)", helper->nick, helper->u ? helper->u->name : "Not Logged In");
	}
	irc_prefmsg (ss_bot, cmdparams->source, "End of List.");	
	return -1;
}

int HelpersChpass(CmdParams *cmdparams) 
{
	hnode_t *node;
	SSHelpers *helper;
	hscan_t hlps;

	SET_SEGV_LOCATION();

	if (IsHelpersInit == 0) 
		return -1;

	hash_scan_begin(&hlps, helperhash);
	while ((node = hash_scan_next(&hlps)) != NULL) {
		helper = hnode_get(node);
		if (helper->u == cmdparams->source) {
			strlcpy(helper->pass, cmdparams->av[0], MAXNICK);
			ircsnprintf(confpath, CONFBUFSIZE, "Helper/%s/Pass", helper->nick);
			SetConf((void *)helper->pass, CFGSTR, confpath);
			irc_prefmsg (ss_bot, cmdparams->source, "Successfully Changed your Password");
			irc_chanalert (ss_bot, "%s changed their helper password", cmdparams->source);
			return NS_SUCCESS;
		}
	}
	irc_prefmsg (ss_bot, cmdparams->source, "You must be logged in to change your Helper Password");
	return NS_SUCCESS;
}

int HelpersLogin(CmdParams *cmdparams) 
{
	hnode_t *node;
	SSHelpers *helper;
	hscan_t hlps;
	UserDetail *ud;

	SET_SEGV_LOCATION();

	if (IsHelpersInit == 0) 
		return -1;

	hash_scan_begin(&hlps, helperhash);
	while ((node = hash_scan_next(&hlps)) != NULL) {
		helper = hnode_get(node);
		if (helper->u == cmdparams->source) {
			irc_prefmsg (ss_bot, cmdparams->source, "You are already logged in account %s", helper->nick);
			return NS_SUCCESS;
		}			
	}

	node = hash_lookup(helperhash, cmdparams->av[0]);
	if (node) {
		helper = hnode_get(node);
		if (!strcasecmp(helper->pass, cmdparams->av[1])) {
			helper->u = cmdparams->source;
			ud = ns_malloc (sizeof(UserDetail));
			ud->type = USER_HELPER;
			ud->data = (void *) helper;
			SetUserModValue (cmdparams->source, (void *)ud);
			irc_prefmsg (ss_bot, cmdparams->source, "Login Successful");
			irc_chanalert (ss_bot, "%s Successfully Logged in", cmdparams->source);
			if ((SecureServ.joinhelpchan == 1) && (IsChannelMember(find_channel(SecureServ.HelpChan), ss_bot->u) != 1)) {
				irc_join (ss_bot, SecureServ.HelpChan, "+a");//CUMODE_CHANADMIN);
			}
			if (IsChannelMember(find_channel(SecureServ.HelpChan), cmdparams->source) != 1) {
				irc_prefmsg (ss_bot, cmdparams->source, "Joining you to the Help Channel");
				irc_svsjoin (ss_bot, cmdparams->source, SecureServ.HelpChan);
			}
				                
			SecureServ.helpcount++;
			return NS_SUCCESS;
		}
		irc_prefmsg (ss_bot, cmdparams->source, "Login Failed");
		irc_chanalert (ss_bot, "%s tried to login with %s, but got the pass wrong (%s)", cmdparams->source, cmdparams->av[0], cmdparams->av[1]);
		return -1;
	} 
	irc_prefmsg (ss_bot, cmdparams->source, "Login Failed");
	irc_chanalert (ss_bot, "%s tried to login with %s but that account does not exist", cmdparams->source, cmdparams->av[0]);
	return -1;
}

int HelpersLogout(CmdParams *cmdparams)
{
	UserDetail *ud;
	hscan_t hlps;
	hnode_t *node;
	SSHelpers *helper;
	
	SET_SEGV_LOCATION();
	if (IsHelpersInit == 0) 
		return -1;

	hash_scan_begin(&hlps, helperhash);
	while ((node = hash_scan_next(&hlps)) != NULL) {
		helper = hnode_get(node);
		if (helper->u == cmdparams->source) {
			irc_prefmsg (ss_bot, cmdparams->source, "You have been logged out of %s", helper->nick);
			irc_chanalert (ss_bot, "%s logged out of account %s", cmdparams->source, helper->nick);
			helper->u = NULL;
			ud = (UserDetail *)GetUserModValue (cmdparams->source);
			if (ud) {
				ns_free (ud);
			}
			SecureServ.helpcount--;
			if (SecureServ.helpcount < 0) {
				SecureServ.helpcount = 0;
			}
			if ((SecureServ.helpcount == 0) && (IsChannelMember(find_channel(SecureServ.HelpChan), ss_bot->u) == 1)) {
				irc_part (ss_bot, SecureServ.HelpChan);
			}
			return NS_SUCCESS;
		}			
	}
	irc_prefmsg (ss_bot, cmdparams->source, "Error, You do not appear to be logged in");
	return -1;
}

int HelpersSignoff(CmdParams *cmdparams) 
{
	UserDetail *ud;
	hscan_t hlps;
	hnode_t *node;
	SSHelpers *helper;
	
	SET_SEGV_LOCATION();
	if (IsHelpersInit == 0) 
		return -1;

	hash_scan_begin(&hlps, helperhash);
	while ((node = hash_scan_next(&hlps)) != NULL) {
		helper = hnode_get(node);
		if (helper->u == cmdparams->source) {
			irc_chanalert (ss_bot, "%s logged out of account %s after he quit", cmdparams->source, helper->nick);
			helper->u = NULL;
			ud = (UserDetail *)GetUserModValue (cmdparams->source);
			if (ud) {
				ns_free (ud);
			}
			SecureServ.helpcount--;
			if (SecureServ.helpcount < 0) {
				SecureServ.helpcount = 0;
			}
			if ((SecureServ.helpcount == 0) && (IsChannelMember(find_channel(SecureServ.HelpChan), ss_bot->u) == 1)) {
				irc_part (ss_bot, SecureServ.HelpChan);
			}
			return NS_SUCCESS;
		}			
	}
	return -1;
}

int HelpersAway(CmdParams *cmdparams) 
{
	UserDetail *ud;
	hscan_t hlps;
	hnode_t *node;
	SSHelpers *helper;

	SET_SEGV_LOCATION();
	if (IsHelpersInit == 0) 
		return -1;

	if (SecureServ.signoutaway != 1) {
		return NS_SUCCESS;
	}
	hash_scan_begin(&hlps, helperhash);
	while ((node = hash_scan_next(&hlps)) != NULL) {
		helper = hnode_get(node);
		if ((helper->u == cmdparams->source) && (cmdparams->source->user->is_away == 1)) {
			irc_chanalert (ss_bot, "%s logged out of account %s after set away", cmdparams->source, helper->nick);
			irc_prefmsg (ss_bot, cmdparams->source, "You have been logged out of SecureServ");
			helper->u = NULL;
			ud = (UserDetail *)GetUserModValue (cmdparams->source);
			if (ud) {
				ns_free (ud);
			}
			SecureServ.helpcount--;
			if (SecureServ.helpcount < 0) {
				SecureServ.helpcount = 0;
			}
			if ((SecureServ.helpcount == 0) && (IsChannelMember(find_channel(SecureServ.HelpChan), ss_bot->u) == 1)) {
				irc_part (ss_bot, SecureServ.HelpChan);
			}
			return NS_SUCCESS;
		}			
	}
	return -1;
}

int HelpersAssist(CmdParams *cmdparams) 
{
	UserDetail *ud, *td;
	Client *tu;
	virientry *ve;

	SET_SEGV_LOCATION();

	if (IsHelpersInit == 0) 
		return -1;

	if (GetUserModValue (cmdparams->source) == NULL) {
		irc_prefmsg (ss_bot, cmdparams->source, "Access Denied");
		irc_chanalert (ss_bot, "%s tried to use assist %s on %s, but is not logged in", cmdparams->source, cmdparams->av[0], cmdparams->av[1]);
		return -1;
	}
	ud = (UserDetail *)GetUserModValue (cmdparams->source);
	if (ud->type != USER_HELPER) {
		irc_prefmsg (ss_bot, cmdparams->source, "Access Denied");
		irc_chanalert (ss_bot, "%s tried to use assist %s on %s, but is not logged in", cmdparams->source, cmdparams->av[0], cmdparams->av[1]);
		return -1;
	}
	/* if we get here, they are ok, so check the target user*/
	tu = find_user(cmdparams->av[1]);
	if (!tu) /* User not found */
		return NS_SUCCESS;

	if (GetUserModValue (tu) == NULL) {
		irc_prefmsg (ss_bot, cmdparams->source, "Invalid User %s. Not Recorded as requiring assistance", tu->name);
		irc_chanalert (ss_bot, "%s tried to use assist %s on %s, but the target is not requiring assistance", cmdparams->source, cmdparams->av[0], cmdparams->av[1]);
		return -1;
	}
	td = GetUserModValue (tu);
	if (td->type != USER_INFECTED) {
		irc_prefmsg (ss_bot, cmdparams->source, "Invalid User %s. Not Recorded as requiring assistance", tu->name);
		irc_chanalert (ss_bot, "%s tried to use assist %s on %s, but the target is not requiring assistance", cmdparams->source, cmdparams->av[0], cmdparams->av[1]);
		return -1;
	}

	/* ok, so far so good, lets see what the helper wants to do with the target user */
	if (!strcasecmp(cmdparams->av[0], "RELEASE")) {
		ClearUserModValue (tu);
		td->data = NULL;
		ns_free (td);
		irc_prefmsg (ss_bot, cmdparams->source,  "Hold on %s is released", tu->name);
		irc_chanalert (ss_bot, "%s released %s", cmdparams->source, tu->name);
		return -1;
	} else if (!strcasecmp(cmdparams->av[0], "KILL")) {
		ve = (virientry *)td->data;
		irc_prefmsg (ss_bot, cmdparams->source, "Akilling %s as they are infected with %s", tu->name, ve->name);	
		irc_chanalert (ss_bot, "%s used assist kill on %s!%s@%s (infected with %s)", cmdparams->source, tu->name, tu->user->username, tu->user->hostname, ve->name);
		nlog (LOG_NORMAL, "%s used assist kill on %s!%s@%s (infected with %s)", cmdparams->source, tu->name, tu->user->username, tu->user->hostname, ve->name);
		if(ve->iscustom) {
			irc_globops (ss_bot, "Akilling %s for Virus %s (Helper %s performed Assist Kill)", tu->name, ve->name, cmdparams->source);
			irc_akill (ss_bot, tu->user->hostname, tu->user->username, SecureServ.akilltime, "Infected with Virus/Trojan %s. (HelperAssist by %s)", ve->name, cmdparams->source);
		}
		else {
			irc_globops (ss_bot, "Akilling %s for Virus %s (Helper %s performed Assist Kill) (http://secure.irc-chat.net/info.php?viri=%s)", tu->name, ve->name, cmdparams->source, ve->name);
			irc_akill (ss_bot, tu->user->hostname, tu->user->username, SecureServ.akilltime, "Infected with Virus/Trojan. Visit http://secure.irc-chat.net/info.php?viri=%s (HelperAssist by %s)", ve->name, cmdparams->source);
		}
		return NS_SUCCESS;
	} else {
		irc_prefmsg (ss_bot, cmdparams->source, "Invalid Syntax. /msg %s help assist", ss_bot->name);
		return -1;
	}		
}	

int do_helpers(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	if (UserLevel(cmdparams->source) < NS_ULEVEL_ADMIN) {
		irc_prefmsg (ss_bot, cmdparams->source, "Permission Denied");
		irc_chanalert (ss_bot, "%s tried to use Helpers, but Permission was denied", cmdparams->source);
		return -1;
	}			
	if (!strcasecmp(cmdparams->av[0], "add")) {
		HelpersAdd(cmdparams);
		return NS_SUCCESS;
	} else if (!strcasecmp(cmdparams->av[0], "del")) {
		if (cmdparams->ac == 4) {
			HelpersDel(cmdparams, cmdparams->av[1]);
			return NS_SUCCESS;
		} else {
			irc_prefmsg (ss_bot, cmdparams->source, "Invalid Syntax. /msg %s help helpers for more info", ss_bot->name);
			return -1;
		}
	} else if (!strcasecmp(cmdparams->av[0], "list")) {
		HelpersList(cmdparams);
		return NS_SUCCESS;
	} else {
		irc_prefmsg (ss_bot, cmdparams->source, "Invalid Syntax. /msg %s help helpers for more info", ss_bot->name);
		return -1;
	}
	return NS_SUCCESS;
}
