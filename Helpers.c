/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2005 Adam Rutter, Justin Hammond, Mark Hetherington
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

#include "neostats.h"
#include "SecureServ.h"

typedef struct Helper{
	char nick[MAXNICK];
	char pass[MAXNICK];
	Client *u;
}Helper;

static hash_t *helperhash;

static bot_cmd helper_commands[]=
{
	{"LOGIN",	ss_cmd_login,	2,	0,				ts_help_login,		ts_help_login_oneline},
 	{"LOGOUT",	ss_cmd_logout,	0,	30,				ts_help_logout,		ts_help_logout_oneline},
	{"CHPASS",	ss_cmd_chpass,	1,	30,				ts_help_chpass,		ts_help_chpass_oneline},
	{"ASSIST",	ss_cmd_assist,	2,	30,				ts_help_assist,		ts_help_assist_oneline},
	{"HELPERS",	ss_cmd_helpers,	1,	NS_ULEVEL_OPER, ts_help_helpers,	ts_help_helpers_oneline},
	{NULL,		NULL,			0, 	0,				NULL, 				NULL}
};

static bot_setting helper_settings[]=
{
	{"NOHELPMSG",	&SecureServ.nohelp,		SET_TYPE_MSG,		0,	BUFSIZE,	NS_ULEVEL_ADMIN,"NoHelpMsg",	NULL,	ts_help_set_nohelpmsg, NULL, (void *)"No Helpers are online at the moment, so you have been Akilled from this network. Please visit http://www.nohack.org for Trojan/Virus Info" },
	{"AUTOSIGNOUT",	&SecureServ.signoutaway,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoAwaySignOut",NULL,	ts_help_set_autosignout, NULL, (void *)1 },
	{"JOINHELPCHAN",&SecureServ.joinhelpchan,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoJoinHelpChan",NULL,	ts_help_set_joinhelpchan, NULL, (void *)1 },
	{NULL,			NULL,					0,					0,	0, 			0,				NULL,			NULL,	NULL, NULL },
};

void HelpersStatus (CmdParams *cmdparams)
{
	irc_prefmsg (ss_bot, cmdparams->source, "AV Channel Helpers Logged in: %d", SecureServ.helpcount);
}

int LoadHelper (void *data)
{
	Helper *helper;

	helper = ns_malloc (sizeof(Helper));
	os_memcpy (helper, data, sizeof(Helper));
	helper->u = NULL;
	hnode_create_insert (helperhash, helper, helper->nick);
	return NS_FALSE;
}

int InitHelpers(void) 
{
	SET_SEGV_LOCATION();
	helperhash = hash_create(-1, 0, 0);
	DBAFetchRows ("helpers", LoadHelper);
	if (SecureServ.helpers == 1) {
		add_bot_cmd_list (ss_bot, helper_commands);
	}
	return NS_SUCCESS;
}

void FiniHelpers(void) 
{
	hscan_t hlps;
	hnode_t *node;
	Helper *helper;

	SET_SEGV_LOCATION();
	if (helperhash) {
		hash_scan_begin(&hlps, helperhash);
		while ((node = hash_scan_next(&hlps)) != NULL) {
			helper = hnode_get(node);
			ClearUserModValue (helper->u);
			hash_delete (helperhash, node);
			hnode_destroy (node);
			ns_free (helper);
		}
		hash_destroy(helperhash);
	}
}

static int HelperLogout (CmdParams *cmdparams)
{
	UserDetail *ud;
	Helper *helper;
	
	SET_SEGV_LOCATION();
	ud = (UserDetail *)GetUserModValue (cmdparams->source);
	if (ud && ud->type == USER_HELPER) {
		helper = (Helper *)ud->data;
		helper->u = NULL;
		ns_free (ud);
		ClearUserModValue (cmdparams->source);
		if (SecureServ.helpcount > 0)
			SecureServ.helpcount--;
		if ((SecureServ.helpcount == 0) && (IsChannelMember(FindChannel(SecureServ.HelpChan), ss_bot->u) == 1)) {
			irc_part( ss_bot, SecureServ.HelpChan, NULL );
		}
		return NS_SUCCESS;
	}
	return NS_FAILURE;
}

int ss_cmd_chpass(CmdParams *cmdparams) 
{
	UserDetail *ud;
	Helper *helper;

	SET_SEGV_LOCATION();
	ud = (UserDetail *)GetUserModValue (cmdparams->source);
	if (ud && ud->type == USER_HELPER) {
		helper = (Helper *)ud->data;
		strlcpy(helper->pass, cmdparams->av[0], MAXNICK);
		DBAStore ("helpers", helper->nick, (void *)helper, sizeof (Helper));
		irc_prefmsg (ss_bot, cmdparams->source, "Successfully changed your password");
		irc_chanalert (ss_bot, "%s changed their helper password", cmdparams->source);
		return NS_SUCCESS;
	}
	irc_prefmsg (ss_bot, cmdparams->source, "You must be logged in to change your Helper Password");
	return NS_SUCCESS;
}

int ss_cmd_login(CmdParams *cmdparams) 
{
	Helper *helper;
	UserDetail *ud;

	SET_SEGV_LOCATION();
	ud = (UserDetail *)GetUserModValue (cmdparams->source);
	if (ud && ud->type == USER_HELPER) {
		irc_prefmsg (ss_bot, cmdparams->source, "You are already logged in");
		return NS_SUCCESS;
	}
	helper = (Helper *)hnode_find (helperhash, cmdparams->av[0]);
	if (helper) {
		if (!ircstrcasecmp(helper->pass, cmdparams->av[1])) {
			Channel* c;

			c = FindChannel(SecureServ.HelpChan);
			helper->u = cmdparams->source;
			ud = ns_malloc (sizeof(UserDetail));
			ud->type = USER_HELPER;
			ud->data = (void *) helper;
			SetUserModValue (cmdparams->source, (void *)ud);
			irc_prefmsg (ss_bot, cmdparams->source, "Login Successful");
			irc_chanalert (ss_bot, "%s logged in as a helper", cmdparams->source->name);
			if ((SecureServ.joinhelpchan == 1) && (IsChannelMember(c, ss_bot->u) != 1)) {
				irc_join (ss_bot, SecureServ.HelpChan, "+a");//CUMODE_CHANADMIN);
			}
			if (IsChannelMember(c, cmdparams->source) != 1) {
				irc_prefmsg (ss_bot, cmdparams->source, "Joining you to the Help Channel");
				irc_svsjoin (ss_bot, cmdparams->source, SecureServ.HelpChan);
			}				                
			SecureServ.helpcount++;
			return NS_SUCCESS;
		}
		irc_prefmsg (ss_bot, cmdparams->source, "Login Failed");
		irc_chanalert (ss_bot, "%s tried to login with %s, but got the pass wrong (%s)", cmdparams->source, cmdparams->av[0], cmdparams->av[1]);
		return NS_SUCCESS;
	} 
	irc_prefmsg (ss_bot, cmdparams->source, "Login Failed");
	irc_chanalert (ss_bot, "%s tried to login with %s but that account does not exist", cmdparams->source, cmdparams->av[0]);
	return NS_SUCCESS;
}

int ss_cmd_logout(CmdParams *cmdparams)
{
	if (HelperLogout (cmdparams) == NS_SUCCESS)
	{
		irc_chanalert (ss_bot, "%s logged out from helper system", cmdparams->source->name);
		irc_prefmsg (ss_bot, cmdparams->source, "You are now logged out");
	}
	else
	{
		irc_prefmsg (ss_bot, cmdparams->source, "Error, You do not appear to be logged in");
	}
	return NS_SUCCESS;
}

int ss_cmd_assist(CmdParams *cmdparams) 
{
	UserDetail *ud, *td;
	Client *tu;
	virientry *ve;

	SET_SEGV_LOCATION();
	ud = (UserDetail *)GetUserModValue (cmdparams->source);
	if (!ud || ud->type != USER_HELPER) {
		irc_prefmsg (ss_bot, cmdparams->source, "Access Denied");
		irc_chanalert (ss_bot, "%s tried to use assist %s on %s, but is not logged in", cmdparams->source->name, cmdparams->av[0], cmdparams->av[1]);
		return NS_SUCCESS;
	}
	/* if we get here, they are ok, so check the target user*/
	tu = FindUser(cmdparams->av[1]);
	if (!tu) /* User not found */
		return NS_SUCCESS;
	td = GetUserModValue (tu);
	if (!td || td->type != USER_INFECTED) {
		irc_prefmsg (ss_bot, cmdparams->source, "Invalid User %s. Not Recorded as requiring assistance", tu->name);
		irc_chanalert (ss_bot, "%s tried to use assist %s on %s, but the target is not requiring assistance", cmdparams->source, cmdparams->av[0], cmdparams->av[1]);
		return NS_SUCCESS;
	}
	/* ok, so far so good, lets see what the helper wants to do with the target user */
	if (!ircstrcasecmp(cmdparams->av[0], "RELEASE")) {
		ClearUserModValue (tu);
		td->data = NULL;
		ns_free (td);
		irc_prefmsg (ss_bot, cmdparams->source,  "Hold on %s is released", tu->name);
		irc_chanalert (ss_bot, "%s released %s", cmdparams->source, tu->name);
		return NS_SUCCESS;
	} else if (!ircstrcasecmp(cmdparams->av[0], "KILL")) {
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
	}
	return NS_ERR_SYNTAX_ERROR;
}	

static int ss_cmd_helpers_add(CmdParams *cmdparams) 
{
	Helper *helper;
	hnode_t *node;
	
	SET_SEGV_LOCATION();
	if (cmdparams->ac < 3) {
		return NS_ERR_NEED_MORE_PARAMS;
	}
	if (hash_lookup(helperhash, cmdparams->av[1])) {
		irc_prefmsg (ss_bot, cmdparams->source, "A Helper with login %s already exists", cmdparams->av[1]);
		return NS_SUCCESS;
	}
	helper = ns_malloc (sizeof(Helper));
	strlcpy(helper->nick, cmdparams->av[1], MAXNICK);
	strlcpy(helper->pass, cmdparams->av[2], MAXNICK);
	helper->u = NULL;
	node = hnode_create(helper);
 	hash_insert(helperhash, node, helper->nick);

	/* ok, now save the helper */
	DBAStore ("helpers", helper->nick, (void *)helper, sizeof (Helper));
	irc_prefmsg (ss_bot, cmdparams->source, "Successfully added Helper %s with Password %s to Helpers List", helper->nick, helper->pass);
	return NS_SUCCESS;
}

static int ss_cmd_helpers_del(CmdParams *cmdparams) 
{
	hnode_t *node;

	SET_SEGV_LOCATION();
	if (cmdparams->ac < 2) {
		return NS_ERR_NEED_MORE_PARAMS;
	}
	node = hash_lookup(helperhash, cmdparams->av[1]);
	if (node) {
		hash_delete(helperhash, node);
		ns_free (hnode_get(node));
		hnode_destroy(node);
		DBADelete ("helpers", cmdparams->av[1]);
		irc_prefmsg (ss_bot, cmdparams->source, "Deleted %s from Helpers List", cmdparams->av[1]);
	} else {
		irc_prefmsg (ss_bot, cmdparams->source, "Error, Could not find %s in helpers list. /msg %s helpers list", cmdparams->av[1], ss_bot->name);
	}
	return NS_SUCCESS;
}

static int ss_cmd_helpers_list(CmdParams *cmdparams) 
{
	hscan_t hlps;
	hnode_t *node;
	Helper *helper;

	SET_SEGV_LOCATION();
	irc_prefmsg (ss_bot, cmdparams->source, "Helpers List (%d):", (int)hash_count(helperhash));
	hash_scan_begin(&hlps, helperhash);
	while ((node = hash_scan_next(&hlps)) != NULL) {
		helper = hnode_get(node);
		irc_prefmsg (ss_bot, cmdparams->source, "%s (%s)", helper->nick, helper->u ? helper->u->name : "Not Logged In");
	}
	irc_prefmsg (ss_bot, cmdparams->source, "End of List.");	
	return NS_SUCCESS;
}

int ss_cmd_helpers(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	if (UserLevel(cmdparams->source) < NS_ULEVEL_ADMIN) {
		return NS_ERR_NO_PERMISSION;
	}			
	if (!ircstrcasecmp(cmdparams->av[0], "ADD")) {
		return ss_cmd_helpers_add(cmdparams);
	} else if (!ircstrcasecmp(cmdparams->av[0], "DEL")) {
		return ss_cmd_helpers_del(cmdparams);
	} else if (!ircstrcasecmp(cmdparams->av[0], "LIST")) {
		return ss_cmd_helpers_list(cmdparams);
	}
	return NS_ERR_SYNTAX_ERROR;
}

int HelpersSignoff(CmdParams *cmdparams) 
{
	if (SecureServ.helpers != 1) {
		return NS_SUCCESS;
	}
	if (HelperLogout(cmdparams) == NS_SUCCESS)
	{
		irc_chanalert (ss_bot, "%s logged out for quit", cmdparams->source->name);
	}
	return NS_SUCCESS;
}

int HelpersAway(CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	if (SecureServ.helpers != 1) {
		return NS_SUCCESS;
	}
	if (SecureServ.signoutaway != 1) {
		return NS_SUCCESS;
	}
	if (HelperLogout(cmdparams) == NS_SUCCESS)
	{
		irc_chanalert (ss_bot, "%s logged out after set away", cmdparams->source->name);
		irc_prefmsg (ss_bot, cmdparams->source, "You have been logged out of SecureServ");
	}
	return NS_SUCCESS;
}

int ss_cmd_set_helpers_cb(CmdParams *cmdparams, SET_REASON reason) 
{
	if (reason == SET_LOAD || reason == SET_LIST) {
		return NS_SUCCESS;
	}
	if (SecureServ.helpers == 1) {
		add_bot_cmd_list (ss_bot, helper_commands);
		add_bot_setting_list (ss_bot, helper_settings);
	} else {
		del_bot_cmd_list (ss_bot, helper_commands);
		del_bot_setting_list (ss_bot, helper_settings);
	}
	return NS_SUCCESS;
}
