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

static int ss_event_signon (CmdParams *cmdparams);
static int ss_event_versionreply (CmdParams *cmdparams);
static int ss_cmd_status (CmdParams *cmdparams);
static int ss_event_nick (CmdParams *cmdparams);
static int ss_event_quit (CmdParams *cmdparams);
static int ss_cmd_viriversion (CmdParams *cmdparams);

static int do_set_treatchanmsgaspm (CmdParams *cmdparams, SET_REASON reason);
static int do_set_monchancycletime (CmdParams *cmdparams, SET_REASON reason);
static int do_set_cycletime (CmdParams *cmdparams, SET_REASON reason);
static int do_set_autoupdate (CmdParams *cmdparams, SET_REASON reason);
static int do_set_updateinfo (CmdParams *cmdparams, SET_REASON reason);

Bot *ss_bot;

/** about info */
const char *ss_about[] = {
	"A Trojan Scanning Bot",
	NULL
};

const char *ss_copyright[] = {
	"Copyright (c) 1999-2004, NeoStats",
	"http://www.neostats.net/",
	NULL
};

/** Module Info definition 
 * version information about our module
 * This structure is required for your module to load and run on NeoStats
 */
ModuleInfo module_info = {
	"SecureServ",
	"A Trojan Scanning Bot",
	ss_copyright,
	ss_about,
	NEOSTATS_VERSION,
	MODULE_VERSION,
	__DATE__,
	__TIME__,
	0,
	0,
};

static bot_cmd ss_commands[]=
{
	{"LOGIN",	ss_cmd_login,		2,	0,				ts_help_login,		ts_help_login_oneline},
 	{"LOGOUT",	ss_cmd_logout,		0,	30,				ts_help_logout,		ts_help_logout_oneline},
	{"CHPASS",	ss_cmd_chpass,		1,	30,				ts_help_chpass,		ts_help_chpass_oneline},
	{"ASSIST",	ss_cmd_assist,		2,	30,				ts_help_assist,		ts_help_assist_oneline},
	{"HELPERS",	ss_cmd_helpers,		1,	NS_ULEVEL_OPER, ts_help_helpers,	ts_help_helpers_oneline},
	{"LIST",	ss_cmd_list,		0,	NS_ULEVEL_OPER, ts_help_list,		ts_help_list_oneline},
	{"EXCLUDE",	ss_cmd_exempt,		1,	50,				ts_help_exclude,	ts_help_exclude_oneline},
	{"CHECKCHAN",ss_cmd_checkchan,	1,	NS_ULEVEL_OPER, ts_help_checkchan,	ts_help_checkchan_oneline},
	{"CYCLE",	ss_cmd_cycle,		0,	NS_ULEVEL_OPER, ts_help_cycle,		ts_help_cycle_oneline},
	{"UPDATE",	ss_cmd_update,		0,	NS_ULEVEL_ADMIN,ts_help_update,		ts_help_update_oneline},
	{"STATUS",	ss_cmd_status,		0,	NS_ULEVEL_OPER, ts_help_status,		ts_help_status_oneline},
	{"BOTS",	ss_cmd_bots,		1,	100,			ts_help_bots,		ts_help_bots_oneline},
	{"MONCHAN",	ss_cmd_monchan,		1,	NS_ULEVEL_OPER, ts_help_monchan,	ts_help_monchan_oneline},
	{"RELOAD",	ss_cmd_reload,		0,	NS_ULEVEL_OPER, ts_help_reload,		ts_help_reload_oneline},
	{"VERSION",	ss_cmd_viriversion,	0,	0,		NULL, 			NULL},
	{NULL,		NULL,				0, 	0,				NULL, 				NULL}
};

static bot_setting ss_settings[]=
{
	{"HELPERS",		&SecureServ.helpers,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN, "helpers",		NULL,	ts_help_set_helpers, do_set_helpers_cb, (void *)1 },
	{"VERSION",		&SecureServ.doscan,		SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoVersionScan",NULL,	ts_help_set_version, NULL, (void *)0 },
	{"AKILLMSG",	&SecureServ.akillinfo,	SET_TYPE_MSG,		0,	BUFSIZE,	NS_ULEVEL_ADMIN,"AkillMsg",		NULL,	ts_help_set_akillmsg, NULL, (void *)"You have been Akilled from this network. Please get a virus scanner and check your PC" },
	{"HELPCHAN",	&SecureServ.HelpChan,	SET_TYPE_CHANNEL,	0,	MAXCHANLEN,	NS_ULEVEL_ADMIN,"HelpChan",		NULL,	ts_help_set_helpchan, NULL, (void *)"#nohack" },
	{"REPORT",		&SecureServ.report,		SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoReport",		NULL,	ts_help_set_report, NULL, (void *)1 },
	{"DOPRIVCHAN",	&SecureServ.doprivchan,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoPrivChan",	NULL,	ts_help_set_doprivchan, NULL, (void *)1 },
	{"CHECKFIZZER",	&SecureServ.dofizzer,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"FizzerCheck",	NULL,	ts_help_set_checkfizzer, NULL, (void *)1 },
	{"MULTICHECK",	&SecureServ.breakorcont,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"MultiCheck",	NULL,	ts_help_set_multicheck, NULL, (void *)1 },
	{"AKILL",		&SecureServ.doakill,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoAkill",		NULL,	ts_help_set_akill, NULL, (void *)1 },
	{"AKILLTIME",	&SecureServ.akilltime,	SET_TYPE_INT,		0,	0,			NS_ULEVEL_ADMIN,"AkillTime",	NULL,	ts_help_set_akilltime, NULL, (void *)3600 },
	{"SVSJOIN",		&SecureServ.dosvsjoin,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoSvsJoin",	NULL,	ts_help_set_dojoin, NULL, (void *)1 },
	{"TREATCHANMSGASPM", &SecureServ.treatchanmsgaspm,SET_TYPE_CUSTOM,0,0,		NS_ULEVEL_ADMIN,"ChanMsgAsPM",	NULL,	ts_help_set_treatchanmsgaspm, do_set_treatchanmsgaspm, (void *)0 },
	{"DOONJOIN",	&SecureServ.DoOnJoin,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoOnJoin",		NULL,	ts_help_set_doonjoin, NULL, (void *)1 },
	{"VERBOSE",		&SecureServ.verbose,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"Verbose",		NULL,	ts_help_set_verbose, NULL, (void *)1 },
	{"BOTECHO",		&SecureServ.BotEcho,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"BotEcho",		NULL,	ts_help_set_botecho, NULL, (void *)0 },
	{"BOTQUITMSG",	&SecureServ.botquitmsg,	SET_TYPE_MSG,		0,	BUFSIZE,	NS_ULEVEL_ADMIN,"BotQuitMsg",	NULL,	ts_help_set_botquitmsg, NULL, (void *)"Client quit" },
	{"MONCHANCYCLE",&SecureServ.monchancycle,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"MonChanCycle", NULL,	ts_help_set_monchancycle, NULL, (void *)1 },
	{"MONCHANCYCLETIME", &SecureServ.monchancycletime,SET_TYPE_INT,1,10000,	NS_ULEVEL_ADMIN,"MonitorBotCycle",NULL,	ts_help_set_monchancycletime, do_set_monchancycletime, (void *)1800 },
	{"CYCLETIME",	&SecureServ.stayinchantime,SET_TYPE_INT,	1,	1000,		NS_ULEVEL_ADMIN,"CycleTime",	NULL,	ts_help_set_cycletime, do_set_cycletime, (void *)60 },
	{"MONBOT",		NULL,					SET_TYPE_CUSTOM,	0,	0,			NS_ULEVEL_ADMIN,NULL,			NULL,	ts_help_set_monbot, do_set_monbot, (void *)0 },
	{"AUTOUPDATE",	NULL,					SET_TYPE_CUSTOM,	0,	0,			NS_ULEVEL_ADMIN,NULL,			NULL,	ts_help_set_autoupdate, do_set_autoupdate, (void *)0 },
	{"UPDATEINFO",	NULL,					SET_TYPE_CUSTOM,	0,	0,			NS_ULEVEL_ADMIN,NULL,			NULL,	ts_help_set_updateinfo, do_set_updateinfo, (void *)0 },
	{"ONJOINBOTMODES",&onjoinbot_modes,		SET_TYPE_STRING,	0,	MODESIZE,	NS_ULEVEL_ADMIN,"OnJoinBotModes",NULL,	ts_help_set_onjoinbotmodes, NULL, (void *)"+" },
	{NULL,			NULL,					0,					0,	0, 			0,				NULL,			NULL,	NULL, NULL },
};

BotInfo ss_botinfo =
{
	"SecureServ",
	"SecureServ1",
	"TS",
	BOT_COMMON_HOST, 
	"Trojan Scanning Bot",
	BOT_FLAG_SERVICEBOT|BOT_FLAG_DEAF, 
	ss_commands, 
	ss_settings,
};

static int do_set_updateinfo(CmdParams *cmdparams, SET_REASON reason) 
{
	SET_SEGV_LOCATION();
	if (reason == SET_LOAD) {
		return NS_SUCCESS;
	}
	if (!strcasecmp(cmdparams->av[0], "LIST")) {
		irc_prefmsg (ss_bot, cmdparams->source, "UPDATEINFO:   %s", SecureServ.updateuname[0] ? "Set" : "Not Set");
		if (SecureServ.updateuname[0]) {
			irc_prefmsg (ss_bot, cmdparams->source, "Update Username is %s, Password is %s", SecureServ.updateuname, SecureServ.updatepw);
		}
		return NS_SUCCESS;
	}
	if (cmdparams->ac < 5) {
		irc_prefmsg (ss_bot, cmdparams->source, "Invalid Syntax. /msg %s help set", ss_bot->name);
		return NS_SUCCESS;
	}
	DBAStoreConfigStr ("UpdateUname", cmdparams->av[1], MAXNICK);
	DBAStoreConfigStr ("UpdatePassword", cmdparams->av[2], MAXNICK);
	strlcpy(SecureServ.updateuname, cmdparams->av[1], MAXNICK);
	strlcpy(SecureServ.updatepw, cmdparams->av[2], MAXNICK);
	irc_chanalert (ss_bot, "%s changed the Update Username and Password", cmdparams->source);
	irc_prefmsg (ss_bot, cmdparams->source, "Update Username and Password has been updated to %s and %s", SecureServ.updateuname, SecureServ.updatepw);
	return NS_SUCCESS;
}

static int do_set_treatchanmsgaspm(CmdParams *cmdparams, SET_REASON reason) 
{
	if (reason == SET_LOAD) {
		return NS_SUCCESS;
	}
	if (reason == SET_LIST) {
		irc_prefmsg (ss_bot, cmdparams->source, "TREATCHANMSGASPM: %s", SecureServ.treatchanmsgaspm ? "Enabled (Warning Read Help)" : "Disabled");
		return NS_SUCCESS;
	}
	if (cmdparams->ac < 4) {
		irc_prefmsg (ss_bot, cmdparams->source, "Invalid Syntax. /msg %s help set for more info", ss_bot->name);
		return NS_SUCCESS;
	}			
	if ((!strcasecmp(cmdparams->av[1], "YES")) || (!strcasecmp(cmdparams->av[1], "ON"))) {
		irc_prefmsg (ss_bot, cmdparams->source, "\2Warning:\2");
		irc_prefmsg (ss_bot, cmdparams->source, "This option can consume a \2LOT\2 of CPU");
		irc_prefmsg (ss_bot, cmdparams->source, "When a Onjoin bot or MonBot is on large channel with lots of chatter");
		irc_prefmsg (ss_bot, cmdparams->source, "Its not a recomended configuration.");
		irc_prefmsg (ss_bot, cmdparams->source, "If you really want to enable this, type \2/msg %s SET TREATCHANMSGASPM IGOTLOTSOFCPU\2 to really enable this", ss_bot->name);
		return NS_SUCCESS;
	} else if (!strcasecmp(cmdparams->av[1], "IGOTLOTSOFCPU")) {
		irc_prefmsg (ss_bot, cmdparams->source, "Channel Messages are now treated as PM Messages. You did read the help didn't you?");
		irc_chanalert (ss_bot, "%s has configured %s to treat Channels messages as PM messages", cmdparams->source, ss_bot->name);
		SecureServ.treatchanmsgaspm = 1;
		DBAStoreConfigInt ("ChanMsgAsPM", &SecureServ.treatchanmsgaspm);
		return NS_SUCCESS;
	} else if ((!strcasecmp(cmdparams->av[1], "NO")) || (!strcasecmp(cmdparams->av[1], "OFF"))) {
		irc_prefmsg (ss_bot, cmdparams->source, "Channel message checking is now disabled");
		irc_chanalert (ss_bot, "%s has disabled channel message checking", cmdparams->source);
		SecureServ.treatchanmsgaspm = 0;
		DBAStoreConfigInt ("ChanMsgAsPM", &SecureServ.treatchanmsgaspm);
		return NS_SUCCESS;
	} else {
		irc_prefmsg (ss_bot, cmdparams->source, "Invalid Syntax. /msg %s help set for more info", ss_bot->name);
		return NS_SUCCESS;
	}
	return NS_SUCCESS;
}
static int do_set_monchancycletime(CmdParams *cmdparams, SET_REASON reason) 
{
	if (reason == SET_LOAD) {
		return NS_SUCCESS;
	}
	set_timer_interval ("MonBotCycle", SecureServ.monchancycletime);
	return NS_SUCCESS;
}
static int do_set_cycletime(CmdParams *cmdparams, SET_REASON reason) 
{
	if (reason == SET_LOAD) {
		return NS_SUCCESS;
	}
	set_timer_interval ("JoinNewChan", SecureServ.stayinchantime);
	return NS_SUCCESS;
}

static int do_set_autoupdate(CmdParams *cmdparams, SET_REASON reason) 
{
	if (reason == SET_LOAD) {
		return NS_SUCCESS;
	}
	if (!strcasecmp(cmdparams->av[0], "LIST")) {
		irc_prefmsg (ss_bot, cmdparams->source, "AUTOUPDATE:   %s", SecureServ.autoupgrade ? "Enabled" : "Disabled");
		return NS_SUCCESS;
	}
	if (cmdparams->ac < 4) {
		irc_prefmsg (ss_bot, cmdparams->source, "Invalid Syntax. /msg %s help set for more info", ss_bot->name);
		return NS_SUCCESS;
	}			
	if ((!strcasecmp(cmdparams->av[1], "YES")) || (!strcasecmp(cmdparams->av[1], "ON"))) {
		if ((SecureServ.updateuname[0]) && (SecureServ.updatepw[0])) {
			irc_prefmsg (ss_bot, cmdparams->source, "AutoUpdate Mode is now enabled");
			irc_chanalert (ss_bot, "%s enabled AutoUpdate Mode", cmdparams->source);
			if (SecureServ.autoupgrade != 1) {
				add_timer (TIMER_TYPE_INTERVAL, AutoUpdate, "AutoUpdate", 7200);
			}
			SecureServ.autoupgrade = 1;
			DBAStoreConfigInt ("AutoUpdate", &SecureServ.autoupgrade);
			return NS_SUCCESS;
		} else {
			irc_prefmsg (ss_bot, cmdparams->source, "You can not enable AutoUpdate, as you have not set a username and password");
			return NS_SUCCESS;
		}
	} else if ((!strcasecmp(cmdparams->av[1], "NO")) || (!strcasecmp(cmdparams->av[1], "OFF"))) {
		irc_prefmsg (ss_bot, cmdparams->source, "AutoUpdate Mode is now disabled");
		irc_chanalert (ss_bot, "%s disabled AutoUpdate Mode", cmdparams->source);
		if (SecureServ.autoupgrade == 1) {
			del_timer ("AutoUpdate");
		}
		SecureServ.autoupgrade = 0;
		DBAStoreConfigInt ("AutoUpdate", &SecureServ.autoupgrade);
		return NS_SUCCESS;
	}
	return NS_SUCCESS;
}
static int ss_cmd_viriversion(CmdParams *cmdparams)
{
	irc_prefmsg (ss_bot, cmdparams->source, "%d", SecureServ.ss_cmd_viriversion);
	return NS_SUCCESS;
}

static int ss_cmd_status(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	irc_prefmsg (ss_bot, cmdparams->source, "SecureServ Status:");
	irc_prefmsg (ss_bot, cmdparams->source, "==================");
	ScanStatus (cmdparams);
	HelpersStatus (cmdparams);
	OnJoinBotStatus (cmdparams);
	irc_prefmsg (ss_bot, cmdparams->source, "End of List.");
	return NS_SUCCESS;
}

int ss_event_newchan(CmdParams *cmdparams)
{
	ChannelDetail *cd;

	SET_SEGV_LOCATION();
	cd = ns_malloc(sizeof(ChannelDetail));
	cd->scanned = 0;
	SetChannelModValue (cmdparams->channel, (void *)cd);
	/* check if its a monchan and we are not in place */
	MonJoin(cmdparams->channel);
	return NS_SUCCESS;
}

int ss_event_joinchan(CmdParams *cmdparams)
{
	ChannelDetail *cd;

	SET_SEGV_LOCATION();
	/* is it exempt? */
	if (SS_IsChanExempt(cmdparams->channel) > 0) {
		return -1;
	}
	
	/* how about the user, is he exempt? */
	if (SS_IsUserExempt(cmdparams->source) > 0) {
		return -1;
	}
	cd = (ChannelDetail *)GetChannelModValue (cmdparams->channel);
	/* if cd doesn't exist, soemthing major is wrong */
	if(cd && cd->scanned == 0) {
		/* Only set the channel to scanned if it is a clean channel 
		 * otherwise we may miss scans
		 */
		if(ScanChan(cmdparams->source, cmdparams->channel) == 0) {
			cd->scanned = 1;
		}
	}
	return NS_SUCCESS;
}

int ss_event_delchan(CmdParams *cmdparams) 
{
	ChannelDetail *cd;

	SET_SEGV_LOCATION();
	cd = (ChannelDetail *)GetChannelModValue (cmdparams->channel);
	ns_free(cd);
	ClearChannelModValue (cmdparams->channel);
	return NS_SUCCESS;
}

int ss_event_away(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	HelpersAway(cmdparams);
	/* TODO: scan away messages for spam */
	return NS_SUCCESS;
}

static int ss_event_channelmessage (CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	/* first, if its the services channel, just ignore it */
	if (IsServicesChannel( cmdparams->channel )) {
		return -1;
	}
	if (SS_IsUserExempt(cmdparams->source) > 0) {
		dlog (DEBUG1, "User %s is exempt from Message Checking", cmdparams->source);
		return -1;
	}
	/* otherwise, just pass it to the ScanMsg function */
	ScanMsg(cmdparams->source, cmdparams->param, 1);
	return NS_SUCCESS;
}

static int ss_event_botkill(CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	/* Check the mon bot first */
	if(CheckMonBotKill(cmdparams)!=0) {
		return NS_SUCCESS;
	}
	/* What else should we check? */
	return NS_SUCCESS;
}

ModuleEvent module_events[] = {
	{ EVENT_SIGNON, 		ss_event_signon},
	{ EVENT_QUIT, 			ss_event_quit},
	{ EVENT_KILL, 			ss_event_quit},
	{ EVENT_JOIN, 			ss_event_joinchan},
	{ EVENT_DELCHAN,		ss_event_delchan},
	{ EVENT_NICK,			ss_event_nick},
	{ EVENT_EMPTYCHAN,		ss_event_emptychan},	
	{ EVENT_KICKBOT,		ss_event_kickbot},
	{ EVENT_AWAY, 			ss_event_away},
	{ EVENT_NEWCHAN,		ss_event_newchan},
	{ EVENT_PRIVATE, 		ss_event_message},
	{ EVENT_NOTICE, 		ss_event_message},
	{ EVENT_CPRIVATE, 		ss_event_channelmessage},
	{ EVENT_CNOTICE, 		ss_event_channelmessage},
	{ EVENT_BOTKILL, 		ss_event_botkill},
	{ EVENT_CTCPVERSIONRPL, ss_event_versionreply},	
	{ EVENT_CTCPVERSIONREQ, ss_event_versionrequest},	
	{ EVENT_NULL, 			NULL}
};

static int ss_event_quit(CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	HelpersSignoff(cmdparams);
	return NS_SUCCESS;
}

/* scan nickname changes */
static int ss_event_nick(CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	if (SS_IsUserExempt(cmdparams->source) > 0) {
		dlog (DEBUG1, "Bye, I'm Exempt %s", cmdparams->source);
		return -1;
	}
	/* check the nickname */
	if(ScanUser(cmdparams->source, SCAN_NICK)) {
		return NS_SUCCESS;
	}

	return NS_SUCCESS;
}

/* scan someone connecting */
static int ss_event_signon(CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	if (SecureServ.doscan == 0) 
		return -1;
	if (IsNetSplit(cmdparams->source)) {
		dlog (DEBUG1, "Ignoring netsplit nick %s", cmdparams->source->name);
		return -1;
	}
	if (SS_IsUserExempt(cmdparams->source) > 0) {
		return -1;
	}
	/* fizzer scan */
	if (SecureServ.dofizzer) {
		if(ScanFizzer(cmdparams->source)) {
			return NS_SUCCESS;
		}
	}
	/* check the nickname, ident, realname */
	if(ScanUser(cmdparams->source, SCAN_NICK|SCAN_IDENT|SCAN_REALNAME)) {
		return NS_SUCCESS;
	}
	return NS_SUCCESS;
}

static int ss_event_versionreply(CmdParams *cmdparams) 
{
	int positive = 0;
	static int versioncount = 0;

	SET_SEGV_LOCATION();
	positive = ScanCTCP(cmdparams->source, cmdparams->param);
	versioncount++;
	/* why do we only change the version reply every 23 entries? Why not? */
	if ((positive == 0) && (versioncount > 23)) {
		strlcpy(SecureServ.sampleversion, cmdparams->param, SS_BUF_SIZE);
		versioncount = 0;
	}
	return NS_SUCCESS;
}

/** Init module
 */
int ModInit (Module *mod_ptr)
{
	SET_SEGV_LOCATION();
	os_memset (&SecureServ, 0, sizeof (SecureServ));
	ModuleConfig (ss_settings);
	SSInitExempts();
	InitScanner();
	InitOnJoinBots();
	return NS_SUCCESS;
}

/** @brief ModSynch
 *
 *  Startup handler
 *
 *  @param none
 *
 *  @return NS_SUCCESS if suceeds else NS_FAILURE
 */

int ModSynch (void)
{
	Channel *c;
	Client *u;
	lnode_t *lnode;
	hnode_t *hnode;
	hscan_t hs;
	
	SET_SEGV_LOCATION();
	ss_bot = AddBot (&ss_botinfo);
	if (!ss_bot) {
		return NS_FAILURE;
	}
	InitHelpers();
	if (SecureServ.verbose) {
		irc_chanalert (ss_bot, "%d Trojans Patterns loaded", ViriCount());
	}
	srand(hash_count(GetChannelHash()));
	/* kick of the autojoin timer */
	add_timer (TIMER_TYPE_INTERVAL, JoinNewChan, "JoinNewChan", SecureServ.stayinchantime);
	add_timer (TIMER_TYPE_INTERVAL, MonBotCycle, "MonBotCycle", SecureServ.monchancycletime);
	dns_lookup("secure.irc-chat.net",  adns_r_a, GotHTTPAddress, "SecureServ Update Server");
	LoadMonChans();
	if (SecureServ.autoupgrade == 1) {
		add_timer (TIMER_TYPE_INTERVAL, AutoUpdate, "AutoUpdate", 7200);
	}
	/* here, we run though the channel lists, as when we were booting, we were not checking. */
	hash_scan_begin(&hs, GetChannelHash());
	while ((hnode = hash_scan_next(&hs)) != NULL) {
		c = hnode_get(hnode);
		if (!c)
			continue;

		/* now scan channel members */
		lnode = list_first(c->members);
		while (lnode) {
			u = find_user(lnode_get(lnode));
			if (SS_IsUserExempt(u) > 0) {
				lnode = list_next(c->members, lnode);
				continue;
			}
			if (u && ScanChan(u, c) == 0) {
				break;
			}
			lnode = list_next(c->members, lnode);
		}
	}
	return NS_SUCCESS;
};

/** Fini module
 * This is required if you need to do cleanup of your module when it ends
 */
void ModFini() 
{
	SET_SEGV_LOCATION();
	FiniHelpers();
	ExitOnJoinBots();
}

int ModAuthUser (Client *u)
{
	UserDetail *ud;

	ud = (UserDetail *)GetUserModValue (u);
	if (ud) {
		if (ud->type == USER_HELPER) {
			return 30;
		}
	}
	return 0;
}

#ifdef WIN32 /* temp */

int main (int argc, char **argv)
{
	return 0;
}
#endif