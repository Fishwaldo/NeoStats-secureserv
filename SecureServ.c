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

static int ScanNick (CmdParams *cmdparams);
static int event_version_reply (CmdParams *cmdparams);
static int do_status (CmdParams *cmdparams);
static int NickChange (CmdParams *cmdparams);
static int DelNick (CmdParams *cmdparams);
static int ss_kick_chan (CmdParams *cmdparams);
static int do_viriversion (CmdParams *cmdparams);

static int do_set_treatchanmsgaspm (CmdParams *cmdparams, SET_REASON reason);
static int do_set_monchancycletime (CmdParams *cmdparams, SET_REASON reason);
static int do_set_cycletime (CmdParams *cmdparams, SET_REASON reason);
static int do_set_autoupdate (CmdParams *cmdparams, SET_REASON reason);
static int do_set_sampletime (CmdParams *cmdparams, SET_REASON reason);
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
	{"LOGIN",	HelpersLogin,	2,	0,				ts_help_login,		ts_help_login_oneline},
 	{"LOGOUT",	HelpersLogout,	0,	30,				ts_help_logout,		ts_help_logout_oneline},
	{"CHPASS",	HelpersChpass,	1,	30,				ts_help_chpass,		ts_help_chpass_oneline},
	{"ASSIST",	HelpersAssist,	2,	30,				ts_help_assist,		ts_help_assist_oneline},
	{"HELPERS",	do_helpers,		1,	NS_ULEVEL_OPER, ts_help_helpers,	ts_help_helpers_oneline},
	{"LIST",	do_list,		0,	NS_ULEVEL_OPER, ts_help_list,		ts_help_list_oneline},
	{"EXCLUDE",	SS_do_exempt,	1,	50,				ts_help_exclude,	ts_help_exclude_oneline},
	{"CHECKCHAN",do_checkchan,	1,	NS_ULEVEL_OPER, ts_help_checkchan,	ts_help_checkchan_oneline},
	{"CYCLE",	do_cycle,		0,	NS_ULEVEL_OPER, ts_help_cycle,		ts_help_cycle_oneline},
	{"UPDATE",	do_update,		0,	NS_ULEVEL_ADMIN,ts_help_update,		ts_help_update_oneline},
	{"STATUS",	do_status,		0,	NS_ULEVEL_OPER, ts_help_status,		ts_help_status_oneline},
	{"BOTS",	do_bots,		1,	100,			ts_help_bots,		ts_help_bots_oneline},
	{"MONCHAN",	do_monchan,		1,	NS_ULEVEL_OPER, ts_help_monchan,	ts_help_monchan_oneline},
	{"RELOAD",	do_reload,		0,	NS_ULEVEL_OPER, ts_help_reload,		ts_help_reload_oneline},
	{"VERSION",	do_viriversion,		0,	0,		NULL, 			NULL},
	{NULL,		NULL,			0, 	0,				NULL, 				NULL}
};

static bot_setting ss_settings[]=
{
	{"SPLITTIME",	&SecureServ.timedif,	SET_TYPE_INT,		0,	1000,		NS_ULEVEL_ADMIN, "SplitTime",	NULL,	ts_help_set_splittime, NULL, (void *)300 },
	{"CHANKEY",		&SecureServ.ChanKey,	SET_TYPE_STRING,	0,	MAXCHANLEN,	NS_ULEVEL_ADMIN, "ChanKey",		NULL,	ts_help_set_chankey, NULL, (void *)"Eeeek" },
	{"VERSION",		&SecureServ.doscan,		SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoVersionScan",NULL,	ts_help_set_version, NULL, (void *)0 },
	{"BOTQUITMSG",	&SecureServ.botquitmsg,	SET_TYPE_MSG,		0,	BUFSIZE,	NS_ULEVEL_ADMIN,"BotQuitMsg",	NULL,	ts_help_set_botquitmsg, NULL, (void *)"Client quit" },
	{"AKILLMSG",	&SecureServ.akillinfo,	SET_TYPE_MSG,		0,	BUFSIZE,	NS_ULEVEL_ADMIN,"AkillMsg",		NULL,	ts_help_set_akillmsg, NULL, (void *)"You have been Akilled from this network. Please get a virus scanner and check your PC" },
	{"NOHELPMSG",	&SecureServ.nohelp,		SET_TYPE_MSG,		0,	BUFSIZE,	NS_ULEVEL_ADMIN,"NoHelpMsg",	NULL,	ts_help_set_nohelpmsg, NULL, (void *)"No Helpers are online at the moment, so you have been Akilled from this network. Please visit http://www.nohack.org for Trojan/Virus Info" },
	{"HELPCHAN",	&SecureServ.HelpChan,	SET_TYPE_CHANNEL,	0,	MAXCHANLEN,	NS_ULEVEL_ADMIN,"HelpChan",		NULL,	ts_help_set_helpchan, NULL, (void *)"#nohack" },
	{"AUTOSIGNOUT",	&SecureServ.signoutaway,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoAwaySignOut",NULL,	ts_help_set_autosignout, NULL, (void *)1 },
	{"JOINHELPCHAN",&SecureServ.joinhelpchan,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoJoinHelpChan",NULL,	ts_help_set_joinhelpchan, NULL, (void *)1 },
	{"REPORT",		&SecureServ.report,		SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoReport",		NULL,	ts_help_set_report, NULL, (void *)1 },
	{"FLOODPROT",	&SecureServ.FloodProt,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoFloodProt",	NULL,	ts_help_set_floodprot, NULL, (void *)1 },
	{"DOPRIVCHAN",	&SecureServ.doprivchan,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoPrivChan",	NULL,	ts_help_set_doprivchan, NULL, (void *)1 },
	{"CHECKFIZZER",	&SecureServ.dofizzer,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"FizzerCheck",	NULL,	ts_help_set_checkfizzer, NULL, (void *)1 },
	{"MULTICHECK",	&SecureServ.breakorcont,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"MultiCheck",	NULL,	ts_help_set_multicheck, NULL, (void *)1 },
	{"AKILL",		&SecureServ.doakill,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoAkill",		NULL,	ts_help_set_akill, NULL, (void *)1 },
	{"AKILLTIME",	&SecureServ.akilltime,	SET_TYPE_INT,		0,	0,			NS_ULEVEL_ADMIN,"AkillTime",	NULL,	ts_help_set_akilltime, NULL, (void *)3600 },
	{"CHANLOCKTIME",&SecureServ.closechantime,SET_TYPE_INT,		0,	600,		NS_ULEVEL_ADMIN,"ChanLockTime", NULL,	ts_help_set_chanlocktime, NULL, (void *)30 },
	{"NFCOUNT",		&SecureServ.nfcount,	SET_TYPE_INT,		0,	100,		NS_ULEVEL_ADMIN,"NFCount",		NULL,	ts_help_set_nfcount, NULL, (void *)5 },
	{"DOJOIN",		&SecureServ.dosvsjoin,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoSvsJoin",	NULL,	ts_help_set_dojoin, NULL, (void *)1 },
	{"DOONJOIN",	&SecureServ.DoOnJoin,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoOnJoin",		NULL,	ts_help_set_doonjoin, NULL, (void *)1 },
	{"BOTECHO",		&SecureServ.BotEcho,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"BotEcho",		NULL,	ts_help_set_botecho, NULL, (void *)0 },
	{"VERBOSE",		&SecureServ.verbose,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"Verbose",		NULL,	ts_help_set_verbose, NULL, (void *)1 },
	{"MONCHANCYCLE",&SecureServ.monchancycle,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"MonChanCycle", NULL,	ts_help_set_monchancycle, NULL, (void *)1 },
	{"TREATCHANMSGASPM", &SecureServ.treatchanmsgaspm,SET_TYPE_CUSTOM,0,0,		NS_ULEVEL_ADMIN,"ChanMsgAsPM",	NULL,	ts_help_set_treatchanmsgaspm, do_set_treatchanmsgaspm, (void *)0 },
	{"MONCHANCYCLETIME", &SecureServ.monchancycletime,SET_TYPE_INT,1,10000,	NS_ULEVEL_ADMIN,"MonitorBotCycle",NULL,	ts_help_set_monchancycletime, do_set_monchancycletime, (void *)1800 },
	{"CYCLETIME",	&SecureServ.stayinchantime,SET_TYPE_INT,	1,	1000,		NS_ULEVEL_ADMIN,"CycleTime",	NULL,	ts_help_set_cycletime, do_set_cycletime, (void *)60 },
	{"MONBOT",		NULL,					SET_TYPE_CUSTOM,	0,	0,			NS_ULEVEL_ADMIN,NULL,			NULL,	ts_help_set_monbot, do_set_monbot, (void *)0 },
	{"AUTOUPDATE",	NULL,					SET_TYPE_CUSTOM,	0,	0,			NS_ULEVEL_ADMIN,NULL,			NULL,	ts_help_set_autoupdate, do_set_autoupdate, (void *)0 },
	{"SAMPLETIME",	NULL,					SET_TYPE_CUSTOM,	0,	0,			NS_ULEVEL_ADMIN,NULL,			NULL,	ts_help_set_sampletime, do_set_sampletime, (void *)0 },
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
	SetConf((void *)cmdparams->av[1], CFGSTR, "UpdateUname");
	SetConf((void *)cmdparams->av[2], CFGSTR, "UpdatePassword");
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
		SetConf((void *)1, CFGINT, "ChanMsgAsPM");
		SecureServ.treatchanmsgaspm = 1;
		return NS_SUCCESS;
	} else if ((!strcasecmp(cmdparams->av[1], "NO")) || (!strcasecmp(cmdparams->av[1], "OFF"))) {
		irc_prefmsg (ss_bot, cmdparams->source, "Channel message checking is now disabled");
		irc_chanalert (ss_bot, "%s has disabled channel message checking", cmdparams->source);
		SetConf((void *)0, CFGINT, "ChanMsgAsPM");
		SecureServ.treatchanmsgaspm = 0;
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
			SetConf((void *)1, CFGINT, "AutoUpdate");
			if (SecureServ.autoupgrade != 1) {
				add_timer (TIMER_TYPE_INTERVAL, AutoUpdate, "AutoUpdate", 7200);
			}
			SecureServ.autoupgrade = 1;
			return NS_SUCCESS;
		} else {
			irc_prefmsg (ss_bot, cmdparams->source, "You can not enable AutoUpdate, as you have not set a username and password");
			return NS_SUCCESS;
		}
	} else if ((!strcasecmp(cmdparams->av[1], "NO")) || (!strcasecmp(cmdparams->av[1], "OFF"))) {
		irc_prefmsg (ss_bot, cmdparams->source, "AutoUpdate Mode is now disabled");
		irc_chanalert (ss_bot, "%s disabled AutoUpdate Mode", cmdparams->source);
		SetConf((void *)0, CFGINT, "AutoUpdate");
		if (SecureServ.autoupgrade == 1) {
			del_timer ("AutoUpdate");
		}
		SecureServ.autoupgrade = 0;
		return NS_SUCCESS;
	}
	return NS_SUCCESS;
}
static int do_set_sampletime(CmdParams *cmdparams, SET_REASON reason) 
{
	int i, j;
	if (reason == SET_LOAD) {
		return NS_SUCCESS;
	}
	if (!strcasecmp(cmdparams->av[0], "LIST")) {
		if (SecureServ.FloodProt) {
			irc_prefmsg (ss_bot, cmdparams->source, "SAMPLETIME:   %d/%d Seconds", SecureServ.JoinThreshold, SecureServ.sampletime);
		}
		return NS_SUCCESS;
	}
	if (cmdparams->ac < 5) {
		irc_prefmsg (ss_bot, cmdparams->source, "Invalid Syntax. /msg %s help set for more info", ss_bot->name);
		return NS_SUCCESS;
	}			
	i = atoi(cmdparams->av[1]);
	j = atoi(cmdparams->av[2]);	
	if ((i <= 0) || (i > 1000)) {
		irc_prefmsg (ss_bot, cmdparams->source, "SampleTime Value out of Range.");
		return NS_SUCCESS;
	}
	if ((j <= 0) || (i > 1000)) {
		irc_prefmsg (ss_bot, cmdparams->source, "Threshold Value is out of Range");
		return NS_SUCCESS;
	}
	/* if we get here, all is ok */
	SecureServ.sampletime = i;
	SecureServ.JoinThreshold = j;
	irc_prefmsg (ss_bot, cmdparams->source, "Flood Protection is now enabled at %d joins in %d Seconds", j, i);
	irc_chanalert (ss_bot, "%s Set Flood Protection to %d joins in %d Seconds", cmdparams->source, j, i);
	SetConf((void *)i, CFGINT, "SampleTime");
	SetConf((void *)j, CFGINT, "JoinThreshold");
	return NS_SUCCESS;
}

static int do_viriversion(CmdParams *cmdparams)
{
	irc_prefmsg (ss_bot, cmdparams->source, "%d", SecureServ.viriversion);
	return NS_SUCCESS;
}

static int do_status(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	irc_prefmsg (ss_bot, cmdparams->source, "SecureServ Status:");
	irc_prefmsg (ss_bot, cmdparams->source, "==================");
	irc_prefmsg (ss_bot, cmdparams->source, "Virus Patterns Loaded: %d", ViriCount());
	irc_prefmsg (ss_bot, cmdparams->source, "CTCP Version Messages Scanned: %d", SecureServ.trigcounts[DET_CTCP]);
	irc_prefmsg (ss_bot, cmdparams->source, "CTCP Messages Acted On: %d", SecureServ.actioncounts[DET_CTCP]);
	irc_prefmsg (ss_bot, cmdparams->source, "CTCP Definitions: %d", SecureServ.definitions[DET_CTCP]);
	irc_prefmsg (ss_bot, cmdparams->source, "Private Messages Received: %d", SecureServ.trigcounts[DET_MSG]);
	irc_prefmsg (ss_bot, cmdparams->source, "Private Messages Acted on: %d", SecureServ.actioncounts[DET_MSG]);
	irc_prefmsg (ss_bot, cmdparams->source, "Private Message Definitions: %d", SecureServ.definitions[DET_MSG]);
	irc_prefmsg (ss_bot, cmdparams->source, "NickNames Checked: %d", SecureServ.trigcounts[DET_NICK]);
	irc_prefmsg (ss_bot, cmdparams->source, "NickName Acted on: %d", SecureServ.actioncounts[DET_NICK]);
	irc_prefmsg (ss_bot, cmdparams->source, "NickName Definitions: %d", SecureServ.definitions[DET_NICK]);
	irc_prefmsg (ss_bot, cmdparams->source, "Ident's Checked: %d", SecureServ.trigcounts[DET_IDENT]);
	irc_prefmsg (ss_bot, cmdparams->source, "Ident's Acted on: %d", SecureServ.actioncounts[DET_IDENT]);
	irc_prefmsg (ss_bot, cmdparams->source, "Ident Definitions: %d", SecureServ.definitions[DET_IDENT]);
	irc_prefmsg (ss_bot, cmdparams->source, "RealNames Checked: %d", SecureServ.trigcounts[DET_REALNAME]);
	irc_prefmsg (ss_bot, cmdparams->source, "RealNames Acted on: %d", SecureServ.actioncounts[DET_REALNAME]);
	irc_prefmsg (ss_bot, cmdparams->source, "RealName Definitions: %d", SecureServ.definitions[DET_REALNAME]);
	irc_prefmsg (ss_bot, cmdparams->source, "ChannelNames Checked: %d", SecureServ.trigcounts[DET_CHAN]);
	irc_prefmsg (ss_bot, cmdparams->source, "ChannelNames Acted on: %d", SecureServ.actioncounts[DET_CHAN]);
	irc_prefmsg (ss_bot, cmdparams->source, "ChannelName Definitions: %d", SecureServ.definitions[DET_CHAN]);
	irc_prefmsg (ss_bot, cmdparams->source, "Channel Messages Checked: %d", SecureServ.trigcounts[DET_CHANMSG]);
	irc_prefmsg (ss_bot, cmdparams->source, "Channel Messages Acted on: %d", SecureServ.actioncounts[DET_CHANMSG]);
	irc_prefmsg (ss_bot, cmdparams->source, "Channel Messages Definitions: %d", SecureServ.definitions[DET_CHANMSG]);
	irc_prefmsg (ss_bot, cmdparams->source, "Built-In Checks Run: %d", SecureServ.actioncounts[DET_BUILTIN]);
	irc_prefmsg (ss_bot, cmdparams->source, "Built-In Checks Acted on: %d", SecureServ.actioncounts[DET_BUILTIN]);
	irc_prefmsg (ss_bot, cmdparams->source, "Built-In Functions: %d", SecureServ.definitions[DET_BUILTIN]);
	irc_prefmsg (ss_bot, cmdparams->source, "AV Channel Helpers Logged in: %d", SecureServ.helpcount);
	irc_prefmsg (ss_bot, cmdparams->source, "Current Top AJPP: %d (in %d Seconds): %s", SecureServ.MaxAJPP, SecureServ.sampletime, SecureServ.MaxAJPPChan);
	if (SecureServ.lastchan[0]) 
		irc_prefmsg (ss_bot, cmdparams->source, "Currently Checking %s with %s", SecureServ.lastchan, SecureServ.lastnick);
	irc_prefmsg (ss_bot, cmdparams->source, "End of List.");
	
	return NS_SUCCESS;
}

int ss_new_chan(CmdParams *cmdparams)
{
	ChannelDetail *cd;

	SET_SEGV_LOCATION();
	/* find the chan in the Core */
	cd = ns_malloc(sizeof(ChannelDetail));
	cd->scanned = 0;
	SetChannelModValue (cmdparams->channel, (void *)cd);
	return NS_SUCCESS;
}

int ss_join_chan(CmdParams *cmdparams)
{
	ChannelDetail *cd;

	SET_SEGV_LOCATION();
	/* is it exempt? */
	if (SS_IsChanExempt(cmdparams->channel) > 0) {
		return -1;
	}
	/* check if its a monchan and we are not in place */
	if (cmdparams->channel->users == 1) 
		MonJoin(cmdparams->channel);
	
	/* how about the user, is he exempt? */
	if (SS_IsUserExempt(cmdparams->source) > 0) {
		return -1;
	}
	
	/* first, check if this is a *bad* channel only if its the first person to join.*/
	/* NOTE: if its a monchan, c->users will be 2 here, as our MonBot would have joined above 
	 * but we only check for 1 users. Why? Easy, because chances are, a MonChan is not going to trigger a 
	 * Signature is it? So this has the side effect of reducing our cpu consuption
	 * and the reason we only check if there is one user, is that we only need to check
	 * a channel name once, not everytime someone joins the channel. 
	 * -Fish
	 */
	 
	 /* this is actually pretty screwed up. You know why? because if a exempt user joins a bad channel 
	  * such as a IRCop, then the usercount will be screwed up next time someone joins it and really should 
	  * be killed 
	  */
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
	if(JoinFloodJoinChan(cmdparams->source, cmdparams->channel))
		return NS_SUCCESS;

	
	return NS_SUCCESS;
}
int ss_part_chan(CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	MonBotDelChan(cmdparams->channel);
/*	OnJoinDelChan(cmdparams->channel);*/
	return NS_SUCCESS;
}

int ss_del_chan(CmdParams *cmdparams) 
{
	ChannelDetail *cd;

	SET_SEGV_LOCATION();
	cd = (ChannelDetail *)GetChannelModValue (cmdparams->channel);
	ns_free(cd);
	ClearChannelModValue (cmdparams->channel);
	JoinFloodDelChan(cmdparams->channel);
	return NS_SUCCESS;
}

int ss_user_away(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	HelpersAway(cmdparams);
	/* TODO: scan away messages for spam */
	return NS_SUCCESS;
}

static int channel_message (CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	/* first, if its the services channel, just ignore it */
	if (!strcasecmp(cmdparams->channel->name, me.serviceschan)) {
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

static int event_botkill(CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	/* Check the mon bot first */
	if(CheckMonBotKill(cmdparams->target->name)!=0) {
		return NS_SUCCESS;
	}
	/* What else should we check? */
	return NS_SUCCESS;
}

ModuleEvent module_events[] = {
	{ EVENT_SIGNON, 	ScanNick},
	{ EVENT_QUIT, 		DelNick},
	{ EVENT_KILL, 		DelNick},
	{ EVENT_JOIN, 		ss_join_chan},
	{ EVENT_DELCHAN,	ss_del_chan},
	{ EVENT_PART,		ss_part_chan},
	{ EVENT_NICK,		NickChange},
	{ EVENT_KICK,		ss_kick_chan},
	{ EVENT_AWAY, 		ss_user_away},
	{ EVENT_NEWCHAN,	ss_new_chan},
	{ EVENT_PRIVATE, 	OnJoinBotMsg},
	{ EVENT_NOTICE, 	OnJoinBotMsg},
	{ EVENT_CPRIVATE, 	channel_message},
	{ EVENT_CNOTICE, 	channel_message},
	{ EVENT_BOTKILL, 	event_botkill},
	{ EVENT_CTCPVERSIONRPL, event_version_reply},	
	{ EVENT_CTCPVERSIONREQ, OnJoinBotVersionRequest},	
	{ EVENT_NULL, 			NULL}
};

static int DelNick(CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	NickFloodSignOff(cmdparams->source->name);
	HelpersSignoff(cmdparams);
	return NS_SUCCESS;
}

/* scan nickname changes */
static int NickChange(CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	/* Possible memory leak here if a helper changes nick? */
	ClearUserModValue (cmdparams->source);
	
	if (SS_IsUserExempt(cmdparams->source) > 0) {
		dlog (DEBUG1, "Bye, I'm Exempt %s", cmdparams->source);
		return -1;
	}
	/* is it a nickflood? */
	CheckNickFlood(cmdparams->source);

	/* check the nickname */
	if(ScanUser(cmdparams->source, SCAN_NICK)) {
		return NS_SUCCESS;
	}

	return NS_SUCCESS;
}

/* scan someone connecting */
static int ScanNick(CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	if (SecureServ.doscan == 0) 
		return -1;
	if (cmdparams->source->flags && NS_FLAGS_NETJOIN)
		return -1;
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


static int ss_kick_chan(CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	if(CheckOnjoinBotKick(cmdparams)) {
		return NS_SUCCESS;
	}
	/* Can we use this event for anything else e.g. channel takeover checks? */
	return NS_SUCCESS;
}
static int event_version_reply(CmdParams *cmdparams) 
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
	SecureServ.sampletime = 5;
	SecureServ.JoinThreshold = 5;
	SS_InitExempts();
	InitScanner();
	InitOnJoinBots();
	InitJoinFlood();
	InitNickFlood();
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
	HelpersInit();
	if (SecureServ.verbose) {
		irc_chanalert (ss_bot, "%d Trojans Patterns loaded", ViriCount());
	}
	srand(hash_count(GetChannelHash()));
	/* kick of the autojoin timer */
	add_timer (TIMER_TYPE_INTERVAL, JoinNewChan, "JoinNewChan", SecureServ.stayinchantime);
	add_timer (TIMER_TYPE_INTERVAL, MonBotCycle, "MonBotCycle", SecureServ.monchancycletime);
	/* start cleaning the nickflood list now */
	/* every sixty seconds should keep the list small, and not put *too* much load on NeoStats */
	add_timer (TIMER_TYPE_INTERVAL, CleanNickFlood, "CleanNickFlood", 60);
	add_timer (TIMER_TYPE_INTERVAL, CheckLockChan, "CheckLockChan", 60);
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