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

#ifdef WIN32
#include "modconfigwin32.h"
#else
#include "modconfig.h"
#endif
#include "neostats.h"
#include "SecureServ.h"

static int ss_event_signon (CmdParams *cmdparams);
static int ss_event_versionreply (CmdParams *cmdparams);
static int ss_cmd_status (CmdParams *cmdparams);
static int ss_event_nick (CmdParams *cmdparams);
static int ss_event_quit (CmdParams *cmdparams);
static int ss_cmd_viriversion (CmdParams *cmdparams);

static int ss_cmd_set_treatchanmsgaspm (CmdParams *cmdparams, SET_REASON reason);
static int ss_cmd_set_monchancycletime_cb (CmdParams *cmdparams, SET_REASON reason);
static int ss_cmd_set_cycletime_cb (CmdParams *cmdparams, SET_REASON reason);

#ifdef WIN32
void *(*old_malloc)(size_t);
void (*old_free) (void *);
#endif

Bot *ss_bot;

/** about info */
const char *ss_about[] = {
	"A Trojan Scanning Bot",
	NULL
};

const char *ss_copyright[] = {
	"Copyright (c) 1999-2005, NeoStats",
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
	MODULE_FLAG_LOCAL_EXCLUDES,
	0,
};

static bot_cmd ss_commands[]=
{
	{"LIST",	ss_cmd_list,		0,	NS_ULEVEL_OPER, ts_help_list,		ts_help_list_oneline},
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
	{"HELPERS",		&SecureServ.helpers,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN, "helpers",		NULL,	ts_help_set_helpers, ss_cmd_set_helpers_cb, (void *)1 },
	{"VERSION",		&SecureServ.doscan,		SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoVersionScan",NULL,	ts_help_set_version, NULL, (void *)0 },
	{"AKILLMSG",	&SecureServ.akillinfo,	SET_TYPE_MSG,		0,	BUFSIZE,	NS_ULEVEL_ADMIN,"AkillMsg",		NULL,	ts_help_set_akillmsg, NULL, (void *)"You have been Akilled from this network. Please get a virus scanner and check your PC" },
	{"HELPCHAN",	&SecureServ.HelpChan,	SET_TYPE_CHANNEL,	0,	MAXCHANLEN,	NS_ULEVEL_ADMIN,"HelpChan",		NULL,	ts_help_set_helpchan, NULL, (void *)"#nohack" },
	{"REPORT",		&SecureServ.report,		SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoReport",		NULL,	ts_help_set_report, NULL, (void *)1 },
	{"DOPRIVCHAN",	&SecureServ.doprivchan,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoPrivChan",	NULL,	ts_help_set_doprivchan, NULL, (void *)1 },
	{"CHECKFIZZER",	&SecureServ.dofizzer,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"FizzerCheck",	NULL,	ts_help_set_checkfizzer, NULL, (void *)1 },
	{"MULTICHECK",	&SecureServ.breakorcont,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"MultiCheck",	NULL,	ts_help_set_multicheck, NULL, (void *)1 },
	{"AKILL",		&SecureServ.doakill,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoAkill",		NULL,	ts_help_set_akill, NULL, (void *)1 },
	{"AKILLTIME",	&SecureServ.akilltime,	SET_TYPE_INT,		0,	20736000,	NS_ULEVEL_ADMIN,"AkillTime",	NULL,	ts_help_set_akilltime, NULL, (void *)3600 },
	{"SVSJOIN",		&SecureServ.dosvsjoin,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoSvsJoin",	NULL,	ts_help_set_dojoin, NULL, (void *)1 },
	{"TREATCHANMSGASPM", &SecureServ.treatchanmsgaspm,SET_TYPE_CUSTOM,0,0,		NS_ULEVEL_ADMIN,"ChanMsgAsPM",	NULL,	ts_help_set_treatchanmsgaspm, ss_cmd_set_treatchanmsgaspm, (void *)0 },
	{"DOONJOIN",	&SecureServ.DoOnJoin,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoOnJoin",		NULL,	ts_help_set_doonjoin, NULL, (void *)1 },
	{"VERBOSE",		&SecureServ.verbose,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"Verbose",		NULL,	ts_help_set_verbose, NULL, (void *)1 },
	{"BOTECHO",		&SecureServ.BotEcho,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"BotEcho",		NULL,	ts_help_set_botecho, NULL, (void *)0 },
	{"BOTQUITMSG",	&SecureServ.botquitmsg,	SET_TYPE_MSG,		0,	BUFSIZE,	NS_ULEVEL_ADMIN,"BotQuitMsg",	NULL,	ts_help_set_botquitmsg, NULL, (void *)"Client quit" },
	{"MONCHANCYCLE",&SecureServ.monchancycle,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"MonChanCycle", NULL,	ts_help_set_monchancycle, NULL, (void *)1 },
	{"MONCHANCYCLETIME", &SecureServ.monchancycletime,SET_TYPE_INT,1,10000,	NS_ULEVEL_ADMIN,"MonitorBotCycle",NULL,	ts_help_set_monchancycletime, ss_cmd_set_monchancycletime_cb, (void *)1800 },
	{"CYCLETIME",	&SecureServ.stayinchantime,SET_TYPE_INT,	1,	1000,		NS_ULEVEL_ADMIN,"CycleTime",	NULL,	ts_help_set_cycletime, ss_cmd_set_cycletime_cb, (void *)60 },
	{"MONBOT",		NULL,					SET_TYPE_CUSTOM,	0,	0,			NS_ULEVEL_ADMIN,"MonBot",		NULL,	ts_help_set_monbot, ss_cmd_set_monbot, (void *)0 },
	{"UPDATEINFO",	NULL,					SET_TYPE_CUSTOM,	0,	0,			NS_ULEVEL_ADMIN,"UpdateUname",			NULL,	ts_help_set_updateinfo, ss_cmd_set_updateinfo, (void *)0 },
	{"AUTOUPDATE",	&SecureServ.autoupgrade,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"AutoUpdate",	NULL,	ts_help_set_autoupdate, ss_cmd_set_autoupdate_cb, (void *)0 },
	{"AUTOUPDATETIME",	&SecureServ.autoupgradetime,SET_TYPE_INT,	3600,	172800,			NS_ULEVEL_ADMIN,"AutoUpdateTime",	NULL,	ts_help_set_autoupdatetime, ss_cmd_set_autoupdatetime_cb, (void *)7200 },
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

static int ss_cmd_set_treatchanmsgaspm(CmdParams *cmdparams, SET_REASON reason) 
{
	switch( reason )
	{
		case SET_LOAD:
			break;
		case SET_LIST:
			irc_prefmsg (ss_bot, cmdparams->source, "TREATCHANMSGASPM: %s", SecureServ.treatchanmsgaspm ? "Enabled (Warning Read Help)" : "Disabled");
			break;
		case SET_CHANGE:
			if (cmdparams->ac < 2) {
				return NS_ERR_NEED_MORE_PARAMS;
			}			
			if ((!ircstrcasecmp(cmdparams->av[1], "ON"))) {
				irc_prefmsg (ss_bot, cmdparams->source, "\2Warning:\2");
				irc_prefmsg (ss_bot, cmdparams->source, "This option can consume a \2LOT\2 of CPU");
				irc_prefmsg (ss_bot, cmdparams->source, "When a Onjoin bot or MonBot is on large channel with lots of chatter");
				irc_prefmsg (ss_bot, cmdparams->source, "Its not a recomended configuration.");
				irc_prefmsg (ss_bot, cmdparams->source, "If you really want to enable this, type \2/msg %s SET TREATCHANMSGASPM IGOTLOTSOFCPU\2 to really enable this", ss_bot->name);
				return NS_SUCCESS;
			} else if (!ircstrcasecmp(cmdparams->av[1], "IGOTLOTSOFCPU")) {
				irc_prefmsg (ss_bot, cmdparams->source, "Channel Messages are now treated as PM Messages. You did read the help didn't you?");
				CommandReport(ss_bot, "%s has configured %s to treat Channels messages as PM messages", cmdparams->source);
				SecureServ.treatchanmsgaspm = 1;
				DBAStoreConfigInt ("ChanMsgAsPM", &SecureServ.treatchanmsgaspm);
				return NS_SUCCESS;
			} else if ((!ircstrcasecmp(cmdparams->av[1], "OFF"))) {
				irc_prefmsg (ss_bot, cmdparams->source, "Channel message checking is now disabled");
				CommandReport(ss_bot, "%s has disabled channel message checking", cmdparams->source);
				SecureServ.treatchanmsgaspm = 0;
				DBAStoreConfigInt ("ChanMsgAsPM", &SecureServ.treatchanmsgaspm);
				return NS_SUCCESS;
			} else {
				return NS_ERR_SYNTAX_ERROR;
			}
			break;
		default:
			break;
	}
	return NS_SUCCESS;
}
static int ss_cmd_set_monchancycletime_cb(CmdParams *cmdparams, SET_REASON reason) 
{
	if( reason == SET_CHANGE )
	{
		SetTimerInterval ("MonBotCycle", SecureServ.monchancycletime);
	}
	return NS_SUCCESS;
}
static int ss_cmd_set_cycletime_cb(CmdParams *cmdparams, SET_REASON reason) 
{
	if( reason == SET_CHANGE )
	{
		SetTimerInterval ("JoinNewChan", SecureServ.stayinchantime);
	}
	return NS_SUCCESS;
}

static int ss_cmd_viriversion(CmdParams *cmdparams)
{
	irc_prefmsg (ss_bot, cmdparams->source, "%d", SecureServ.datfileversion);
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

int ss_event_newchan( CmdParams *cmdparams )
{
	SET_SEGV_LOCATION();
	SetChannelModValue(cmdparams->channel, (void *) 0 );
	/* check if its a monchan and we are not in place */
	MonJoin( cmdparams->channel );
	return NS_SUCCESS;
}

int ss_event_joinchan(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	/* is channel exempt? */
	if( ModIsChannelExcluded( cmdparams->channel ) > 0 )
		return NS_SUCCESS;
	/* is user exempt */
	if( ModIsUserExcluded( cmdparams->source ) == NS_TRUE )
		return NS_SUCCESS;
	/* is channel already scanned */
	if( GetChannelModValue( cmdparams->channel ) == 0 ) {
		/* only set the channel to scanned if clean so defintion remains active */
		if( ScanChannelName( cmdparams->source, cmdparams->channel ) == 0 )
			SetChannelModValue( cmdparams->channel, ( void * ) 1 );
	}
	return NS_SUCCESS;
}

int ss_event_delchan(CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	ClearChannelModValue (cmdparams->channel);
	return NS_SUCCESS;
}

int ss_event_away(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	HelpersAway(cmdparams);
	ScanAwayMsg(cmdparams->source, cmdparams->source->user->awaymsg);
	return NS_SUCCESS;
}

int ss_event_topic(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	ScanTopic(cmdparams->source, cmdparams->channel->topic);
	return NS_SUCCESS;
}

static int ss_event_channelmessage (CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	/* first, if its the services channel, just ignore it */
	if (IsServicesChannel( cmdparams->channel )) {
		return NS_SUCCESS;
	}
	if (ModIsUserExcluded(cmdparams->source) == NS_TRUE) {
		dlog (DEBUG1, "User %s is exempt from Message Checking", cmdparams->source);
		return NS_SUCCESS;
	}
	ScanChanMsg(cmdparams->source, cmdparams->param);
	if (SecureServ.treatchanmsgaspm == 1) {
		ScanPrivmsg(cmdparams->source, cmdparams->param);
	}
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
	{ EVENT_QUIT, 			ss_event_quit,		EVENT_FLAG_EXCLUDE_MODME},
	{ EVENT_KILL, 			ss_event_quit},
	{ EVENT_JOIN, 			ss_event_joinchan,	EVENT_FLAG_EXCLUDE_MODME},
	{ EVENT_DELCHAN,		ss_event_delchan},
	{ EVENT_NICK,			ss_event_nick},
	{ EVENT_EMPTYCHAN,		ss_event_emptychan},	
	{ EVENT_KICKBOT,		ss_event_kickbot},
	{ EVENT_AWAY, 			ss_event_away},
	{ EVENT_TOPIC, 			ss_event_topic},
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
	ScanQuitMsg(cmdparams->source, cmdparams->param); 
	return NS_SUCCESS;
}

/* scan nickname changes */
static int ss_event_nick(CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	if (ModIsUserExcluded(cmdparams->source) == NS_FALSE) {
		/* check the nickname */
		ScanNick(cmdparams->source);
	}
	return NS_SUCCESS;
}

/* scan someone connecting */
static int ss_event_signon(CmdParams *cmdparams) 
{
	SET_SEGV_LOCATION();
	if (SecureServ.doscan == 0) 
		return NS_SUCCESS;
	if (IsNetSplit(cmdparams->source)) {
		dlog (DEBUG1, "Ignoring netsplit nick %s", cmdparams->source->name);
		return NS_SUCCESS;
	}
	if (ModIsUserExcluded(cmdparams->source) == NS_TRUE) {
		return NS_SUCCESS;
	}
	/* fizzer scan */
	if (SecureServ.dofizzer && ScanFizzer(cmdparams->source)) {
		return NS_SUCCESS;
	}
	/* check the nickname, ident, realname */
	if (ScanNick(cmdparams->source) && SecureServ.breakorcont != 0) {
		return NS_SUCCESS;
	}
	if (ScanIdent(cmdparams->source) && SecureServ.breakorcont != 0) {
		return NS_SUCCESS;
	}
	if (ScanRealname(cmdparams->source) && SecureServ.breakorcont != 0) {
		return NS_SUCCESS;
	}
	return NS_SUCCESS;
}

static int ss_event_versionreply(CmdParams *cmdparams) 
{
	int positive = 0;
	static int versioncount = 0;

	SET_SEGV_LOCATION();
	positive = ScanCTCPVersion(cmdparams->source, cmdparams->param);
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

int ModInit( void )
{
	SET_SEGV_LOCATION();
#ifdef WIN32
	old_malloc = pcre_malloc;
	old_free = pcre_free;
	pcre_malloc = os_malloc;
	pcre_free = os_free;
#endif
	os_memset (&SecureServ, 0, sizeof (SecureServ));
	ModuleConfig (ss_settings);
	InitScanner();
	InitOnJoinBots();
	return NS_SUCCESS;
}

int ScanMember( Channel *c, ChannelMember *m, void *v )
{
	if( ModIsUserExcluded( m->u ) == NS_FALSE ) {
		if( ScanChannelName( m->u, c ) == 0 ) {
			/* Channel is OK so mark as clean */
			SetChannelModValue( c, (void *) 1 );
			return NS_TRUE;
		}
	}
	return NS_FALSE;
}

int ScanChannel (Channel *c, void *v)
{
	GetChannelMembers (c, ScanMember, NULL);
	return NS_FALSE;
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
	SET_SEGV_LOCATION();
	ss_bot = AddBot (&ss_botinfo);
	if (!ss_bot) {
		return NS_FAILURE;
	}
	InitHelpers();
	if (SecureServ.verbose) {
		irc_chanalert (ss_bot, "%d Trojans Patterns loaded", SecureServ.defcount);
	}
	srand(hash_count(GetChannelHash()));
	/* kick of the autojoin timer */
	AddTimer (TIMER_TYPE_INTERVAL, JoinNewChan, "JoinNewChan", SecureServ.stayinchantime);
	AddTimer (TIMER_TYPE_INTERVAL, MonBotCycle, "MonBotCycle", SecureServ.monchancycletime);
	dns_lookup("secure.irc-chat.net",  adns_r_a, GotHTTPAddress, "SecureServ Update Server");
	LoadMonChans();
	if (SecureServ.autoupgrade == 1) {
		AddTimer (TIMER_TYPE_INTERVAL, AutoUpdate, "AutoUpdate", SecureServ.autoupgradetime);
	}
	/* here, we run though the channel lists, as when we were booting, we were not checking. */
	GetChannelList (ScanChannel, NULL);
	return NS_SUCCESS;
};

/** Fini module
 * This is required if you need to do cleanup of your module when it ends
 */
int ModFini( void )
{
	SET_SEGV_LOCATION();
	FiniHelpers();
	FiniOnJoinBots();
#ifdef WIN32
	pcre_malloc = old_malloc;
	pcre_free = old_free;
#endif
	return NS_SUCCESS;
}

int ModAuthUser (Client *u)
{
	UserDetail *ud;

	ud = (UserDetail *)GetUserModValue (u);
	if (ud && ud->type == USER_HELPER) {
		return 30;
	}
	return 0;
}

