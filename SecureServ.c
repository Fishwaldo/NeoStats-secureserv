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

#include "neostats.h"
#include "SecureServ.h"

static int ScanNick(char **av, int ac);
static int LoadConfig(void);
static int check_version_reply(User* u, char **av, int ac);
static int do_status(User *u, char **av, int ac);
static int NickChange(char **av, int ac);
static int DelNick(char **av, int ac);
static int ss_kick_chan(char **argv, int ac);

char s_SecureServ[MAXNICK];
static ModUser *ss_bot;

ModuleInfo __module_info = {
	"SecureServ",
	"A Trojan Scanning Bot",
	MODULE_VERSION,
	__DATE__,
	__TIME__
};

int do_viriversion(User *u, char **av, int ac)
{
	prefmsg(u->nick, s_SecureServ, "%d", SecureServ.viriversion);
	return 0;
}

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
	{"VERSION",	do_viriversion,	0,	NS_ULEVEL_OPER,	NULL, 				NULL},
	{NULL,		NULL,			0, 	0,				NULL, 				NULL}
};

int __ModuleAuth (User * u)
{
	UserDetail *ud;
	ud = (UserDetail *)u->moddata[SecureServ.modnum];
	if (ud) {
		if (ud->type == USER_HELPER) {
			return 30;
		}
	}
	return 0;
}

static int do_set_updateinfo(User *u, char **av, int ac) 
{
	SET_SEGV_LOCATION();
	if (!strcasecmp(av[2], "LIST")) {
		prefmsg(u->nick, s_SecureServ, "UPDATEINFO:   %s", strlen(SecureServ.updateuname) > 0 ? "Set" : "Not Set");
		if (strlen(SecureServ.updateuname)) {
			prefmsg(u->nick, s_SecureServ, "Update Username is %s, Password is %s", SecureServ.updateuname, SecureServ.updatepw);
		}
		return 1;
	}
	if (ac < 5) {
		prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set", s_SecureServ);
		return 1;
	}
	SetConf((void *)av[3], CFGSTR, "UpdateUname");
	SetConf((void *)av[4], CFGSTR, "UpdatePassword");
	strlcpy(SecureServ.updateuname, av[3], MAXNICK);
	strlcpy(SecureServ.updatepw, av[4], MAXNICK);
	chanalert(s_SecureServ, "%s changed the Update Username and Password", u->nick);
	prefmsg(u->nick, s_SecureServ, "Update Username and Password has been updated to %s and %s", SecureServ.updateuname, SecureServ.updatepw);
	return 1;
}
static int do_set_treatchanmsgaspm(User *u, char **av, int ac) 
{
	if (!strcasecmp(av[2], "LIST")) {
		prefmsg(u->nick, s_SecureServ, "TREATCHANMSGASPM: %s", SecureServ.treatchanmsgaspm ? "Enabled (Warning Read Help)" : "Disabled");
		return 1;
	}
	if (ac < 4) {
		prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
		return 1;
	}			
	if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
		prefmsg(u->nick, s_SecureServ, "\2Warning:\2");
		prefmsg(u->nick, s_SecureServ, "This option can consume a \2LOT\2 of CPU");
		prefmsg(u->nick, s_SecureServ, "When a Onjoin bot or MonBot is on large channel with lots of chatter");
		prefmsg(u->nick, s_SecureServ, "Its not a recomended configuration.");
		prefmsg(u->nick, s_SecureServ, "If you really want to enable this, type \2/msg %s SET TREATCHANMSGASPM IGOTLOTSOFCPU\2 to really enable this", s_SecureServ);
		return 1;
	} else if (!strcasecmp(av[3], "IGOTLOTSOFCPU")) {
		prefmsg(u->nick, s_SecureServ, "Channel Messages are now treated as PM Messages. You did read the help didn't you?");
		chanalert(s_SecureServ, "%s has configured %s to treat Channels messages as PM messages", u->nick, s_SecureServ);
		SetConf((void *)1, CFGINT, "ChanMsgAsPM");
		SecureServ.treatchanmsgaspm = 1;
		return 1;
	} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
		prefmsg(u->nick, s_SecureServ, "Version Checking is now Disabled");
		chanalert(s_SecureServ, "%s has disabled Version Checking", u->nick);
		SetConf((void *)0, CFGINT, "ChanMsgAsPM");
		SecureServ.treatchanmsgaspm = 0;
		return 1;
	} else {
		prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
		return 1;
	}
	return 1;
}
static int do_set_monchancycletime(User *u, char **av, int ac) 
{
	change_mod_timer_interval ("MonitorBotCycle", SecureServ.monchancycletime);
	return 1;
}
static int do_set_cycletime(User *u, char **av, int ac) 
{
	change_mod_timer_interval ("JoinNewChan", SecureServ.stayinchantime);
	return 1;
}

static int do_set_autoupdate(User *u, char **av, int ac) 
{
	if (!strcasecmp(av[2], "LIST")) {
		prefmsg(u->nick, s_SecureServ, "AUTOUPDATE:   %s", SecureServ.autoupgrade ? "Enabled" : "Disabled");
		return 1;
	}
	if (ac < 4) {
		prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
		return 1;
	}			
	if ((!strcasecmp(av[3], "YES")) || (!strcasecmp(av[3], "ON"))) {
		if ((strlen(SecureServ.updateuname) > 0) && (strlen(SecureServ.updatepw) > 0)) {
			prefmsg(u->nick, s_SecureServ, "AutoUpdate Mode is now enabled");
			chanalert(s_SecureServ, "%s enabled AutoUpdate Mode", u->nick);
			SetConf((void *)1, CFGINT, "AutoUpdate");
			SecureServ.autoupgrade = 1;
			return 1;
		} else {
			prefmsg(u->nick, s_SecureServ, "You can not enable AutoUpdate, as you have not set a username and password");
			return 1;
		}
	} else if ((!strcasecmp(av[3], "NO")) || (!strcasecmp(av[3], "OFF"))) {
		prefmsg(u->nick, s_SecureServ, "AutoUpdate Mode is now disabled");
		chanalert(s_SecureServ, "%s disabled AutoUpdate Mode", u->nick);
		SetConf((void *)0, CFGINT, "AutoUpdate");
		SecureServ.autoupgrade = 0;
		return 1;
	}
	return 1;
}
static int do_set_sampletime(User *u, char **av, int ac) 
{
	int i, j;
	if (!strcasecmp(av[2], "LIST")) {
		if (SecureServ.FloodProt) {
			prefmsg(u->nick, s_SecureServ, "SAMPLETIME:   %d/%d Seconds", SecureServ.JoinThreshold, SecureServ.sampletime);
		}
		return 1;
	}
	if (ac < 5) {
		prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
		return 1;
	}			
	i = atoi(av[3]);
	j = atoi(av[4]);	
	if ((i <= 0) || (i > 1000)) {
		prefmsg(u->nick, s_SecureServ, "SampleTime Value out of Range.");
		return 1;
	}
	if ((j <= 0) || (i > 1000)) {
		prefmsg(u->nick, s_SecureServ, "Threshold Value is out of Range");
		return 1;
	}
	/* if we get here, all is ok */
	SecureServ.sampletime = i;
	SecureServ.JoinThreshold = j;
	prefmsg(u->nick, s_SecureServ, "Flood Protection is now enabled at %d joins in %d Seconds", j, i);
	chanalert(s_SecureServ, "%s Set Flood Protection to %d joins in %d Seconds", u->nick, j, i);
	SetConf((void *)i, CFGINT, "SampleTime");
	SetConf((void *)j, CFGINT, "JoinThreshold");
	return 1;
}

static bot_setting ss_settings[]=
{
	{"NICK",		&s_SecureServ,			SET_TYPE_NICK,		0,	MAXNICK, 	NS_ULEVEL_ADMIN, "Nick",		NULL,	ns_help_set_nick, NULL  },
	{"USER",		&SecureServ.user,		SET_TYPE_USER,		0,	MAXUSER, 	NS_ULEVEL_ADMIN, "User",		NULL,	ns_help_set_user, NULL  },
	{"HOST",		&SecureServ.host,		SET_TYPE_HOST,		0,	MAXHOST, 	NS_ULEVEL_ADMIN, "Host",		NULL,	ns_help_set_host, NULL  },
	{"REALNAME",	&SecureServ.realname,	SET_TYPE_REALNAME,	0,	MAXREALNAME,NS_ULEVEL_ADMIN, "RealName",	NULL,	ns_help_set_realname, NULL  },
	{"SPLITTIME",	&SecureServ.timedif,	SET_TYPE_INT,		0,	1000,		NS_ULEVEL_ADMIN, "SplitTime",	NULL,	ts_help_set_splittime, NULL },
	{"CHANKEY",		&SecureServ.ChanKey,	SET_TYPE_STRING,	0,	CHANLEN,	NS_ULEVEL_ADMIN, "ChanKey",		NULL,	ts_help_set_chankey, NULL },
	{"VERSION",		&SecureServ.doscan,		SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoVersionScan",NULL,	ts_help_set_version, NULL },
	{"SIGNONMSG",	&SecureServ.signonscanmsg,	SET_TYPE_MSG,	0,	0,			NS_ULEVEL_ADMIN,"SignOnMsg",	NULL,	ts_help_set_signonmsg, NULL },
	{"BOTQUITMSG",	&SecureServ.botquitmsg,	SET_TYPE_MSG,		0,	0,			NS_ULEVEL_ADMIN,"BotQuitMsg",	NULL,	ts_help_set_botquitmsg, NULL },
	{"AKILLMSG",	&SecureServ.akillinfo,	SET_TYPE_MSG,		0,	0,			NS_ULEVEL_ADMIN,"AkillMsg",		NULL,	ts_help_set_akillmsg, NULL },
	{"NOHELPMSG",	&SecureServ.nohelp,		SET_TYPE_MSG,		0,	0,			NS_ULEVEL_ADMIN,"NoHelpMsg",	NULL,	ts_help_set_nohelpmsg, NULL },
	{"HELPCHAN",	&SecureServ.HelpChan,	SET_TYPE_CHANNEL,	0,	0,			NS_ULEVEL_ADMIN,"HelpChan",		NULL,	ts_help_set_helpchan, NULL },
	{"AUTOSIGNOUT",	&SecureServ.signoutaway,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoAwaySignOut",NULL,	ts_help_set_autosignout, NULL },
	{"JOINHELPCHAN",&SecureServ.joinhelpchan,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoJoinHelpChan",NULL,	ts_help_set_joinhelpchan, NULL },
	{"REPORT",		&SecureServ.report,		SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoReport",		NULL,	ts_help_set_report, NULL },
	{"FLOODPROT",	&SecureServ.FloodProt,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoFloodProt",	NULL,	ts_help_set_floodprot, NULL },
	{"DOPRIVCHAN",	&SecureServ.doprivchan,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoPrivChan",	NULL,	ts_help_set_doprivchan, NULL },
	{"CHECKFIZZER",	&SecureServ.dofizzer,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"FizzerCheck",	NULL,	ts_help_set_checkfizzer, NULL },
	{"MULTICHECK",	&SecureServ.breakorcont,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"MultiCheck",	NULL,	ts_help_set_multicheck, NULL },
	{"AKILL",		&SecureServ.doakill,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoAkill",		NULL,	ts_help_set_akill, NULL },
	{"AKILLTIME",	&SecureServ.akilltime,	SET_TYPE_INT,		0,	0,			NS_ULEVEL_ADMIN,"AkillTime",	NULL,	ts_help_set_akilltime, NULL },
	{"CHANLOCKTIME",&SecureServ.closechantime,SET_TYPE_INT,		0,	600,		NS_ULEVEL_ADMIN,"ChanLockTime", NULL,	ts_help_set_chanlocktime, NULL },
	{"NFCOUNT",		&SecureServ.nfcount,	SET_TYPE_INT,		0,	100,		NS_ULEVEL_ADMIN,"NFCount",		NULL,	ts_help_set_nfcount, NULL },
	{"DOJOIN",		&SecureServ.dosvsjoin,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoSvsJoin",	NULL,	ts_help_set_dojoin, NULL },
	{"DOONJOIN",	&SecureServ.DoOnJoin,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"DoOnJoin",		NULL,	ts_help_set_doonjoin, NULL },
	{"BOTECHO",		&SecureServ.BotEcho,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"BotEcho",		NULL,	ts_help_set_botecho, NULL },
	{"VERBOSE",		&SecureServ.verbose,	SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"Verbose",		NULL,	ts_help_set_verbose, NULL },
	{"MONCHANCYCLE",&SecureServ.monchancycle,SET_TYPE_BOOLEAN,	0,	0,			NS_ULEVEL_ADMIN,"MonChanCycle", NULL,	ts_help_set_monchancycle, NULL },
	{"TREATCHANMSGASPM", &SecureServ.treatchanmsgaspm,SET_TYPE_CUSTOM,0,0,		NS_ULEVEL_ADMIN,"ChanMsgAsPM",	NULL,	ts_help_set_treatchanmsgaspm, do_set_treatchanmsgaspm },
	{"MONCHANCYCLETIME", &SecureServ.monchancycletime,SET_TYPE_CUSTOM,1,10000,	NS_ULEVEL_ADMIN,"MonitorBotCycle",NULL,	ts_help_set_monchancycletime, do_set_monchancycletime },
	{"CYCLETIME",	&SecureServ.stayinchantime,SET_TYPE_CUSTOM,	1,	1000,		NS_ULEVEL_ADMIN,"CycleTime",	NULL,	ts_help_set_cycletime, do_set_cycletime },
	{"MONBOT",		NULL,					SET_TYPE_CUSTOM,	0,	0,			NS_ULEVEL_ADMIN,NULL,			NULL,	ts_help_set_monbot, do_set_monbot },
	{"AUTOUPDATE",	NULL,					SET_TYPE_CUSTOM,	0,	0,			NS_ULEVEL_ADMIN,NULL,			NULL,	ts_help_set_autoupdate, do_set_autoupdate },
	{"SAMPLETIME",	NULL,					SET_TYPE_CUSTOM,	0,	0,			NS_ULEVEL_ADMIN,NULL,			NULL,	ts_help_set_sampletime, do_set_sampletime },
	{"UPDATEINFO",	NULL,					SET_TYPE_CUSTOM,	0,	0,			NS_ULEVEL_ADMIN,NULL,			NULL,	ts_help_set_updateinfo, do_set_updateinfo },
	{"ONJOINBOTMODES",&onjoinbot_modes,		SET_TYPE_STRING,	0,	MODESIZE,	NS_ULEVEL_ADMIN,"OnJoinBotModes",NULL,	ts_help_set_onjoinbotmodes, NULL },
	{NULL,			NULL,					0,					0,	0, 			0,				NULL,			NULL,	NULL, NULL },
};

static int do_status(User *u, char **av, int ac)
{
	SET_SEGV_LOCATION();
	prefmsg(u->nick, s_SecureServ, "SecureServ Status:");
	prefmsg(u->nick, s_SecureServ, "==================");
	prefmsg(u->nick, s_SecureServ, "Virus Patterns Loaded: %d", ViriCount());
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
	prefmsg(u->nick, s_SecureServ, "Channel Messages Checked: %d", SecureServ.trigcounts[DET_CHANMSG]);
	prefmsg(u->nick, s_SecureServ, "Channel Messages Acted on: %d", SecureServ.actioncounts[DET_CHANMSG]);
	prefmsg(u->nick, s_SecureServ, "Channel Messages Definitions: %d", SecureServ.definitions[DET_CHANMSG]);
	prefmsg(u->nick, s_SecureServ, "Built-In Checks Run: %d", SecureServ.actioncounts[DET_BUILTIN]);
	prefmsg(u->nick, s_SecureServ, "Built-In Checks Acted on: %d", SecureServ.actioncounts[DET_BUILTIN]);
	prefmsg(u->nick, s_SecureServ, "Built-In Functions: %d", SecureServ.definitions[DET_BUILTIN]);
	prefmsg(u->nick, s_SecureServ, "AV Channel Helpers Logged in: %d", SecureServ.helpcount);
	prefmsg(u->nick, s_SecureServ, "Current Top AJPP: %d (in %d Seconds): %s", SecureServ.MaxAJPP, SecureServ.sampletime, SecureServ.MaxAJPPChan);
	if (strlen(SecureServ.lastchan) > 0) 
		prefmsg(u->nick, s_SecureServ, "Currently Checking %s with %s", SecureServ.lastchan, SecureServ.lastnick);
	prefmsg(u->nick, s_SecureServ, "End of List.");
	
	return 1;
}

static int Online(char **av, int ac) 
{
	Chans *c;
	User *u;
	lnode_t *lnode;
	hnode_t *hnode;
	hscan_t hs;
	
	SET_SEGV_LOCATION();
	ss_bot = init_mod_bot(s_SecureServ, SecureServ.user, SecureServ.host, SecureServ.realname,
		services_bot_modes, BOT_FLAG_DEAF, ss_commands, ss_settings, __module_info.module_name);
	HelpersInit();
	if (SecureServ.verbose) {
		chanalert(s_SecureServ, "%d Trojans Patterns loaded", ViriCount());
	}
	srand(hash_count(ch));
	/* kick of the autojoin timer */
	add_mod_timer("JoinNewChan", "RandomJoinChannel", __module_info.module_name, SecureServ.stayinchantime);
	add_mod_timer("MonBotCycle", "MonitorBotCycle", __module_info.module_name, SecureServ.monchancycletime);
	/* start cleaning the nickflood list now */
	/* every sixty seconds should keep the list small, and not put *too* much load on NeoStats */
	add_mod_timer("CleanNickFlood", "CleanNickFlood", __module_info.module_name, 60);
	add_mod_timer("CheckLockChan", "CheckLockedChans", __module_info.module_name, 60);
	dns_lookup("secure.irc-chat.net",  adns_r_a, GotHTTPAddress, "SecureServ Update Server");
	SecureServ.isonline = 1;
	LoadMonChans();

	/* here, we run though the channel lists, as when we were booting, we were not checking. */
	hash_scan_begin(&hs, ch);
	while ((hnode = hash_scan_next(&hs)) != NULL) {
		c = hnode_get(hnode);
		if (!c)
			continue;

		/* now scan channel members */
		lnode = list_first(c->chanmembers);
		while (lnode) {
			u = finduser(lnode_get(lnode));
			if (SS_IsUserExempt(u) > 0) {
				lnode = list_next(c->chanmembers, lnode);
				continue;
			}
			if (u && ScanChan(u, c) == 0) {
				break;
			}
			lnode = list_next(c->chanmembers, lnode);
		}
	}

	return 1;
};

static int LoadConfig(void) 
{
	char *tmp;

	SET_SEGV_LOCATION();

	if (GetConf((void *) &tmp, CFGSTR, "Nick") < 0) {
		strlcpy(s_SecureServ, "SecureServ", MAXNICK);
	} else {
		strlcpy(s_SecureServ, tmp, MAXNICK);
		free(tmp);
	}
	if (GetConf((void *) &tmp, CFGSTR, "User") < 0) {
		strlcpy(SecureServ.user, "TS", MAXUSER);
	} else {
		strlcpy(SecureServ.user, tmp, MAXUSER);
		free(tmp);
	}
	if (GetConf((void *) &tmp, CFGSTR, "Host") < 0) {
		strlcpy(SecureServ.host, me.name, MAXHOST);
	} else {
		strlcpy(SecureServ.host, tmp, MAXHOST);
		free(tmp);
	}
	if (GetConf((void *) &tmp, CFGSTR, "RealName") < 0) {
		strlcpy(SecureServ.realname, "Trojan Scanning Bot", MAXREALNAME);
	} else {
		strlcpy(SecureServ.realname, tmp, MAXREALNAME);
		free(tmp);
	}
	if (GetConf((void *) &tmp, CFGSTR, "OnJoinBotModes") < 0) {
		strlcpy(onjoinbot_modes, "+", MODESIZE);
	} else {
		strlcpy(onjoinbot_modes, tmp, MODESIZE);
		free(tmp);
	}
	if(GetConf((void *)&SecureServ.FloodProt, CFGBOOL, "DoFloodProt") <= 0) {
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
	if(GetConf((void *)&SecureServ.doscan, CFGBOOL, "DoVersionScan") <= 0) {
		/* not configured, don't scan */
		SecureServ.doscan = 0;
	} 
	if(GetConf((void *)&SecureServ.doprivchan, CFGBOOL, "DoPrivChan") <= 0) {
		/* not configured, do scan */
		SecureServ.doprivchan = 1;
	} 
	if (GetConf((void *)&SecureServ.timedif, CFGINT, "SplitTime") <= 0) {
		/* use Default */
		SecureServ.timedif = 300;
	}
	if (GetConf((void *)&SecureServ.signoutaway, CFGBOOL, "DoAwaySignOut") <= 0) {
		/* yes */
		SecureServ.signoutaway = 1;
	}
	if (GetConf((void *)&SecureServ.report, CFGBOOL, "DoReport") <= 0) {
		/* yes */
		SecureServ.report = 1;
	}
	if (GetConf((void *)&SecureServ.joinhelpchan, CFGBOOL, "DoJoinHelpChan") <= 0) {
		/* yes */
		SecureServ.joinhelpchan = 1;
	}
	if (GetConf((void *)&SecureServ.verbose, CFGBOOL, "Verbose") <= 0){
		/* yes */
		SecureServ.verbose = 1;
	}
	if (GetConf((void *)&SecureServ.monchancycle, CFGBOOL, "MonChanCycle") <= 0){
		/* yes */
		SecureServ.monchancycle = 1;
	}
	if (GetConf((void *)&SecureServ.stayinchantime, CFGINT, "CycleTime") <= 0) {
		/* 60 seconds */
		SecureServ.stayinchantime = 60;
	}
	if (GetConf((void *)&SecureServ.monchancycletime, CFGINT, "MonCycleTime") <= 0) {
		/* 30 min cycle time */
		SecureServ.monchancycletime = 1800;
	}
	if (GetConf((void *)&SecureServ.nfcount, CFGINT, "NFCount") <= 0) {
		/* 5 in 10 seconds */
		SecureServ.nfcount = 5;
	}
	if (GetConf((void *)&SecureServ.autoupgrade, CFGBOOL, "AutoUpdate") <= 0) {
		/* disable autoupgrade is the default */
		SecureServ.autoupgrade = 0;
	}
	if (GetConf((void *)&SecureServ.treatchanmsgaspm, CFGBOOL, "ChanMsgAsPM") <= 0) {
		/* disable is the default */
		SecureServ.treatchanmsgaspm = 0;
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
	if (GetConf((void *)&SecureServ.dofizzer, CFGBOOL, "FizzerCheck") <= 0) {
		/* scan for fizzer is the default */
		SecureServ.dofizzer = 1;
	}
	if (GetConf((void *)&SecureServ.breakorcont, CFGBOOL, "MultiCheck") <= 0) {
		/* break is the default is the default */
		SecureServ.breakorcont = 1;
	}
	if (GetConf((void *)&SecureServ.DoOnJoin, CFGBOOL, "DoOnJoin") <= 0) {
		/* yes is the default is the default */
		SecureServ.DoOnJoin = 1;
	}
	if (GetConf((void *)&SecureServ.BotEcho, CFGBOOL, "BotEcho") <= 0) {
		/* yes is the default is the default */
		SecureServ.BotEcho = 0;
	}	
	if (GetConf((void *)&SecureServ.doakill, CFGBOOL, "DoAkill") <= 0) {
		/* we akill is the default */
		SecureServ.doakill = 1;
	}
	if (GetConf((void *)&SecureServ.akilltime, CFGINT, "AkillTime") <= 0) {
		/* 1 hour is the default */
		SecureServ.akilltime = 3600;
	}
	if (GetConf((void *)&SecureServ.dosvsjoin, CFGBOOL, "DoSvsJoin") <= 0) {
		/* scan for fizzer is the default */
		SecureServ.dosvsjoin = 1;
	}
	if (GetConf((void *)&SecureServ.sampletime, CFGINT, "SampleTime") <= 0) {
		/* 5 secondsis the default */
		SecureServ.sampletime = 5;
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
	if (GetConf((void *)&tmp, CFGSTR, "BotQuitMsg") <= 0) {
		strlcpy(SecureServ.botquitmsg, "Client quit", BUFSIZE);
	} else {
		strlcpy(SecureServ.botquitmsg, tmp, BUFSIZE);
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
	return 1;
}
int ss_new_chan(char **av, int ac)
{
	Chans* c;
	ChannelDetail *cd;

	SET_SEGV_LOCATION();
	/* find the chan in the Core */
	c = findchan(av[0]);
	if (!c) {
		nlog(LOG_WARNING, LOG_MOD, "newchan: Can't Find Channel %s", av[0]);
		return -1;
	}
	cd = malloc(sizeof(ChannelDetail));
	cd->scanned = 0;
	c->moddata[SecureServ.modnum] = cd;
	return 1;
}

int ss_join_chan(char **av, int ac)
{
	Chans* c;
	User* u;
	ChannelDetail *cd;

	SET_SEGV_LOCATION();
	/* if we are not online, exit this */
	if (!SecureServ.isonline) {
		return -1;
	}

	/* find the chan in the Core */
	c = findchan(av[0]);
	if (!c) {
		nlog(LOG_WARNING, LOG_MOD, "joinchan: Can't Find Channel %s", av[0]);
		return -1;
	}
	
	/* is it exempt? */
	if (SS_IsChanExempt(c) > 0) {
		return -1;
	}

	u = finduser(av[1]);
	if (!u) {
		nlog(LOG_WARNING, LOG_MOD, "Can't find nick %s", av[1]);
		return -1;
	}
	
	/* check if its a monchan and we are not in place */
	if (c->cur_users == 1) 
		MonJoin(c);
	
	/* how about the user, is he exempt? */
	if (SS_IsUserExempt(u) > 0) {
		return -1;
	}
	
	/* first, check if this is a *bad* channel only if its the first person to join.*/
	/* NOTE: if its a monchan, c->cur_users will be 2 here, as our MonBot would have joined above 
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
	cd = c->moddata[SecureServ.modnum];
	/* if cd doesn't exist, soemthing major is wrong */
	if(cd && cd->scanned == 0) {
		/* Only set the channel to scanned if it is a clean channel 
		 * otherwise we may miss scans
		 */
		if(ScanChan(u, c) == 0) {
			cd->scanned = 1;
		}
	}
	if(JoinFloodJoinChan(u, c))
		return 1;

	
	return 1;
}
int ss_part_chan(char **av, int ac) 
{
	Chans *c;
	
	SET_SEGV_LOCATION();
	c = findchan(av[0]);
	if (!c) {
		return -1;
	}
	MonBotDelChan(c);
	OnJoinDelChan(c);
	return 1;
}

int ss_del_chan(char **av, int ac) 
{
	Chans* c;
	ChannelDetail *cd;

	SET_SEGV_LOCATION();
	c = findchan(av[0]);
	if (!c) {
		nlog(LOG_WARNING, LOG_MOD, "Can't find Channel %s", av[0]);
		return -1;
	}
	cd = c->moddata[SecureServ.modnum];
	free(cd);
	c->moddata[SecureServ.modnum] = NULL;

	JoinFloodDelChan(c);

	return 1;
}

int ss_user_away(char **av, int ac)
{
	SET_SEGV_LOCATION();
	HelpersAway(av, ac);
	/* TODO: scan away messages for spam */
	return 1;
}
/* this is a future s->flags define that we dont use yet */
#ifndef NS_FLAGS_NETJOIN
/* @brief we allocate the moduledata struct for the server so we can check for TS problems with servers */

int ss_new_server(char **av, int ac)
{
	Server *s;
	ServerDetail *sd;
	s = findserver(av[0]);
	if (s) {
		sd = malloc(sizeof(ServerDetail));
		sd->tsoutcount = 0;
		s->moddata[SecureServ.modnum] = sd;
	}
	return 1;
}

/* @brief We de-allocate the serverdetail struct for the server */

int ss_quit_server(char **av, int ac)
{
	Server *s;
	s = findserver(av[0]);
	if (s) {
		free(s->moddata[SecureServ.modnum]);
	}
	return 1;
}

#endif

static int event_private(char **av, int ac) 
{
	User *u;

	SET_SEGV_LOCATION();
	u = finduser(av[0]); 
	if (!u) { 
		nlog(LOG_WARNING, LOG_CORE, "Unable to find user %s (ts)", av[0]); 
		return -1; 
	} 
	/* first, figure out what bot its too */
	if (strcasecmp(av[1], s_SecureServ)) {
		/* Check it is intended for an onjoin bot */
		if(strcasecmp(SecureServ.monbot, av[1]) == 0 || strcasecmp(SecureServ.lastnick, av[1]) == 0) {
			OnJoinBotMsg(u, av[1], av[2]);
		}		
		return -1;
	}
	return 1;
}

static int event_notice(char **av, int ac) 
{
	User *u;

	SET_SEGV_LOCATION();
	u = finduser(av[0]); 
	if(!u) {
		return 0;
	}
	/* if its not a ctcp message, it is probably a notice for the ONJOIN bots */
	if (av[2][0] != '\1') {
		/* Check it is intended for an onjoin bot */
		if(strcasecmp(SecureServ.monbot, av[1]) == 0 || strcasecmp(SecureServ.lastnick, av[1]) == 0) {
			OnJoinBotMsg(u, av[1], av[2]);
		}		
		return 0;
	}

	if (!strncasecmp(av[2], "\1version", 8)) {
		check_version_reply(u, av, ac);
	}				
	return 1;
}

static int event_cprivate(char **av, int ac) 
{
	User *u;

	SET_SEGV_LOCATION();

	/* first, if its the services channel, just ignore it */
	if (!strcasecmp(av[1], me.chan)) {
		return -1;
	}

	u = finduser(av[0]); 
	if (!u) { 
		return -1; 
	} 

	/* otherwise, just pass it to the ScanMsg function */
	ScanMsg(u, av[2], 1);
	return 1;
}

static int event_cnotice(char **av, int ac) 
{
	User *u;

	SET_SEGV_LOCATION();

	/* first, if its the services channel, just ignore it */
	if (!strcasecmp(av[1], me.chan)) {
		return -1;
	}

	u = finduser(av[0]); 
	if(!u) {
		return -1; 
	}

	/* otherwise, just pass it to the ScanMsg function */
	ScanMsg(u, av[2], 1);

	return 1;
}

static int event_botkill(char **av, int ac) 
{
	SET_SEGV_LOCATION();
	/* Check the mon bot first */
	if(CheckMonBotKill(av[0])!=0) {
		return 1;
	}
	/* What else should we check? */
	return 1;
}

EventFnList __module_events[] = {
 	{ EVENT_ONLINE, 	Online},
	{ EVENT_SIGNON, 	ScanNick},
	{ EVENT_SIGNOFF, 	DelNick},
	{ EVENT_KILL, 		DelNick},
	{ EVENT_JOINCHAN, 	ss_join_chan},
	{ EVENT_DELCHAN,	ss_del_chan},
	{ EVENT_PARTCHAN,	ss_part_chan},
	{ EVENT_NICKCHANGE, NickChange},
	{ EVENT_KICK,		ss_kick_chan},
	{ EVENT_AWAY, 		ss_user_away},
	{ EVENT_NEWCHAN,	ss_new_chan},
#ifndef NS_FLAGS_NETJOIN
	{ EVENT_SERVER,		ss_new_server},
	{ EVENT_SQUIT,		ss_quit_server},
#endif
	{ EVENT_PRIVATE, 	event_private},
	{ EVENT_NOTICE, 	event_notice},
	{ EVENT_CPRIVATE, 	event_cprivate},
	{ EVENT_CNOTICE, 	event_cnotice},
	{ EVENT_BOTKILL, 	event_botkill},
	{ NULL, 			NULL}
};

static int DelNick(char **av, int ac) 
{
	User *u;

	SET_SEGV_LOCATION();
	u = finduser(av[0]);
	NickFloodSignOff(av[0]);
	/* u->moddata is free'd in helpers_signoff */
	if(u) {
		HelpersSignoff(u);
	}
	return 1;
}

/* scan nickname changes */
static int NickChange(char **av, int ac) 
{
	User *u;
	
	SET_SEGV_LOCATION();
	if (!SecureServ.isonline) {
		return 1;
	}
	
	u = finduser(av[1]);
	if (!u) {
		nlog(LOG_WARNING, LOG_MOD, "Cant Find user %s", av[1]);
		return 1;
	}
	
	/* Possible memory leak here if a helper changes nick? */
	u->moddata[SecureServ.modnum] = NULL;
	
	if (SS_IsUserExempt(u) > 0) {
		nlog(LOG_DEBUG1, LOG_MOD, "Bye, I'm Exempt %s", u->nick);
		return -1;
	}
	/* is it a nickflood? */
	CheckNickFlood(u);

	/* check the nickname */
	if(ScanUser(u, SCAN_NICK)) {
		return 1;
	}

	return 1;
}

/* scan someone connecting */
static int ScanNick(char **av, int ac) 
{
	User *u;
#ifndef NS_FLAGS_NETJOIN
	ServerDetail *sd;
#endif

	SET_SEGV_LOCATION();
	/* don't do anything if NeoStats hasn't told us we are online yet */
	if (!SecureServ.isonline)
		return 0;
							
	u = finduser(av[0]);
	if (!u) {
		nlog(LOG_WARNING, LOG_MOD, "Ehhh, Can't find user %s", av[0]);
		return -1;
	}
	
	if (SS_IsUserExempt(u) > 0) {
		return -1;
	}

	/* fizzer scan */
	if (SecureServ.dofizzer == 1) {
		if(ScanFizzer(u)) {
			return 1;
		}
	}
	/* check the nickname, ident, realname */
	if(ScanUser(u, SCAN_NICK|SCAN_IDENT|SCAN_REALNAME)) {
		return 1;
	}

	if (SecureServ.doscan == 0) 
		return -1;
#ifndef NS_FLAGS_NETJOIN
	sd = u->server->moddata[SecureServ.modnum];

	if (time(NULL) - u->TS > SecureServ.timedif) {
		if (sd) {
			sd->tsoutcount++;
			if (sd->tsoutcount >= 10) {
				chanalert(s_SecureServ, "Hrm. Is the time on %s correct? There are a lot of Netsplit Nicks", u->server->name);
				globops(s_SecureServ, "Hrm. TS on %s seems to be incorrect. You should fix this ASAP.", u->server->name);
				/* reset so we don't blast all the time */
				sd->tsoutcount = 0;
			}
		}
		nlog(LOG_DEBUG1, LOG_MOD, "Netsplit Nick %s, Not Scanning %d > %d", av[0], (int)(time(NULL) - u->TS), SecureServ.timedif);
		return -1;
	} else {
		if (sd) sd->tsoutcount = 0;
	}
#else
	if (u->flags && NS_FLAGS_NETJOIN)
		return -1;
#endif
	prefmsg(u->nick, s_SecureServ, SecureServ.signonscanmsg);
	privmsg(u->nick, s_SecureServ, "\1VERSION\1");
	return 1;
}

static int check_version_reply(User* u, char **av, int ac) 
{
	char *buf;
	int positive = 0;
	char **av1;
	int ac1 = 0;
	static int versioncount = 0;

	SET_SEGV_LOCATION();
	buf = av[2];	
	buf += 9;	/* skip "\1version " */
	
	/* send a Module_Event, so StatServ can pick up the version info !!! */
	/* nice little side effect isn't it? */
	AddStringToList(&av1, u->nick, &ac1);
	AddStringToList(&av1, buf, &ac1);	
 	ModuleEvent(EVENT_CLIENTVERSION, av1, ac1);
 	free(av1);
 	/* reset segvinmodule */
	SET_SEGV_INMODULE("SecureServ");
	
	if (SecureServ.verbose) {
		chanalert(s_SecureServ, "Got Version Reply from %s: %s", u->nick, buf);
	}
	positive = ScanCTCP(u, buf);
	versioncount++;
	/* why do we only change the version reply every 23 entries? Why not? */
	if ((positive == 0) && (versioncount > 23)) {
		strlcpy(SecureServ.sampleversion, buf, SS_BUF_SIZE);
		versioncount = 0;
	}
	return 0;
}

int __ModInit(int modnum, int apiversion) 
{
	int i;
	
	SET_SEGV_LOCATION();
#ifdef NS_ERR_VERSION /* Forward port version checks */
	/* Check that our compiled version if compatible with the calling version of NeoStats */
	if(	ircstrncasecmp (me.version, NEOSTATS_VERSION, VERSIONSIZE) !=0) {
		return NS_ERR_VERSION;
	}
#endif 
	if (apiversion < REQUIREDAPIVER) {
		nlog(LOG_CRITICAL, LOG_MOD, "Can't Load SecureServ. API Version MisMatch");
		return -1;
	}
	strlcpy(s_SecureServ, "SecureServ", MAXNICK);
	
	SecureServ.isonline = 0;			
	SecureServ.helpcount = 0;
	SecureServ.doUpdate = 0;
	SecureServ.MaxAJPP = 0;
	SecureServ.updateurl[0] = 0;
	SecureServ.monchancycle = 1;
	for (i = 0; i > MAX_PATTERN_TYPES; i++) {
		SecureServ.trigcounts[i] = 0;
		SecureServ.actioncounts[i] = 0;
	}
	SecureServ.MaxAJPPChan[0] = 0;
	SecureServ.modnum = modnum;

	LoadConfig();
	SS_InitExempts();
	InitScanner();
	InitOnJoinBots();
	InitJoinFlood();
	InitNickFlood();

	return 1;
}

void __ModFini() 
{
	SET_SEGV_LOCATION();
	ExitOnJoinBots();
};

static int ss_kick_chan(char **argv, int ac) 
{
	SET_SEGV_LOCATION();
	if(CheckOnjoinBotKick(argv, ac)) {
		return 1;
	}
	/* Can we use this event for anything else e.g. channel takeover checks? */
	return 1;
}
