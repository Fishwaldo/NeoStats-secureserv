/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2004 Justin Hammond
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

#include <stdio.h>
#include "dl.h"
#include "log.h"
#include "stats.h"
#include "conf.h"
#include "SecureServ.h"

#define MAX_NICKS	100
#define DEFAULT_VERSION_RESPONSE "Visual IRC 2.0rc5 (English) - Fast. Powerful. Free. http://www.visualirc.net/beta.php"

typedef struct randomnicks {
	char nick[MAXNICK];
	char user[MAXUSER];
	char host[MAXHOST];
	char rname[MAXREALNAME];
}randomnicks;

static char confbuf[CONFBUFSIZE];
static list_t *monchans;
static int SaveMonChans();
/* this is the list of random nicknames */
static list_t *nicks;
static char onjoinbot_modes[] = "+";

static unsigned hrand(unsigned upperbound, unsigned lowerbound) 
{
	if ((upperbound < 1)) {
		return -1;
	}
	return ((unsigned)(rand()%((int)(upperbound-lowerbound+1))-((int)(lowerbound-1))));
}
  
static int chkmonchan (const void *key1, const void *key2) 
{
	char *chan = (char *)key1;
	char *chk = (char *)key2;
	return (strcasecmp(chan, chk));
}

static int is_monchan(char* chan)
{
	if (list_find(monchans, chan, chkmonchan)) {
		return(1);
	}
	return(0);
}

static Chans *GetRandomChan() 
{
	hscan_t cs;
	hnode_t *cn;
	int randno, curno;
	
	curno = 0;
	randno = hrand(hash_count(ch), 1);	
	if (randno == -1) {
		return NULL;
	}
	hash_scan_begin(&cs, ch);
	while ((cn = hash_scan_next(&cs)) != NULL) {
		if (curno == randno) {
			return((Chans *)hnode_get(cn));
		}
		curno++;
	}
	nlog(LOG_WARNING, LOG_MOD, "GetRandomChan() ran out of channels?");
	return NULL;
}

static Chans * GetNewChan () 
{
	Chans *c;
	int i;

	for(i = 0; i < 5; i++) {
		c = GetRandomChan();
		if (c != NULL) {
			nlog(LOG_DEBUG1, LOG_MOD, "Random Chan is %s", c->name);

			/* if channel is private and setting is enabled, don't join */
			if ((SecureServ.doprivchan == 0) && (is_pub_chan(c))) {
				nlog(LOG_DEBUG1, LOG_MOD, "Not Scanning %s, as its a private channel", c->name);
				continue;
			}

			if (!strcasecmp(SecureServ.lastchan, c->name) || !strcasecmp(me.chan, c->name)) {
				/* this was the last channel we joined, don't join it again */
				nlog(LOG_DEBUG1, LOG_MOD, "Not Scanning %s, as we just did it", c->name);
				continue;
			}
			/* if the channel is exempt, restart */
			if (IsChanExempt(c) > 0) {
				continue;
			}
			/* if we are already monitoring with a monbot, don't join */
			if (is_monchan(c->name)) {
				nlog(LOG_DEBUG1, LOG_MOD, "Not Scanning %s as we are monitoring it with a monbot",c->name);
				continue;
			}
			return(c);
		} else {
			/* hu? */
			nlog(LOG_DEBUG1, LOG_MOD, "Hu? Couldn't find a channel");
			SecureServ.lastchan[0] = 0;
			SecureServ.lastnick[0] = 0;
			return NULL;
		}
	}
	/* give up after 5 attempts */
	nlog(LOG_DEBUG1, LOG_MOD, "Couldn't find a fresh Channel, Giving up");
	SecureServ.lastchan[0] = 0;
	SecureServ.lastnick[0] = 0;
	return NULL;
}

static randomnicks * GetNewBot(int resetflag)
{
	randomnicks *nickname = NULL;
	lnode_t *rnn;
	int randno, curno, i;

	for(i = 0; i < 5; i++) {
		curno = 1;
		randno = hrand(list_count(nicks)-1, 0 );
		rnn = list_first(nicks);
		while (rnn != NULL) {
			if (curno == randno) {
				nickname = lnode_get(rnn);
				if (!strcasecmp(nickname->nick, SecureServ.lastnick)) {
					/* its the same as last time, nope */
					nlog(LOG_DEBUG1, LOG_MOD, "%s was used last time. Retring", nickname->nick);
					break;
				}
				/* make sure no one is online with this nickname */
				if (finduser(nickname->nick) != NULL) {
					nlog(LOG_DEBUG1, LOG_MOD, "%s is online, can't use that nick, retring", nickname->nick);
					break;
				}
				nlog(LOG_DEBUG1, LOG_MOD, "RandomNick is %s", nickname->nick);
				return nickname;
			}
			curno++;
			rnn = list_next(nicks, rnn);
		}
	}
	/* give up if we try five times */
	nlog(LOG_DEBUG1, LOG_MOD, "Couldn't find a free nickname, giving up");
	if(resetflag) {
		SecureServ.lastchan[0] = 0;
		SecureServ.lastnick[0] = 0;
	}
	return NULL;
}

void JoinNewChan() 
{
	Chans *c;
	randomnicks *nickname = NULL;

	SET_SEGV_LOCATION();
	/* first, if the lastchan and last nick are not empty, it means one of our bots is in a chan, sign them off */
	if (finduser(SecureServ.lastnick)) {
		if (SecureServ.lastchan[0] != 0) {
			spart_cmd(SecureServ.lastnick, SecureServ.lastchan);
		}
		del_bot(SecureServ.lastnick, "Finished Scanning");
		SecureServ.lastchan[0] = 0;
		SecureServ.lastnick[0] = 0;
	}
	/* restore segvinmodules */
	SET_SEGV_INMODULE("SecureServ");

	/* if we don't do OnJoin Checking, Don't go any further */
	if (SecureServ.DoOnJoin < 1)
		return;

	if (list_count(nicks) < 1) {
		/* just broadcast a error every time we try, till a admin either turns of Onjoin checking, or adds a few bots */
		chanalert(s_SecureServ, "Warning!!! BotList is empty. We cant do OnJoin Checking. Add a few bots via ./msg %s bots command", s_SecureServ);
		return;
	}

	c = GetNewChan ();
	if (c == NULL) {
		return;
	}
		strlcpy(SecureServ.lastchan, c->name, CHANLEN);

	nickname = GetNewBot(1);
	if(nickname == NULL) {
		return;
	}
	strlcpy(SecureServ.lastnick, nickname->nick, MAXNICK);

	/* ok, init the new bot. */
	if (init_bot(nickname->nick, nickname->user, nickname->host, nickname->rname, onjoinbot_modes, "SecureServ") == -1) {
		/* hu? Nick was in use. How is that possible? */
		SecureServ.lastchan[0] = 0;
		SecureServ.lastnick[0] = 0;
		nlog(LOG_WARNING, LOG_MOD, "init_bot reported nick was in use. How? Dunno");
		return;
	}
	CloakHost(findbot(nickname->nick));
	join_bot_to_chan (nickname->nick, c->name, 0);

	if (SecureServ.verbose) {
		chanalert(me.allbots ? nickname->nick : s_SecureServ, "Scanning %s with %s for OnJoin Viruses", c->name, nickname->nick);
	}
}

static int CheckChan(User *u, char *requestchan) 
{
	Chans *c;
	randomnicks *nickname = NULL;
	
	SET_SEGV_LOCATION();
	c = findchan(requestchan);
	if (!c) {
		prefmsg(u->nick, s_SecureServ, "Can not find Channel %s, It has to have Some Users!", requestchan);
		return -1;
	}			

	nickname = GetNewBot(0);
	if(nickname ==NULL) {
		prefmsg(u->nick, s_SecureServ, "Couldnt Find a free Nickname to check %s with. Giving up (Try again later)", requestchan);
		return -1;
	}
	/* first, if the lastchan and last nick are not empty, it means one of our bots is in a chan, sign them off */
	if (SecureServ.lastchan[0] != 0) {
		spart_cmd(SecureServ.lastnick, SecureServ.lastchan);
		del_bot(SecureServ.lastnick, "Finished Scanning");
	}
	/* restore segvinmodules */
	SET_SEGV_INMODULE("SecureServ");

	strlcpy(SecureServ.lastnick, nickname->nick, MAXNICK);
	strlcpy(SecureServ.lastchan, c->name, CHANLEN);

	/* ok, init the new bot. */
	init_bot(nickname->nick, nickname->user, nickname->host, nickname->rname, onjoinbot_modes, "SecureServ");
	CloakHost(findbot(nickname->nick));
	join_bot_to_chan (nickname->nick, c->name, 0);

	chanalert(me.allbots ? nickname->nick : s_SecureServ, "Scanning %s with %s for OnJoin Viruses by request of %s", c->name, nickname->nick, u->nick);
	prefmsg(u->nick, s_SecureServ, "Scanning %s with %s", c->name, nickname->nick);
	return 1;
}

void OnJoinBotMsg(User *u, char **argv, int ac) 
{
	char *buf;

	SET_SEGV_LOCATION();
	if (!u) {
		return;
	}
	
	if (!strcasecmp(argv[1], "\1version\1")) {
		/* its a version request */
		nlog(LOG_NORMAL, LOG_MOD, "Received version request from %s to OnJoin Bot %s", u->nick, argv[0]);
		notice(u->nick, argv[0], "\1VERSION %s\1", SecureServ.sampleversion);
		return;
	}	

	/* check if this user is exempt */
	if (IsUserExempt(u) > 0) {
		nlog(LOG_DEBUG1, LOG_MOD, "User %s is exempt from Message Checking", u->nick);
		return;
	}

	buf = joinbuf(argv, ac, 1);

	nlog(LOG_NORMAL, LOG_MOD, "Received message from %s to OnJoin Bot %s: %s", u->nick, argv[0], buf);
	if (SecureServ.verbose||SecureServ.BotEcho) {
		chanalert(me.allbots ? argv[0] : s_SecureServ, "OnJoin Bot %s Received Private Message from %s: %s", argv[0], u->nick, buf);
	}

	ScanMsg(u, buf);
	free(buf);
}				

int CheckOnjoinBotKick(char **argv, int ac) 
{
	lnode_t *mn;
	
	SET_SEGV_LOCATION();
	/* check its one of our nicks */
	if (!strcasecmp(SecureServ.lastnick, argv[1]) && (!strcasecmp(SecureServ.lastchan, argv[0]))) {
		nlog(LOG_NOTICE, LOG_MOD, "Our Bot %s was kicked from %s", argv[1], argv[0]);
		SecureServ.lastchan[0] = 0;
		return 1;
	}
	if (SecureServ.monbot[0] == 0) {
		return 0;
	}
	/* if its our monbot, rejoin the channel! */
	if (!strcasecmp(SecureServ.monbot, argv[1])) {
		mn = list_first(monchans);
		while (mn != NULL) {
			if (!strcasecmp(argv[0], lnode_get(mn))) {
				/* rejoin the monitor bot to the channel */
				join_bot_to_chan (SecureServ.monbot, argv[0], 0);
				/* restore segvinmodules */
				SET_SEGV_INMODULE("SecureServ");
				if (SecureServ.verbose) {
					chanalert(s_SecureServ, "%s was kicked out of Monitored Channel %s by %s. Rejoining", argv[1], argv[0], argv[2]);
				}
				nlog(LOG_NOTICE, LOG_MOD, "%s was kicked out of Monitored Channel %s by %s. Rejoining", argv[1], argv[0], argv[2]);
				return 1;
			}
			mn = list_next(monchans, mn);
		}
		return 1;
	}					
	return 0;
}		

static int MonChan(User *u, char *requestchan) 
{
	Chans *c;
	randomnicks *nickname = NULL;
	lnode_t *rnn;
	char *buf;
	
	SET_SEGV_LOCATION();
	c = findchan(requestchan);

	if (!c) {
		if (u) prefmsg(u->nick, s_SecureServ, "Can not find Channel %s, It has to have Some Users!", requestchan);
		return -1;
	}			
	if (SecureServ.monbot[0] == 0) {
		if (u) prefmsg(u->nick, s_SecureServ, "Warning, No Monitor Bot set. /msg %s help set", s_SecureServ);
		return -1;
	}
	/* check to see we are not already monitoring this chan */
	rnn = list_first(monchans);
	while (rnn != NULL) {
		if (!strcasecmp(c->name,  lnode_get(rnn))) { 
			prefmsg(u->nick, s_SecureServ, "Already Monitoring %s",	(char*)lnode_get(rnn));
			/* XXX TODO What if we are setup to monitor this chan, but not joined? */
			return -1;
		}
 		rnn = list_next(monchans, rnn);
	}
	if (list_isfull(monchans)) {
		prefmsg(u->nick, s_SecureServ, "Can not monitor any additional channels");
		return -1;
	}


	if (findbot(SecureServ.monbot) == NULL) {
		/* the monbot isn't online. Initilze it */
		rnn = list_first(nicks);
		while (rnn != NULL) {
			nickname = lnode_get(rnn);
			if (!strcasecmp(nickname->nick, SecureServ.monbot)) {
				/* its the same as last time, nope */
				break;
			}
			rnn = list_next(nicks, rnn);
		}
		if (rnn != NULL) {
			init_bot(nickname->nick, nickname->user, nickname->host, nickname->rname, onjoinbot_modes, "SecureServ");
			CloakHost(findbot(nickname->nick));
		} else {
			nlog(LOG_WARNING, LOG_MOD, "Warning, MonBot %s isn't available!", SecureServ.monbot);			
			return -1;
		}
	}
	/* restore segvinmodules */
	SET_SEGV_INMODULE("SecureServ");
	
	/* join the monitor bot to the new channel */
	join_bot_to_chan (SecureServ.monbot, c->name, 0);
	/* restore segvinmodules */
	SET_SEGV_INMODULE("SecureServ");

	if (SecureServ.verbose) chanalert(me.allbots ? SecureServ.monbot : s_SecureServ, "Monitoring %s with %s for Viruses by request of %s", c->name, SecureServ.monbot, u ? u->nick : s_SecureServ);
	if (u) prefmsg(u->nick, s_SecureServ, "Monitoring %s with %s", c->name, SecureServ.monbot);
	
	buf = malloc(CHANLEN);
	strlcpy(buf, c->name, CHANLEN);
	rnn = lnode_create(buf);
	list_append(monchans, rnn);
	SaveMonChans();
	return 1;
}

static int StopMon(User *u, char *chan) 
{
	lnode_t *node, *node2;
	int ok = 0; 

	SET_SEGV_LOCATION();
	node = list_first(monchans);
	while (node != NULL) {
		node2 = list_next(monchans, node);
		if (!strcasecmp(chan, lnode_get(node))) {
			list_delete(monchans, node);
			prefmsg(u->nick, s_SecureServ, "Deleted %s out of Monitored Channels List.", (char*)lnode_get(node));
			spart_cmd(SecureServ.monbot, lnode_get(node));
			free(lnode_get(node));
			lnode_destroy(node);
			ok = 1;
		}
		node = node2;			
	}
	if (ok == 1) {
		SaveMonChans();
	} else {
		prefmsg(u->nick, s_SecureServ, "Couldn't find Channel %s in Monitored Channel list", chan);
	}
	return 1;
}		

int ListMonChan(User *u) 
{
	lnode_t *node;

	SET_SEGV_LOCATION();
	prefmsg(u->nick, s_SecureServ, "Monitored Channels List (%d):", (int)list_count(monchans)); node = list_first(monchans);
	while (node != NULL) {
		prefmsg(u->nick, s_SecureServ, "%s", (char*)lnode_get(node));
		node = list_next(monchans, node);
	}
	prefmsg(u->nick, s_SecureServ, "End of List");
	return 1;
}


int LoadMonChans() 
{
	int i;
	char **chan;

	SET_SEGV_LOCATION();
	monchans = list_create(20);
	if (GetDir("MonChans", &chan) > 0) {
		for (i = 0; chan[i] != NULL; i++) {
			MonChan(NULL, chan[i]);
		}
	}
	free(chan);	
	return 1;
}

int SaveMonChans() 
{
	lnode_t *node;
	char buf[CONFBUFSIZE];

	SET_SEGV_LOCATION();
	DelConf("MonChans");
	node = list_first(monchans);
	while (node != NULL) {
		ircsnprintf(buf, CONFBUFSIZE, "MonChans/%s", (char *)lnode_get(node));
		SetConf((void *)1, CFGINT, buf);
		node = list_next(monchans, node);
	}
	return 1;
}

int MonChanCount(void)
{
	return (list_count(monchans));
}

int OnJoinBotConf(void)
{
	randomnicks *rnicks;
	lnode_t *node;
	int i;
	char **data;
	char *tmp;

	SET_SEGV_LOCATION();
	/* get Random Nicknames */
	if (GetDir("RandomNicks", &data) > 0) {
		/* try */
		for (i = 0; data[i] != NULL; i++) {
			rnicks = malloc(sizeof(randomnicks));
			strlcpy(rnicks->nick, data[i], MAXNICK);
	
			ircsnprintf(confbuf, CONFBUFSIZE, "RandomNicks/%s/User", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, confbuf) <= 0) {
				free(rnicks);
				continue;
			} else {
				strlcpy(rnicks->user, tmp, MAXUSER);
				free(tmp);
			}
			ircsnprintf(confbuf, CONFBUFSIZE, "RandomNicks/%s/Host", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, confbuf) <= 0) {
				free(rnicks);
				continue;
			} else {
				strlcpy(rnicks->host, tmp, MAXHOST);
				free(tmp);
			}
			ircsnprintf(confbuf, CONFBUFSIZE, "RandomNicks/%s/RealName", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, confbuf) <= 0) {
				free(rnicks);
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
			nlog(LOG_DEBUG2, LOG_MOD, "Warning, Cant find nick %s in random bot list for monbot", tmp);
		}
		free(tmp);
	}
	return 1;
}

int InitOnJoinBots(void)
{
	SET_SEGV_LOCATION();
	/* init the random nicks list */
	nicks = list_create(MAX_NICKS);
	/* init CTCP version response */
	strlcpy(SecureServ.sampleversion, DEFAULT_VERSION_RESPONSE, SS_BUF_SIZE);
	OnJoinBotConf();
	return 1;
}

int ExitOnJoinBots(void)
{
	SET_SEGV_LOCATION();
	if (finduser(SecureServ.lastnick)) {
		chanalert(s_SecureServ, "SecureServ is unloading, OnJoinBot %s leaving", SecureServ.lastnick);
		if (SecureServ.lastchan[0] != 0) {
			spart_cmd(SecureServ.lastnick, SecureServ.lastchan);
		}
		del_bot(SecureServ.lastnick, SecureServ.botquitmsg);
		SecureServ.lastchan[0] = 0;
		SecureServ.lastnick[0] = 0;
	}
	if (SecureServ.monbot[0] != 0) {
		chanalert(s_SecureServ, "SecureServ is unloading, monitor bot %s leaving", SecureServ.monbot);
		del_bot(SecureServ.monbot, SecureServ.botquitmsg);
		return -1;
	}
	return 1;
}

int do_bots(User* u, char **argv, int argc)
{
	int i;
	lnode_t *node;
	randomnicks *bots;
	char *buf, *buf2;

	SET_SEGV_LOCATION();
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
			prefmsg(u->nick, s_SecureServ, "Error, Bot list is full");
			return 0;
		}
		buf = malloc(CONFBUFSIZE);
		ircsnprintf(buf, CONFBUFSIZE, "RandomNicks/%s/User", argv[3]);
		SetConf((void *)argv[4], CFGSTR, buf);
		ircsnprintf(buf, CONFBUFSIZE, "RandomNicks/%s/Host", argv[3]);
		SetConf((void *)argv[5], CFGSTR, buf);
		ircsnprintf(buf, CONFBUFSIZE, "RandomNicks/%s/RealName", argv[3]);
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
					buf = malloc(CONFBUFSIZE);
					ircsnprintf(buf, CONFBUFSIZE, "RandomNicks/%s", bots->nick);
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
	return 0;
}

int do_checkchan(User* u, char **argv, int argc)
{
	SET_SEGV_LOCATION();
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
}

int do_monchan(User* u, char **argv, int argc)
{
	SET_SEGV_LOCATION();
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
}

int do_cycle(User* u, char **argv, int argc)
{
	SET_SEGV_LOCATION();
	if (UserLevel(u) < NS_ULEVEL_OPER) {
		prefmsg(u->nick, s_SecureServ, "Permission Denied");
		chanalert(s_SecureServ, "%s tried to cycle, but Permission was denied", u->nick);
		return -1;
	}			
	JoinNewChan();
	return 1;
}

int do_set_monbot(User* u, char **av, int ac)
{
	SET_SEGV_LOCATION();
	/* this is ok, its just to shut up fussy compilers */
	randomnicks *nickname = NULL;
	lnode_t *rnn;

	if (ac < 4) {
		prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg %s help set for more info", s_SecureServ);
		return 1;
	}			
	/* Do not allow overwrite of the monbot if one is already 
		* assigned and we have monchans. 
		*/
	if(SecureServ.monbot[0] != 0 && MonChanCount() > 1) {
		prefmsg(u->nick, s_SecureServ, "Monitor bot already set to %s and is monitoring channels.", SecureServ.monbot);
		return 1;
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
		return 1;
	}
	prefmsg(u->nick, s_SecureServ, "Can't find Bot %s in bot list. /msg %s bot list for Bot List", av[3], s_SecureServ);
	return 1;
}
