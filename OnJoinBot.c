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

#define MAX_NICKS	100
#define DEFAULT_VERSION_RESPONSE "Visual IRC 2.0rc5 (English) - Fast. Powerful. Free. http://www.visualirc.net/beta.php"

typedef struct randomnicks {
	char nick[MAXNICK];
	char user[MAXUSER];
	char host[MAXHOST];
	char realname[MAXREALNAME];
}randomnicks;

static char confbuf[CONFBUFSIZE];
static list_t *monchans;
static int SaveMonChans();
/* this is the list of random nicknames */
static list_t *nicks;
char onjoinbot_modes[MODESIZE] = "+";
static lnode_t *lastmonchan;


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

int is_monchan(char* chan)
{
	if (list_find(monchans, chan, chkmonchan)) {
		return(1);
	}
	return(0);
}

static Channel *GetRandomChan() 
{
	hscan_t cs;
	hnode_t *cn;
	int randno, curno;
	
	curno = 0;
	randno = hrand(hash_count(GetChannelHash()), 1);	
	if (randno == -1) {
		return NULL;
	}
	hash_scan_begin(&cs, GetChannelHash());
	while ((cn = hash_scan_next(&cs)) != NULL) {
		if (curno == randno) {
			return((Channel *)hnode_get(cn));
		}
		curno++;
	}
	nlog (LOG_WARNING, "GetRandomChan() ran out of channels?");
	return NULL;
}

static Channel * GetNewChan () 
{
	Channel *c;
	int i;

	for(i = 0; i < 5; i++) {
		c = GetRandomChan();
		if (c != NULL) {
			dlog (DEBUG1, "Random Chan is %s", c->name);

			/* if channel is private and setting is enabled, don't join */
			if ((SecureServ.doprivchan == 0) && (is_priv_chan(c))) {
				dlog (DEBUG1, "Not Scanning %s, as its a private channel", c->name);
				continue;
			}

			if (!strcasecmp(me.serviceschan, c->name)) {
				/* this was the last channel we joined, don't join it again */
				dlog (DEBUG1, "Not Scanning %s, as this is the services channel", c->name);
				continue;
			}
			if (!strcasecmp(SecureServ.lastchan, c->name)) {
				/* this was the last channel we joined, don't join it again */
				dlog (DEBUG1, "Not Scanning %s, as we just did it", c->name);
				continue;
			}
			/* if the channel is exempt, restart */
			if (SS_IsChanExempt(c) > 0) {
				continue;
			}
			/* if we are already monitoring with a monbot, don't join */
			if (is_monchan(c->name)) {
				dlog (DEBUG1, "Not Scanning %s as we are monitoring it with a monbot",c->name);
				continue;
			}
			return(c);
		} else {
			/* hu? */
			dlog (DEBUG1, "Hu? Couldn't find a channel");
			SecureServ.lastchan[0] = 0;
			SecureServ.lastnick[0] = 0;
			return NULL;
		}
	}
	/* give up after 5 attempts */
	dlog (DEBUG1, "Couldn't find a fresh Channel, Giving up");
	SecureServ.lastchan[0] = 0;
	SecureServ.lastnick[0] = 0;
	return NULL;
}

static randomnicks * GetNewBot(int resetflag)
{
	randomnicks *nickname = NULL;
	lnode_t *rnn;
	int randno, curno, i;

	if(list_count(nicks) == 0) {
		/* No bots available */
		dlog (DEBUG1, "No bots available, giving up");
		return NULL;
	}

	if(list_count(nicks) == 1) {
		/* If only one bot, no need for random (which crashes with 1 anyway) 
		 * so just return the single bot */
		rnn = list_first(nicks);
		if(rnn != NULL) {
			nickname = lnode_get(rnn);
			/* make sure no one is online with this nickname */
			if (find_user(nickname->nick) != NULL) {
				dlog (DEBUG1, "%s is online, can't use that nick", nickname->nick);
				return NULL;
			}
			dlog (DEBUG1, "RandomNick is %s", nickname->nick);
			return nickname;
		}
		return NULL;
	}

	for(i = 0; i < 5; i++) {
		curno = 1;
		randno = hrand(list_count(nicks)-1, 0 );
		rnn = list_first(nicks);
		while (rnn != NULL) {
			if (curno == randno) {
				nickname = lnode_get(rnn);
				if (!strcasecmp(nickname->nick, SecureServ.lastnick)) {
					/* its the same as last time, nope */
					dlog (DEBUG1, "%s was used last time. Retring", nickname->nick);
					break;
				}
				/* make sure no one is online with this nickname */
				if (find_user(nickname->nick) != NULL) {
					dlog (DEBUG1, "%s is online, can't use that nick, retring", nickname->nick);
					break;
				}
				dlog (DEBUG1, "RandomNick is %s", nickname->nick);
				return nickname;
			}
			curno++;
			rnn = list_next(nicks, rnn);
		}
	}
	/* give up if we try five times */
	dlog (DEBUG1, "Couldn't find a ns_free nickname, giving up");
	if(resetflag) {
		SecureServ.lastchan[0] = 0;
		SecureServ.lastnick[0] = 0;
	}
	return NULL;
}

int MonBotCycle()
{
	lnode_t *mcnode;
	Channel *c;
	char *chan;
	/* cycle one of hte monchans, if configured to */
	if (SecureServ.monbot[0] == 0) {
		return NS_SUCCESS;
	}
	if (SecureServ.monchancycle > 0) {
	/* this is broken, so lets just do something simple for the meantime */
#if 0
		if (lastmonchan == NULL) {
			/* its brand new */
			mcnode = list_first(monchans);	
		} else {
			mcnode = list_next(monchans, lastmonchan);
			if (mcnode == NULL) {
				/* we have moved through all teh chans, start from scratch */
				mcnode = list_first(monchans);
			}
		}
		if (mcnode == NULL) {
			/* No MonChans so abort */
			return NS_SUCCESS;
		}
		/* check the channel is active, if not, just bail out */
		if (!find_channel(lnode_get(mcnode))) {
			return NS_SUCCESS;
		}	
#else
		mcnode = list_first(monchans);
		while (mcnode != NULL) {
			chan = lnode_get(mcnode);
			if (!chan) {
				nlog (LOG_WARNING, "MonChans has a empty node?");
				mcnode = list_next(monchans, mcnode);
				continue;
			}
			c = find_channel(chan);
			if (!c) {
				/* channel isn't online atm, ignore */
				mcnode = list_next(monchans, mcnode);
				continue;
			}
			if (IsChannelMember(c, find_user(SecureServ.monbot))) {
				irc_part (find_bot(SecureServ.monbot), c->name);
			}
			irc_join (find_bot(SecureServ.monbot), c->name, 0);
			mcnode = list_next(monchans, mcnode);
		}
#endif
			
	}
	return NS_SUCCESS;
}

int JoinNewChan() 
{
	Channel *c;
	randomnicks *nickname = NULL;

	SET_SEGV_LOCATION();

	/* first, if the lastchan and last nick are not empty, it means one of our bots is in a chan, sign them off */
	if (SecureServ.lastnick[0] != 0) {
		if (find_user(SecureServ.lastnick)) {
			if (SecureServ.lastchan[0] != 0) {
				irc_part (find_bot(SecureServ.lastnick), SecureServ.lastchan);
			}
			irc_quit ( find_bot(SecureServ.lastnick), "Finished Scanning");
			SecureServ.lastchan[0] = 0;
			SecureServ.lastnick[0] = 0;
		}
	}
	/* if we don't do OnJoin Checking, Don't go any further */
	if (SecureServ.DoOnJoin < 1)
		return NS_SUCCESS;

	if (list_count(nicks) < 1) {
		/* just broadcast a error every time we try, till a admin either turns of Onjoin checking, or adds a few bots */
		irc_chanalert (ss_bot, "Warning!!! BotList is empty. We cant do OnJoin Checking. Add a few bots via ./msg %s bots command", ss_bot->name);
		return NS_SUCCESS;
	}

	c = GetNewChan ();
	if (c == NULL) {
		return NS_SUCCESS;
	}
		strlcpy(SecureServ.lastchan, c->name, MAXCHANLEN);

	nickname = GetNewBot(1);
	if(nickname == NULL) {
		return NS_SUCCESS;
	}
	strlcpy(SecureServ.lastnick, nickname->nick, MAXNICK);

	/* ok, init the new bot. */
	if (init_bot(nickname->nick, nickname->user, nickname->host, nickname->realname, onjoinbot_modes, "SecureServ") == -1) {
		/* hu? Nick was in use. How is that possible? */
		SecureServ.lastchan[0] = 0;
		SecureServ.lastnick[0] = 0;
		nlog (LOG_WARNING, "init_bot reported nick was in use. How? Dunno");
		return NS_SUCCESS;
	}
	irc_cloakhost (find_bot(nickname->nick));
	irc_join (find_bot(nickname->nick), c->name, 0);

	if (SecureServ.verbose) {
		irc_chanalert (ss_bot, "Scanning %s with %s for OnJoin Viruses", c->name, nickname->nick);
	}
	return NS_SUCCESS;
}

static int CheckChan(Client *u, char *requestchan) 
{
	Channel *c;
	randomnicks *nickname = NULL;
	lnode_t *lnode;
	Client *cm;
	
	SET_SEGV_LOCATION();
	c = find_channel(requestchan);
	if (!c) {
		irc_prefmsg (ss_bot, u, "Can not find Channel %s, It has to have Some Users!", requestchan);
		return -1;
	}			

	/* first, run the channel through the viri list, make sure its not bad */
	
	/* now scan channel members */
	lnode = list_first(c->members);
	while (lnode) {
		cm = find_user(lnode_get(lnode));
		if (cm && ScanChan(cm, c) == 0) {
			/* if its 0, means its ok, no need to scan other members */
			break;
		}
		lnode = list_next(c->members, lnode);
	}



	nickname = GetNewBot(0);
	if(nickname ==NULL) {
		irc_prefmsg (ss_bot, u, "Couldnt Find a ns_free Nickname to check %s with. Giving up (Try again later)", requestchan);
		return -1;
	}
	/* first, if the lastchan and last nick are not empty, it means one of our bots is in a chan, sign them off */
	if (SecureServ.lastchan[0] != 0) {
		irc_part (find_bot(SecureServ.lastnick), SecureServ.lastchan);
		irc_quit ( find_bot(SecureServ.lastnick), "Finished Scanning");
	}
	strlcpy(SecureServ.lastnick, nickname->nick, MAXNICK);
	strlcpy(SecureServ.lastchan, c->name, MAXCHANLEN);

	/* ok, init the new bot. */
	init_bot(nickname->nick, nickname->user, nickname->host, nickname->realname, onjoinbot_modes, "SecureServ");
	irc_cloakhost (find_bot(nickname->nick));
	irc_join (find_bot(nickname->nick), c->name, 0);

	irc_chanalert (ss_bot, "Scanning %s with %s for OnJoin Viruses by request of %s", c->name, nickname->nick, u->name);
	irc_prefmsg (ss_bot, u, "Scanning %s with %s", c->name, nickname->nick);
	return 1;
}

void OnJoinBotMsg(Client *u, char *botname, char *msg)
{
	SET_SEGV_LOCATION();

	if (!u) {
		return;
	}
	
	if (!strncasecmp(msg, "\1version\1", sizeof("\1version\1"))) {
		/* its a version request */
		nlog (LOG_NORMAL, "Received version request from %s to OnJoin Bot %s", u->name, botname);
		irc_notice (find_bot(botname), u, "\1VERSION %s\1", SecureServ.sampleversion);
		return;
	}	

	/* check if this user is exempt */
	if (SS_IsUserExempt(u) > 0) {
		dlog (DEBUG1, "User %s is exempt from Message Checking", u->name);
		return;
	}

	nlog (LOG_NORMAL, "Received message from %s to OnJoin Bot %s: %s", u->name, botname, msg);
	if (SecureServ.verbose||SecureServ.BotEcho) {
		irc_chanalert (ss_bot, "OnJoin Bot %s Received Private Message from %s: %s", botname, u->name, msg);
	}

	ScanMsg(u, msg, 0);
}				

int CheckOnjoinBotKick(CmdParams *cmdparams) 
{
	lnode_t *mn;
	
	SET_SEGV_LOCATION();
	/* check its one of our nicks */
	if (!strcasecmp(SecureServ.lastnick, cmdparams->target->name) && (!strcasecmp(SecureServ.lastchan, cmdparams->channel->name))) {
		nlog (LOG_NOTICE, "Our Bot %s was kicked from %s", cmdparams->target->name, cmdparams->channel->name);
		SecureServ.lastchan[0] = 0;
		return 1;
	}
	if (SecureServ.monbot[0] == 0) {
		return 0;
	}
	/* if its our monbot, rejoin the channel! */
	if (!strcasecmp(SecureServ.monbot, cmdparams->target->name)) {
		mn = list_first(monchans);
		while (mn != NULL) {
			if (!strcasecmp(cmdparams->channel->name, lnode_get(mn))) {
				/* rejoin the monitor bot to the channel */
				irc_join (find_bot(SecureServ.monbot), cmdparams->channel->name, 0);
				if (SecureServ.verbose) {
					irc_chanalert (ss_bot, "%s was kicked out of Monitored Channel %s by %s. Rejoining", cmdparams->target->name, cmdparams->channel->name, cmdparams->source);
				}
				nlog (LOG_NOTICE, "%s was kicked out of Monitored Channel %s by %s. Rejoining", cmdparams->target->name, cmdparams->channel->name, cmdparams->source);
				return 1;
			}
			mn = list_next(monchans, mn);
		}
		return 1;
	}					
	return 0;
}		
int MonJoin(Channel *c) {
	randomnicks *nickname = NULL;
	lnode_t *rnn, *mn;

	if (SecureServ.monbot[0] == 0) {
		return -1;
	}
	mn = list_first(monchans);
	while (mn != NULL) {
		if (!strcasecmp(c->name, lnode_get(mn))) {
			if (find_bot(SecureServ.monbot) == NULL) {
				/* the monbot isn't online. Initilze it */
				rnn = list_first(nicks);
				while (rnn != NULL) {
					nickname = lnode_get(rnn);
					if (!strcasecmp(nickname->nick, SecureServ.monbot)) {
						/* its our bot */
						break;
					}
					rnn = list_next(nicks, rnn);
				}
				if (rnn != NULL) {
					init_bot(nickname->nick, nickname->user, nickname->host, nickname->realname, onjoinbot_modes, "SecureServ");
					irc_cloakhost (find_bot(nickname->nick));
				} else {
					nlog (LOG_WARNING, "Warning, MonBot %s isn't available!", SecureServ.monbot);			
					return -1;
				}
			}
			/* if they the monbot is not a member of the channel, join it. */
			if (!IsChannelMember(c, find_user(SecureServ.monbot))) {
				/* join the monitor bot to the new channel */
				irc_join (find_bot(SecureServ.monbot), c->name, 0);
			}	
		return 1;
		}
		mn = list_next(monchans, mn);
	}
	return 1;
}	
int MonBotDelChan(Channel *c) 
{
	if (c->users != 2) {
		return -1;
	}
	if (SecureServ.monbot[0] == 0) {
		return -1;
	}
	/* really easy way to tell if this is our monitored channel */
	if (IsChannelMember(c, find_user(SecureServ.monbot))) {
		/* yep, its us just part the channel */
		irc_part (find_bot(SecureServ.monbot), c->name);
	}				
	return 1;
}

static int MonChan(Client *u, char *requestchan) 
{
	Channel *c;
	randomnicks *nickname = NULL;
	lnode_t *rnn, *mn;
	char *buf;
	
	SET_SEGV_LOCATION();

	if (list_isfull(monchans)) {
		if (u) irc_prefmsg (ss_bot, u, "Can not monitor any additional channels");
		nlog (LOG_WARNING, "MonChan List is full. Not Monitoring %s", requestchan);
		return -1;
	}

	mn = list_first(monchans);
	while (mn != NULL) {
		if (!strcasecmp(requestchan, lnode_get(mn))) {
			if (u) irc_prefmsg (ss_bot, u, "Already Monitoring Channel %s", requestchan);
			return 1;
		}
		mn = list_next(monchans, mn);
	}

	c = find_channel(requestchan);

	if (!c) {
		if (u) irc_prefmsg (ss_bot, u, "Can not find Channel %s, It has to have Some Users!", requestchan);
		return -1;
	}			
	/* dont allow excepted channels */
	if (SS_IsChanExempt(c) > 0) {
		if (u) irc_prefmsg (ss_bot, u, "Can not monitor a channel listed as a Exempt Channel");
		return -1;
	}


	if (SecureServ.monbot[0] == 0) {
		if (u) irc_prefmsg (ss_bot, u, "Warning, No Monitor Bot set. /msg %s help set", ss_bot->name);
		return -1;
	}
	if (IsChannelMember(c, find_user(SecureServ.monbot))) {
		if (u) irc_prefmsg (ss_bot, u, "Already Monitoring %s",	c->name);
		return -1;
	}

	if (find_bot(SecureServ.monbot) == NULL) {
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
			init_bot(nickname->nick, nickname->user, nickname->host, nickname->realname, onjoinbot_modes, "SecureServ");
			irc_cloakhost (find_bot(nickname->nick));
		} else {
			nlog (LOG_WARNING, "Warning, MonBot %s isn't available!", SecureServ.monbot);			
			return -1;
		}
	}
	/* append it to the list */
	buf = ns_malloc (MAXCHANLEN);
	strlcpy(buf, requestchan, MAXCHANLEN);
	rnn = lnode_create(buf);
	list_append(monchans, rnn);
	/* join the monitor bot to the new channel */
	irc_join (find_bot(SecureServ.monbot), c->name, 0);
	if (SecureServ.verbose) irc_chanalert (ss_bot, "Monitoring %s with %s for Viruses by request of %s", c->name, SecureServ.monbot, u ? u->name : ss_bot->name);
	if (u) irc_prefmsg (ss_bot, u, "Monitoring %s with %s", c->name, SecureServ.monbot);
	
	return 1;
}

static int StopMon(Client *u, char *chan) 
{
	lnode_t *node, *node2;
	int ok = 0; 

	SET_SEGV_LOCATION();
	node = list_first(monchans);
	while (node != NULL) {
		node2 = list_next(monchans, node);
		if (!strcasecmp(chan, lnode_get(node))) {
			list_delete(monchans, node);
			irc_prefmsg (ss_bot, u, "Deleted %s out of Monitored Channels List.", (char*)lnode_get(node));
			irc_part (find_bot(SecureServ.monbot), lnode_get(node));
			ns_free (lnode_get(node));
			lnode_destroy(node);
			ok = 1;
		}
		node = node2;			
	}
	if (ok == 1) {
		SaveMonChans();
	} else {
		irc_prefmsg (ss_bot, u, "Couldn't find Channel %s in Monitored Channel list", chan);
	}
	return 1;
}		

int ListMonChan(Client *u) 
{
	lnode_t *node;

	SET_SEGV_LOCATION();
	irc_prefmsg (ss_bot, u, "Monitored Channels List (%d):", (int)list_count(monchans)); node = list_first(monchans);
	node = list_first(monchans);
	while (node != NULL) {
		irc_prefmsg (ss_bot, u, "%s", (char*)lnode_get(node));
		node = list_next(monchans, node);
	}
	irc_prefmsg (ss_bot, u, "End of List");
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
	ns_free (chan);	
	lastmonchan = NULL;
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
			rnicks = ns_malloc (sizeof(randomnicks));
			strlcpy(rnicks->nick, data[i], MAXNICK);
	
			ircsnprintf(confbuf, CONFBUFSIZE, "RandomNicks/%s/User", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, confbuf) <= 0) {
				ns_free (rnicks);
				continue;
			} else {
				strlcpy(rnicks->user, tmp, MAXUSER);
				ns_free (tmp);
			}
			ircsnprintf(confbuf, CONFBUFSIZE, "RandomNicks/%s/Host", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, confbuf) <= 0) {
				ns_free (rnicks);
				continue;
			} else {
				strlcpy(rnicks->host, tmp, MAXHOST);
				ns_free (tmp);
			}
			ircsnprintf(confbuf, CONFBUFSIZE, "RandomNicks/%s/RealName", data[i]);
			if (GetConf((void *)&tmp, CFGSTR, confbuf) <= 0) {
				ns_free (rnicks);
				continue;
			} else {
				strlcpy(rnicks->realname, tmp, MAXREALNAME);
				ns_free (tmp);
			}			
			dlog (DEBUG2, "Adding Random Nick %s!%s@%s with RealName %s", rnicks->nick, rnicks->user, rnicks->host, rnicks->realname);
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
			dlog (DEBUG2, "Warning, Cant find nick %s in random bot list for monbot", tmp);
		}
		ns_free (tmp);
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
	if (find_user(SecureServ.lastnick)) {
		irc_chanalert (ss_bot, "SecureServ is unloading, OnJoinBot %s leaving", SecureServ.lastnick);
		if (SecureServ.lastchan[0] != 0) {
			irc_part (find_bot(SecureServ.lastnick), SecureServ.lastchan);
		}
		irc_quit ( find_bot(SecureServ.lastnick), SecureServ.botquitmsg);
		SecureServ.lastchan[0] = 0;
		SecureServ.lastnick[0] = 0;
	}
	if (SecureServ.monbot[0] != 0) {
		irc_chanalert (ss_bot, "SecureServ is unloading, monitor bot %s leaving", SecureServ.monbot);
		irc_quit ( find_bot(SecureServ.monbot), SecureServ.botquitmsg);
		return -1;
	}
	return 1;
}

int do_bots(CmdParams *cmdparams)
{
	int i;
	lnode_t *node;
	randomnicks *bots;
	char *buf, *buf2;

	SET_SEGV_LOCATION();
	if (!strcasecmp(cmdparams->av[0], "LIST")) {
		node = list_first(nicks);
		i = 1;
		irc_prefmsg (ss_bot, cmdparams->source, "Bot List:");
		while (node) {
			bots = lnode_get(node);
			irc_prefmsg (ss_bot, cmdparams->source, "%d) %s (%s@%s) - %s", i, bots->nick, bots->user, bots->host, bots->realname);
			++i;
 			node = list_next(nicks, node);
		}
		irc_prefmsg (ss_bot, cmdparams->source, "End of List.");
		irc_chanalert (ss_bot, "%s requested Bot List", cmdparams->source->name);
	} else if (!strcasecmp(cmdparams->av[0], "ADD")) {
		if (cmdparams->ac < 7) {
			irc_prefmsg (ss_bot, cmdparams->source, "Syntax Error. /msg %s help bots", ss_bot->name);
			return 0;
		}
		if (list_isfull(nicks)) {
			irc_prefmsg (ss_bot, cmdparams->source, "Error, Bot list is full");
			return 0;
		}
		buf = ns_malloc (CONFBUFSIZE);
		ircsnprintf(buf, CONFBUFSIZE, "RandomNicks/%s/User", cmdparams->av[1]);
		SetConf((void *)cmdparams->av[2], CFGSTR, buf);
		ircsnprintf(buf, CONFBUFSIZE, "RandomNicks/%s/Host", cmdparams->av[1]);
		SetConf((void *)cmdparams->av[3], CFGSTR, buf);
		ircsnprintf(buf, CONFBUFSIZE, "RandomNicks/%s/RealName", cmdparams->av[1]);
		buf2 = joinbuf(cmdparams->av, cmdparams->ac, 4);			
		SetConf((void *)buf2, CFGSTR, buf);
		ns_free (buf);
		bots = ns_malloc (sizeof(randomnicks));
		strlcpy(bots->nick, cmdparams->av[1], MAXNICK);
		strlcpy(bots->user, cmdparams->av[2], MAXUSER);
		strlcpy(bots->host, cmdparams->av[3], MAXHOST);
		strlcpy(bots->realname, buf2, MAXREALNAME);
		ns_free (buf2);
		node = lnode_create(bots);
		list_append(nicks, node);
		irc_prefmsg (ss_bot, cmdparams->source, "Added %s (%s@%s - %s) Bot to Bot list", bots->nick, bots->user, bots->host, bots->realname);
		irc_chanalert (ss_bot, "%s added %s (%s@%s - %s) Bot to Bot list", cmdparams->source->name, bots->nick, bots->user, bots->host, bots->realname);
		return 1;
	} else if (!strcasecmp(cmdparams->av[0], "DEL")) {
		if (cmdparams->ac < 4) {
			irc_prefmsg (ss_bot, cmdparams->source, "Syntax Error. /msg %s help bots", ss_bot->name);
			return 0;
		}
		if (atoi(cmdparams->av[1]) != 0) {
			node = list_first(nicks);
			i = 1;
			while (node) {
				if (i == atoi(cmdparams->av[1])) {
					/* delete the entry */
					bots = lnode_get(node);
					/* dont delete the bot if its setup as the monbot */
					if (!strcasecmp(bots->nick, SecureServ.monbot)) {
						irc_prefmsg (ss_bot, cmdparams->source, "Cant delete %s from botlist as its set as the monitor Bot", bots->nick);
						return -1;
					}
					/* don't delete the bot if its online! */
					if (find_bot(bots->nick)) {
						irc_prefmsg (ss_bot, cmdparams->source, "Can't delete %s from botlist as its online at the moment", bots->nick);
						return -1;
					}
					list_delete(nicks, node);
					buf = ns_malloc (CONFBUFSIZE);
					ircsnprintf(buf, CONFBUFSIZE, "RandomNicks/%s", bots->nick);
					DelConf(buf);
					ns_free (buf);
					irc_prefmsg (ss_bot, cmdparams->source, "Deleted %s out of Bot list", bots->nick);
					irc_chanalert (ss_bot, "%s deleted %s out of bot list", cmdparams->source->name, bots->nick);
					lnode_destroy(node);
					ns_free (bots);
					return 1;
				}
				++i;
				node = list_next(nicks, node);
			}		
			/* if we get here, then we can't find the entry */
			irc_prefmsg (ss_bot, cmdparams->source, "Error, Can't find entry %d. /msg %s bots list", atoi(cmdparams->av[1]), ss_bot->name);
			return 0;
		} else {
			irc_prefmsg (ss_bot, cmdparams->source, "Error, Out of Range");
			return 0;
		}
	} else {
		irc_prefmsg (ss_bot, cmdparams->source, "Syntax Error. /msg %s help bots", ss_bot->name);
		return 0;
	}
	return 0;
}

int do_checkchan(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	CheckChan(cmdparams->source, cmdparams->channel->name);
	return 1;
}

int do_monchan(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	if (!strcasecmp(cmdparams->av[0], "ADD")) {
		if (cmdparams->ac < 4) {
			irc_prefmsg (ss_bot, cmdparams->source, "Syntax Error. /msg %s help monchan", ss_bot->name);
			return -1;
		}
		MonChan(cmdparams->source, cmdparams->av[1]);
		/* dont save in MonChan, as thats also called by LoadChan */
		SaveMonChans();
	} else if (!strcasecmp(cmdparams->av[0], "DEL")) {
		if (cmdparams->ac < 4) {
			irc_prefmsg (ss_bot, cmdparams->source, "Syntax Error. /msg %s help monchan", ss_bot->name);
			return -1;
		}
		StopMon(cmdparams->source, cmdparams->av[1]);
	} else if (!strcasecmp(cmdparams->av[0], "LIST")) {
		ListMonChan(cmdparams->source);
	} else {
		irc_prefmsg (ss_bot, cmdparams->source, "Syntax Error. /msg %s help monchan", ss_bot->name);
	}
	return 1;
}

int do_cycle(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	JoinNewChan();
	return 1;
}

int do_set_monbot(CmdParams *cmdparams, SET_REASON reason)
{
	/* this is ok, its just to shut up fussy compilers */
	randomnicks *nickname = NULL;
	lnode_t *rnn;

	SET_SEGV_LOCATION();
	if (!strcasecmp(cmdparams->av[0], "LIST")) {
		irc_prefmsg (ss_bot, cmdparams->source, "MONBOT:       %s", (strlen(SecureServ.monbot) > 0) ? SecureServ.monbot : "Not Set");
		return 1;
	}
	if (cmdparams->ac < 4) {
		irc_prefmsg (ss_bot, cmdparams->source, "Invalid Syntax. /msg %s help set for more info", ss_bot->name);
		return 1;
	}			
	/* Do not allow overwrite of the monbot if one is already 
		* assigned and we have monchans. 
		*/
	if(SecureServ.monbot[0] != 0 && MonChanCount() > 1) {
		irc_prefmsg (ss_bot, cmdparams->source, "Monitor bot already set to %s and is monitoring channels.", SecureServ.monbot);
		return 1;
	}
	/* don't allow a monitor bot to be assigned if we don't have enough onjoin bots */
	if (list_count(nicks) <= 2) {
		irc_prefmsg (ss_bot, cmdparams->source, "Not enough Onjoin bots would be left if you assign a MonBot. Please create more Onjoin Bots");
		return 1;
	}
	rnn = list_first(nicks);
	while (rnn != NULL) {
		nickname = lnode_get(rnn);
		if (!strcasecmp(nickname->nick, cmdparams->av[1])) {
			/* ok, got the bot ! */
			break;
		}
		rnn = list_next(nicks, rnn);
	}
	if (rnn != NULL) {
		/* Do not allow monbot to be assigned if its online as a Onjoin bot atm */
		if (find_user(nickname->nick)) {
			irc_prefmsg (ss_bot, cmdparams->source, "Can not assign a Monitor Bot while it is online as a Onjoin Bot. Please try again in a couple of minutes");
			return 1;
		}
		SetConf((void *)cmdparams->av[1], CFGSTR, "MonBot");
		strlcpy(SecureServ.monbot, nickname->nick, MAXNICK);
		irc_prefmsg (ss_bot, cmdparams->source, "Monitoring Bot set to %s", cmdparams->av[1]);
		irc_chanalert (ss_bot, "%s set the Monitor bot to %s", cmdparams->source->name, cmdparams->av[1]);
		return 1;
	}
	irc_prefmsg (ss_bot, cmdparams->source, "Can't find Bot %s in bot list. /msg %s bot list for Bot List", cmdparams->av[1], ss_bot->name);
	return 1;
}

int CheckMonBotKill(char* nick)
{
	randomnicks *nickname = NULL;
	lnode_t *rnn;
	lnode_t *mcnode;
	Channel *c;
	char *chan;

	if (SecureServ.monbot[0] == 0) {
		return 0;
	}
	if (strcasecmp(nick, SecureServ.monbot)) {
		return 0;
	}
	rnn = list_first(nicks);
	while (rnn != NULL) {
		nickname = lnode_get(rnn);
		if (!strcasecmp(nickname->nick, SecureServ.monbot)) {
			/* its our bot */
			break;
		}
		rnn = list_next(nicks, rnn);
	}
	if (rnn != NULL) {
		init_bot(nickname->nick, nickname->user, nickname->host, nickname->realname, onjoinbot_modes, "SecureServ");
		irc_cloakhost (find_bot(nickname->nick));
	} else {
		nlog (LOG_WARNING, "Warning, MonBot %s isn't available!", SecureServ.monbot);			
		return -1;
	}
	mcnode = list_first(monchans);
	while (mcnode != NULL) {
		chan = lnode_get(mcnode);
		if (!chan) {
			nlog (LOG_WARNING, "MonChans has a empty node?");
			mcnode = list_next(monchans, mcnode);
			continue;
		}
		c = find_channel(chan);
		if (!c) {
			/* channel isn't online atm, ignore */
			mcnode = list_next(monchans, mcnode);
			continue;
		}
		irc_join (find_bot(SecureServ.monbot), c->name, 0);
		mcnode = list_next(monchans, mcnode);		
	}
	return 1;
}

void OnJoinDelChan(Channel* c) 
{
	SET_SEGV_LOCATION();

	if (c->users != 2) {
		return;
	}
	/* first, if the lastchan and last nick are not empty, it means one of our bots is in a chan, sign them off */
	if (SecureServ.lastnick[0] != 0 && SecureServ.lastchan[0] != 0) {
		if (find_user(SecureServ.lastnick)) {
			if (strcasecmp(SecureServ.lastchan, c->name) == 0) {
				irc_part (find_bot(SecureServ.lastnick), SecureServ.lastchan);
				irc_quit ( find_bot(SecureServ.lastnick), "Finished Scanning");
				SecureServ.lastchan[0] = 0;
				SecureServ.lastnick[0] = 0;
			}
		}
	}
}
