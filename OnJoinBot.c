/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2003 Justin Hammond
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

list_t *monchans;
int SaveMonChans();

#ifdef UMODE_HIDE
static char onjoinbot_modes[]="+x";
#else
static char onjoinbot_modes[]="+";
#endif

unsigned hrand(unsigned upperbound, unsigned lowerbound) {
	if ((upperbound < 1)) return -1;
	return ((unsigned)(rand()%((int)(upperbound-lowerbound+1))-((int)(lowerbound-1))));
}
  
int chkmonchan (const void *key1, const void *key2) {
	char *chan = (char *)key1;
	char *chk = (char *)key2;
	return (strcasecmp(chan, chk));
}


Chans *GetRandomChan() {
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

void JoinNewChan() {
	Chans *c;
	randomnicks *nickname = NULL;
	lnode_t *rnn;
	int i, j, trynick, trychan;
	User *u;

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


	trychan = 0;
restartchans:
	trychan++;
	if (trychan > 5) {
		/* give up after 5 attempts */
		nlog(LOG_DEBUG1, LOG_MOD, "Couldn't find a fresh Channel, Giving up");
		SecureServ.lastchan[0] = 0;
		SecureServ.lastnick[0] = 0;
		return;
	}

	c = GetRandomChan();
	if (c != NULL) {
		nlog(LOG_DEBUG1, LOG_MOD, "Random Chan is %s", c->name);

		/* if channel is private and setting is enabled, don't join */
		if ((SecureServ.doprivchan == 0) && (is_pub_chan(c))) {
			nlog(LOG_DEBUG1, LOG_MOD, "Not Scanning %s, as its a private channel", c->name);
			goto restartchans;
		}


		if (!strcasecmp(SecureServ.lastchan, c->name) || !strcasecmp(me.chan, c->name)) {
			/* this was the last channel we joined, don't join it again */
			nlog(LOG_DEBUG1, LOG_MOD, "Not Scanning %s, as we just did it", c->name);
			goto restartchans;
		}
		/* if the channel is exempt, restart */
		if (Chan_Exempt(c) > 0) {
			goto restartchans;
		}
		/* if we are already monitoring with a monbot, don't join */
		if (list_find(monchans, c->name, chkmonchan)) {
			nlog(LOG_DEBUG1, LOG_MOD, "Not Scanning %s as we are monitoring it with a monbot",c->name);
			goto restartchans;
		}
		strlcpy(SecureServ.lastchan, c->name, CHANLEN);
	} else {
		/* hu? */
		nlog(LOG_DEBUG1, LOG_MOD, "Hu? Couldn't find a channel");
		SecureServ.lastchan[0] = 0;
		SecureServ.lastnick[0] = 0;
		return;
	}
	trynick = 0;
restartnicks:
	trynick++;
	if (trynick > 5) {
		/* give up if we try five times */
		nlog(LOG_DEBUG1, LOG_MOD, "Couldn't find a free nickname, giving up");
		SecureServ.lastchan[0] = 0;
		SecureServ.lastnick[0] = 0;
		return;
	}
	j = 1;
	i = hrand(list_count(nicks)-1, 0 );
	rnn = list_first(nicks);
	while (rnn != NULL) {
		if (j == i) {
			nickname = lnode_get(rnn);
			if (!strcasecmp(nickname->nick, SecureServ.lastnick)) {
				/* its the same as last time, nope */
				nlog(LOG_DEBUG1, LOG_MOD, "%s was used last time. Retring", nickname->nick);
				goto restartnicks;
			}
			/* make sure no one is online with this nickname */
			u = finduser(nickname->nick);
			if (u != NULL) {
				nlog(LOG_DEBUG1, LOG_MOD, "%s is online, can't use that nick, retring", nickname->nick);
				goto restartnicks;
			}
			break;
		}
		j++;
		rnn = list_next(nicks, rnn);
	}
	strlcpy(SecureServ.lastnick, nickname->nick, MAXNICK);
	nlog(LOG_DEBUG1, LOG_MOD, "RandomNick is %s", nickname->nick);

	/* ok, init the new bot. */
	if (init_bot(nickname->nick, nickname->user, nickname->host, nickname->rname, onjoinbot_modes, "SecureServ") == -1) {
		/* hu? Nick was in use. How is that possible? */
		SecureServ.lastchan[0] = 0;
		SecureServ.lastnick[0] = 0;
		nlog(LOG_WARNING, LOG_MOD, "init_bot reported nick was in use. How? Dunno");
		return;
	}
#if defined(ULTIMATE3) || defined(BAHAMUT) || defined(QUANTUM) || defined(LIQUID)
	sjoin_cmd(nickname->nick, c->name, 0);
#else
	sjoin_cmd(nickname->nick, c->name);
#endif

	if (SecureServ.verbose) chanalert(me.allbots ? nickname->nick : s_SecureServ, "Scanning %s with %s for OnJoin Viruses", c->name, nickname->nick);
	
	
	
}

int CheckChan(User *u, char *requestchan) {
	Chans *c;
	randomnicks *nickname = NULL;
	lnode_t *rnn;
	int i, j, trynick, trychan;
	
	c = findchan(requestchan);

	if (!c) {
		prefmsg(u->nick, s_SecureServ, "Can not find Channel %s, It has to have Some Users!", requestchan);
		return -1;
	}			
	trynick = 0;

restartnicksondemand:
	trynick++;
	if (trynick > 5) {
		/* give up if we try five times */
		nlog(LOG_DEBUG1, LOG_MOD, "Couldn't find a free nickname, giving up");
		prefmsg(u->nick, s_SecureServ, "Couldnt Find a free Nickname to check %s with. Giving up (Try again later)", requestchan);
#if 0
		SecureServ.lastchan[0] = 0;
		SecureServ.lastnick[0] = 0;
#endif
		return -1;
	}
	j = 1;
	i = hrand(list_count(nicks)-1, 0 );
	rnn = list_first(nicks);
	while (rnn != NULL) {
		if (j == i) {
			nickname = lnode_get(rnn);
			if (!strcasecmp(nickname->nick, SecureServ.lastnick)) {
				/* its the same as last time, nope */
				goto restartnicksondemand;
			}
			/* make sure no one is online with this nickname */
			if (finduser(nickname->nick) != NULL) {
				goto restartnicksondemand;
			}
			break;
		}
		j++;
		rnn = list_next(nicks, rnn);
	}
	nlog(LOG_DEBUG1, LOG_MOD, "RandomNick is %s", nickname->nick);

	/* first, if the lastchan and last nick are not empty, it means one of our bots is in a chan, sign them off */
	if (SecureServ.lastchan[0] != 0) {
		spart_cmd(SecureServ.lastnick, SecureServ.lastchan);
		del_bot(SecureServ.lastnick, "Finished Scanning");
	}
	/* restore segvinmodules */
	SET_SEGV_INMODULE("SecureServ");
	trychan = 0;

	strlcpy(SecureServ.lastnick, nickname->nick, MAXNICK);
	strlcpy(SecureServ.lastchan, c->name, CHANLEN);

	/* ok, init the new bot. */
	init_bot(nickname->nick, nickname->user, nickname->host, nickname->rname, onjoinbot_modes, "SecureServ");
#if defined(ULTIMATE3) || defined(BAHAMUT) || defined(QUANTUM) || defined(LIQUID)
	sjoin_cmd(nickname->nick, c->name, 0);
#else
	sjoin_cmd(nickname->nick, c->name);
#endif

	chanalert(me.allbots ? nickname->nick : s_SecureServ, "Scanning %s with %s for OnJoin Viruses by request of %s", c->name, nickname->nick, u->nick);
	prefmsg(u->nick, s_SecureServ, "Scanning %s with %s", c->name, nickname->nick);
	return 1;
}


void OnJoinBotMsg(User *u, char **argv, int ac) {
	char *buf;
	lnode_t *node;
	virientry *viridetails;
	int rc;

	if (!u) {
		return;
	}
	
	if (!strcasecmp(argv[1], "\1version\1")) {
		/* its a version request */
		notice(u->nick, s_SecureServ, "\1VERSION %s\1", SecureServ.sampleversion);
		return;
	}	

	/* check if this user is exempt */
	if (is_exempt(u) > 0) {
		nlog(LOG_DEBUG1, LOG_MOD, "User %s is exempt from Message Checking", u->nick);
		return;
	}


	buf = joinbuf(argv, ac, 1);
	node = list_first(viri);
	nlog(LOG_NORMAL, LOG_MOD, "Received message from %s to OnJoin Bot: %s", u->nick, buf);
	if (SecureServ.verbose||SecureServ.BotEcho) chanalert(me.allbots ? argv[0] : s_SecureServ, "OnJoin Bot %s Received Private Message from %s: %s", argv[0], u->nick, buf);
	do {
		viridetails = lnode_get(node);
		if ((viridetails->dettype == DET_MSG) || (viridetails->dettype > 20)) {
			SecureServ.trigcounts[DET_MSG]++;
			nlog(LOG_DEBUG1, LOG_MOD, "SecureServ: Checking Message %s (%s) against %s", buf, u->nick, viridetails->recvmsg);
			rc = pcre_exec(viridetails->pattern, viridetails->patternextra, buf, strlen(buf), 0, 0, NULL, 0);
			if (rc < -1) {
				nlog(LOG_WARNING, LOG_MOD, "PatternMatch PrivateMessage Failed: (%d)", rc);
				continue;
			}
			if (rc > -1) {					
				gotpositive(u, viridetails, DET_MSG);
				if (SecureServ.breakorcont == 0)
					continue;
				else 
					break;
			}
	
		}
	} while ((node = list_next(viri, node)) != NULL);
	free(buf);
}				

int ss_kick_chan(char **argv, int ac) {
	lnode_t *mn;
	
	/* check its one of our nicks */
	if (!strcasecmp(SecureServ.lastnick, argv[1]) && (!strcasecmp(SecureServ.lastchan, argv[0]))) {
		nlog(LOG_DEBUG1, LOG_MOD, "Our Bot %s was kicked from %s", argv[1], argv[0]);
		SecureServ.lastchan[0] = 0;
	}
	if (SecureServ.monbot[0] == 0) {
		return 1;
	}
	/* if its our monbot, rejoin the channel! */
	if (!strcasecmp(SecureServ.monbot, argv[1])) {
		mn = list_first(monchans);
		while (mn != NULL) {
			if (!strcasecmp(argv[0], lnode_get(mn))) {
				/* rejoin the monitor bot to the channel */
#if defined(ULTIMATE3) || defined(BAHAMUT) || defined(QUANTUM) || defined(LIQUID)
				sjoin_cmd(SecureServ.monbot, argv[0], 0);
#else
				sjoin_cmd(SecureServ.monbot, argv[0]);
#endif
				/* restore segvinmodules */
				SET_SEGV_INMODULE("SecureServ");
				if (SecureServ.verbose) chanalert(s_SecureServ, "%s was kicked out of Monitored Chanel %s by %s. Rejoining", argv[1], argv[0], argv[2]);
				return 1;
			}
			mn = list_next(monchans, mn);
		}
	}					
	return 1;
}		


int MonChan(User *u, char *requestchan) {
	Chans *c;
	randomnicks *nickname = NULL;
	lnode_t *rnn;
	char *buf;
	
	c = findchan(requestchan);

	if (!c) {
		if (u) prefmsg(u->nick, s_SecureServ, "Can not find Channel %s, It has to have Some Users!", requestchan);
		return -1;
	}			
	if (SecureServ.monbot[0] ==0) {
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
		prefmsg(u->nick, s_SecureServ, "Can not monitor any additionally channels");
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
		} else {
			nlog(LOG_WARNING, LOG_MOD, "Warning, MonBot %s isn't available!", SecureServ.monbot);			return -1;
		}
	}
	/* restore segvinmodules */
	SET_SEGV_INMODULE("SecureServ");
	
	/* join the monitor bot to the new channel */
#if defined(ULTIMATE3) || defined(BAHAMUT) || defined(QUANTUM) || defined(LIQUID)
	sjoin_cmd(SecureServ.monbot, c->name, 0);
#else
	sjoin_cmd(SecureServ.monbot, c->name);
#endif
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

int StopMon(User *u, char *chan) {
	lnode_t *node, *node2;
	int ok = 0; 

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

int ListMonChan(User *u) {
	lnode_t *node;
	prefmsg(u->nick, s_SecureServ, "Monitored Channels List (%d):", (int)list_count(monchans)); node = list_first(monchans);
	while (node != NULL) {
		prefmsg(u->nick, s_SecureServ, "%s", (char*)lnode_get(node));
		node = list_next(monchans, node);
	}
	prefmsg(u->nick, s_SecureServ, "End of List");
	return 1;
}


int LoadMonChans() {
	int i;
	char **chan;
	monchans = list_create(20);
	if (GetDir("MonChans", &chan) > 0) {
		for (i = 0; chan[i] != NULL; i++) {
			MonChan(NULL, chan[i]);
		}
	}
	free(chan);	
	return 1;
}

int SaveMonChans() {
	lnode_t *node;
	char buf[255];
	DelConf("MonChans");
	node = list_first(monchans);
	while (node != NULL) {
		ircsnprintf(buf, 255, "MonChans/%s", (char *)lnode_get(node));
		SetConf((void *)1, CFGINT, buf);
		node = list_next(monchans, node);
	}
	return 1;
}
