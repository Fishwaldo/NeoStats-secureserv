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
** $Id: OnJoinBot.c,v 1.20 2003/07/17 13:41:33 fishwaldo Exp $
*/


#include <stdio.h>
#include <fnmatch.h>
#include "dl.h"
#include "log.h"
#include "stats.h"
#include "conf.h"
#include "SecureServ.h"


unsigned hrand(unsigned upperbound, unsigned lowerbound) {
	if ((upperbound < 1)) return -1;
	return ((unsigned)(rand()%((int)(upperbound-lowerbound+1))-((int)(lowerbound-1))));
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
		if (strlen(SecureServ.lastchan) > 1) {
			spart_cmd(SecureServ.lastnick, SecureServ.lastchan);
		}
		del_bot(SecureServ.lastnick, "Finished Scanning");
		strncpy(SecureServ.lastchan, "\0", CHANLEN);
		strncpy(SecureServ.lastnick, "\0", MAXNICK);
	}
	/* restore segvinmodules */
	strcpy(segvinmodule, "SecureServ");

	/* if we don't do OnJoin Checking, Don't go any further */
	if (SecureServ.DoOnJoin < 1)
		return;



	trychan = 0;
restartchans:
	trychan++;
	if (trychan > 5) {
		/* give up after 5 attempts */
		nlog(LOG_DEBUG1, LOG_MOD, "Couldn't find a fresh Channel, Giving up");
		strncpy(SecureServ.lastchan, "\0", CHANLEN);
		strncpy(SecureServ.lastnick, "\0", MAXNICK);
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
		strncpy(SecureServ.lastchan, c->name, CHANLEN);
	} else {
		/* hu? */
		nlog(LOG_DEBUG1, LOG_MOD, "Hu? Couldn't find a channel");
		strncpy(SecureServ.lastchan, "\0", CHANLEN);
		strncpy(SecureServ.lastnick, "\0", MAXNICK);
		return;
	}
	trynick = 0;
restartnicks:
	trynick++;
	if (trynick > 5) {
		/* give up if we try five times */
		nlog(LOG_DEBUG1, LOG_MOD, "Couldn't find a free nickname, giving up");
		strncpy(SecureServ.lastchan, "\0", CHANLEN);
		strncpy(SecureServ.lastnick, "\0", MAXNICK);
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
	strncpy(SecureServ.lastnick, nickname->nick, MAXNICK);
	nlog(LOG_DEBUG1, LOG_MOD, "RandomNick is %s", nickname->nick);

	/* ok, init the new bot. */
	if (init_bot(nickname->nick, nickname->user, nickname->host, nickname->rname, "+", "SecureServ") == -1) {
		/* hu? Nick was in use. How is that possible? */
		strncpy(SecureServ.lastnick, "\0", MAXNICK);
		strncpy(SecureServ.lastchan, "\0", MAXNICK);
		nlog(LOG_WARNING, LOG_MOD, "init_bot reported nick was in use. How? Dunno");
		return;
	}
#ifdef ULTIMATE3
	sjoin_cmd(nickname->nick, c->name, 0);
#else
	sjoin_cmd(nickname->nick, c->name);
#endif

	if (SecureServ.verbose) chanalert(me.allbots ? nickname->nick : s_SecureServ, "Scanning %s with %s for OnJoin Virus's", c->name, nickname->nick);
	
	
	
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
		strncpy(SecureServ.lastchan, "\0", CHANLEN);
		strncpy(SecureServ.lastnick, "\0", MAXNICK);
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
	if (strlen(SecureServ.lastchan) > 1) {
		spart_cmd(SecureServ.lastnick, SecureServ.lastchan);
		del_bot(SecureServ.lastnick, "Finished Scanning");
	}
	/* restore segvinmodules */
	strcpy(segvinmodule, "SecureServ");
	trychan = 0;

	strncpy(SecureServ.lastnick, nickname->nick, MAXNICK);
	strncpy(SecureServ.lastchan, c->name, CHANLEN);

	/* ok, init the new bot. */
	init_bot(nickname->nick, nickname->user, nickname->host, nickname->rname, "+i", "SecureServ");
#ifdef ULTIMATE3
	sjoin_cmd(nickname->nick, c->name, 0);
#else
	sjoin_cmd(nickname->nick, c->name);
#endif

	chanalert(me.allbots ? nickname->nick : s_SecureServ, "Scanning %s with %s for OnJoin Virus's by request of %s", c->name, nickname->nick, u->nick);
	prefmsg(u->nick, s_SecureServ, "Scanning %s with %s", c->name, nickname->nick);
	return 1;
}


void OnJoinBotMsg(User *u, char **argv, int ac) {
	char *buf;
	lnode_t *node;
	virientry *viridetails;
	int rc;
	
	/* check if this user is exempt */
	if (is_exempt(u) > 0) {
		nlog(LOG_DEBUG1, LOG_MOD, "User %s is exempt from Message Checking", u->nick);
		return;
	}


	buf = joinbuf(argv, ac, 1);
	node = list_first(viri);
	nlog(LOG_NORMAL, LOG_MOD, "Recieved Messaage from %s to OnJoin Bot: %s", u->nick, buf);
	if (SecureServ.verbose) chanalert(me.allbots ? argv[0] : s_SecureServ, "OnJoin Bot %s Recieved Private Message from %s: %s", argv[0], u->nick, buf);
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
	/* check its one of our nicks */
	if (!strcasecmp(SecureServ.lastnick, argv[1]) && (!strcasecmp(SecureServ.lastchan, argv[0]))) {
		nlog(LOG_DEBUG1, LOG_MOD, "Our Bot %s was kicked from %s", argv[1], argv[0]);
		strncpy(SecureServ.lastchan, "\0", MAXNICK);
	}
	return 1;
}		
