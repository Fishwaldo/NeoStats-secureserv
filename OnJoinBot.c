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
** $Id: OnJoinBot.c,v 1.3 2003/04/22 12:49:26 fishwaldo Exp $
*/


#include <stdio.h>
#include <fnmatch.h>
#include "dl.h"
#include "log.h"
#include "stats.h"
#include "conf.h"
#include "SecureServ.h"


unsigned hrand(unsigned upperbound, unsigned lowerbound) {
	return ((unsigned)(rand()%((int)(upperbound-lowerbound+1))-((int)(lowerbound-1))));
}
  

Chans *GetRandomChan() {
	hscan_t cs;
	hnode_t *cn;
	int randno, curno;
	
	curno = 0;
	randno = hrand(hash_count(ch), 1);	
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
	static char lastchan[CHANLEN];
	static char lastnick[MAXNICK];
	randomnicks *nickname = NULL;
	lnode_t *rnn;
	int i, j, trynick, trychan;
	User *u;

	/* first, if the lastchan and last nick are not empty, it means one of our bots is in a chan, sign them off */
	if (strlen(lastchan) > 1) {
		spart_cmd(lastnick, lastchan);
		del_bot(lastnick, "Finished Scanning");
	}
	trychan = 0;
restartchans:
	trychan++;
	if (trychan > 5) {
		/* give up after 5 attempts */
		nlog(LOG_DEBUG1, LOG_MOD, "Couldn't find a fresh Channel, Giving up");
		return;
	}

	c = GetRandomChan();
	if (c != NULL) {
		nlog(LOG_DEBUG1, LOG_MOD, "Random Chan is %s", c->name);
		if (!strcasecmp(lastchan, c->name) || !strcasecmp(me.chan, c->name)) {
			/* this was the last channel we joined, don't join it again */
			goto restartchans;
		}
		strncpy(lastchan, c->name, CHANLEN);
	}
	trynick = 0;
restartnicks:
	trynick++;
	if (trynick > 5) {
		/* give up if we try five times */
		nlog(LOG_DEBUG1, LOG_MOD, "Couldn't find a free nickname, giving up");
		return;
	}
	j = 1;
	i = hrand(list_count(nicks)-1, 0 );
	rnn = list_first(nicks);
	while (rnn != NULL) {
		if (j == i) {
			nickname = lnode_get(rnn);
			if (!strcasecmp(nickname->nick, lastnick)) {
				/* its the same as last time, nope */
				goto restartnicks;
			}
			/* make sure no one is online with this nickname */
			u = finduser(nickname->nick);
			if (u != NULL) {
				goto restartnicks;
			}
			break;
		}
		j++;
		rnn = list_next(nicks, rnn);
	}
	strncpy(lastnick, nickname->nick, MAXNICK);
	nlog(LOG_DEBUG1, LOG_MOD, "RandomNick is %s", nickname->nick);

	/* ok, init the new bot. */
	init_bot(nickname->nick, nickname->user, nickname->host, nickname->rname, "+i", "SecureServ");
#ifdef ULTIMATE3
	sjoin_cmd(nickname->nick, c->name, "");
#else
	sjoin_cmd(nickname->nick, c->name);
#endif

	if (SecureServ.verbose) chanalert(me.allbots ? nickname->nick : s_SecureServ, "Scanning %s for OnJoin Virus's", c->name);
	
	
	
}
