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
** $Id: FloodCheck.c,v 1.9 2003/07/30 15:38:41 fishwaldo Exp $
*/

/* http://sourceforge.net/projects/muhstik/ */

#include <stdio.h>
#include <fnmatch.h>
#include "dl.h"
#include "log.h"
#include "stats.h"
#include "conf.h"
#include "SecureServ.h"

/* the structure to keep track of joins per period (ajpp = average joins per period) */
struct ci_ {
	Chans *c;
	int ajpp;
	time_t sampletime;
	int locked;
};

typedef struct ci_ ChanInfo;

/* the hash that contains the channels we are tracking */

hash_t *FC_Chans;

/* init the channel hash */	
void ss_init_chan_hash() {

	FC_Chans = hash_create(-1, 0, 0);
}

/* update ajpp for chan, if required */
int ss_join_chan(char **av, int ac) {
	User *u;
	Chans *c;
	ChanInfo *ci;
	hnode_t *cn;
        lnode_t *node;
        virientry *viridetails;
        int rc;
	

	/* if we not even inited, exit this */
	if (SecureServ.inited != 1) return -1;

	/* find the chan in the Core */
	c = findchan(av[0]);
	if (!c) {
		nlog(LOG_WARNING, LOG_MOD, "joinchan: Can't Find Channel %s", av[0]);
		return -1;
	}
	
	/* is it exempt? */
	if (Chan_Exempt(c) > 0) {
		return -1;
	}

	
	/* first, check if this is a *bad* channel */
        node = list_first(viri);
        if (node) {
                do {
       	        	viridetails = lnode_get(node);
               		if (viridetails->dettype == DET_CHAN) {
               			SecureServ.trigcounts[DET_CHAN]++;
                               	nlog(LOG_DEBUG1, LOG_MOD, "TS: Checking Chan %s against %s", c->name, viridetails->recvmsg);
                                rc = pcre_exec(viridetails->pattern, viridetails->patternextra, c->name, strlen(c->name), 0, 0, NULL, 0);
       	                        if (rc < -1) {
        	                        nlog(LOG_WARNING, LOG_MOD, "PatternMatch Chan Failed: (%d)", rc);
                       	                continue;
                               	}
                                if (rc > -1) {
	                                gotpositive(finduser(av[1]), viridetails, DET_CHAN);
               	                        if (SecureServ.breakorcont == 0)
                	                        continue;
                               	        else
                                       	        return 1;
                                }
       	                }
               	} while ((node = list_next(viri, node)) != NULL);
	}

	
	u = finduser(av[1]);
	if (u) {
		/* check for netjoins!!!*/
		/* XXX this isn't really the best, as a lot of 
		* floodbots could connect to a IRC server, wait 
		* SecureServ.timediff, and then join the channel, 
		* and SecureServ isn't going to flag them. It would be
		* nicer if the IRCd protocol could easily identify nicks
		* that are ridding in on a netjoin. 
		*/
		if ((time(NULL) - u->TS) > SecureServ.timedif) {
			nlog(LOG_DEBUG2, LOG_MOD, "Nick %s is Riding a NetJoin", av[1]);
			/* forget the update */
			return -1;
		}

		/* ok, now if the server just linked in as well, ignore this */
		/* XXX should this time be configurable? */
		if ((time(NULL) - u->server->connected_since) < 120) {
			nlog(LOG_DEBUG2, LOG_MOD, "Ignoring %s joining %s as it seems server %s just linked", u->nick, c->name, u->server->name);
			return -1;
		}
	} else {
		nlog(LOG_WARNING, LOG_MOD, "Can't find nick %s", av[1]);
		return -1;
	}

	/* if channel flood protection is disabled, return here */
	if (SecureServ.FloodProt == 0) {
		return 1;
	}

	/* find the chan in SecureServ's list */
	cn = hash_lookup(FC_Chans, c->name);
	if (!cn) {

		/* if it doesn't exist, means we have to create it ! */
		nlog(LOG_DEBUG2, LOG_MOD, "Creating Channel Record in JoinSection %s", c->name);
		ci = malloc(sizeof(ChanInfo));
		ci->ajpp = 0;
		ci->sampletime = 0;
		ci->c = c;
		ci->locked = 0;
		cn = hnode_create(ci);
		hash_insert(FC_Chans, cn, c->name);
	} else {		
		ci = hnode_get(cn);
	}
		
	/* Firstly, if the last join was "SampleTime" seconds ago
	 * then reset the time, and set ajpp to 1
	 */
	if ((time(NULL) - ci->sampletime) > SecureServ.sampletime) {
		nlog(LOG_DEBUG2, LOG_MOD, "ChanJoin: SampleTime Expired, Resetting %s", av[0]);
		ci->sampletime = time(NULL);
		ci->ajpp = 1;
		return 1;
	}
		
	/* now check if ajpp has exceeded the threshold */
	
	/* XXX TOTHINK should we have different thresholds for different channel 
	 * sizes? Needs some real life testing I guess 
	 */		
	ci->ajpp++;	

	if (ci->ajpp > SecureServ.JoinThreshold) {
		nlog(LOG_WARNING, LOG_MOD, "Warning, Possible Flood on %s. (AJPP: %d/%d Sec, SampleTime %d", ci->c->name, ci->ajpp, (time(NULL) - ci->sampletime), SecureServ.sampletime);
		chanalert(s_SecureServ, "Warning, Possible Flood on %s. Closing Chan. (AJPP: %d/%d Sec, SampleTime %d)", ci->c->name, ci->ajpp, (time(NULL) - ci->sampletime), SecureServ.sampletime);			
		globops(s_SecureServ, "Warning, Possible Flood on %s. Closing Chan. (AJPP: %d/%d Sec, SampleTime %d)", ci->c->name, ci->ajpp, (time(NULL) - ci->sampletime), SecureServ.sampletime);			
		prefmsg(ci->c->name, s_SecureServ, "Temporarly closing channel due to possible floodbot attack. Channel will be re-opened in %d seconds", SecureServ.closechantime);
		/* uh oh, channel is under attack. Close it down. */
		schmode_cmd(s_SecureServ, ci->c->name, "+ik", SecureServ.ChanKey);
		ci->locked = time(NULL);
	}		

	/* just some record keeping */
	if (ci->ajpp > SecureServ.MaxAJPP) {
		nlog(LOG_DEBUG1, LOG_MOD, "New AJPP record on %s at %d Joins in %d Seconds", c->name, ci->ajpp, time(NULL) - ci->sampletime);
		if (SecureServ.verbose) chanalert(s_SecureServ, "New AJPP record on %s at %d Joins in %d Seconds", c->name, ci->ajpp, time(NULL) - ci->sampletime);
		SecureServ.MaxAJPP = ci->ajpp;
		strncpy(SecureServ.MaxAJPPChan, c->name, CHANLEN);
	}
	return 1;
}

/* delete the channel from our hash */
int ss_del_chan(char **av, int ac) {
	Chans *c;
        ChanInfo *ci;
        hnode_t *cn;

	c = findchan(av[0]);
	if (!c) {
		nlog(LOG_WARNING, LOG_MOD, "Can't find Channel %s", av[0]);
		return -1;
	}
	cn = hash_lookup(FC_Chans, c->name);
	if (cn) {
		ci = hnode_get(cn);
		hash_delete(FC_Chans, cn);
		free(ci);
		hnode_destroy(cn);
#if 0		
	} else {
		/* ignore this, as it just means since we started SecureServ, no one has joined the channel, and now the last person has left. Was just flooding logfiles */
		//nlog(LOG_WARNING, LOG_MOD, "Can't Find Channel %s in our Hash", c->name);
#endif
	}
	return 1;
}

int CheckLockChan() {
	hscan_t cs;
	hnode_t *cn;
	ChanInfo *ci;
	
	/* scan through the channels */
	hash_scan_begin(&cs, FC_Chans);
	while ((cn = hash_scan_next (&cs)) != NULL) {
		ci = hnode_get(cn);
		/* if the locked time plus closechantime is greater than current time, then unlock the channel */
		if ((ci->locked > 0) && (ci->locked + SecureServ.closechantime < time(NULL))) {
			schmode_cmd(s_SecureServ, ci->c->name, "-ik", SecureServ.ChanKey);
			chanalert(s_SecureServ, "Unlocking %s after floodprotection timeout", ci->c->name);
			globops(s_SecureServ, "Unlocking %s after flood protection timeout", ci->c->name);
			prefmsg(ci->c->name, s_SecureServ, "Unlocking the Channel now");
			ci->locked = 0;
		}					
	}
	return 1;
}
