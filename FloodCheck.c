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

/* http://sourceforge.net/projects/muhstik/ */

#include <stdio.h>
#include "neostats.h"
#include "SecureServ.h"

/* the structure to keep track of joins per period (ajpp = average joins per period) */
typedef struct ChanInfo {
	Channel *c;
	int ajpp;
	time_t sampletime;
	int locked;
}ChanInfo;

/* this is the nickflood stuff */
typedef struct nicktrack {
	char nick[MAXNICK];
	int changes;
	int when;
}nicktrack;

/* the hash that contains the channels we are tracking */
static hash_t *FC_Chans;

/* the hash that contains the nicks we are tracking */
static hash_t *nickflood;

/* init the channel hash */	
int InitJoinFlood(void) 
{
	SET_SEGV_LOCATION();
	FC_Chans = hash_create(-1, 0, 0);
	return 1;
}

/* update ajpp for chan, if required */
int JoinFloodJoinChan (Client *u, Channel *c) 
{
	ChanInfo *ci;
	hnode_t *cn;

	
	SET_SEGV_LOCATION();
	
	if (u->flags && NS_FLAGS_NETJOIN) {
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
		dlog (DEBUG2, "Creating Channel Record in JoinSection %s", c->name);
		ci = ns_malloc (sizeof(ChanInfo));
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
		dlog (DEBUG2, "ChanJoin: SampleTime Expired, Resetting %s", c->name);
		ci->sampletime = time(NULL);
		ci->ajpp = 1;
		return 1;
	}
		
	/* now check if ajpp has exceeded the threshold */
	
	/* XXX TOTHINK should we have different thresholds for different channel 
	 * sizes? Needs some real life testing I guess 
	 */		
	ci->ajpp++;	

	if ((ci->ajpp > SecureServ.JoinThreshold) && (ci->locked > 0)) {
		nlog (LOG_WARNING, "Warning, Possible Flood on %s. Closing Channel. (AJPP: %d/%d Sec, SampleTime %d", ci->c->name, ci->ajpp, (int)(time(NULL) - ci->sampletime), SecureServ.sampletime);
		irc_chanalert (ss_bot, "Warning, Possible Flood on %s. Closing Channel. (AJPP: %d/%d Sec, SampleTime %d)", ci->c->name, ci->ajpp, (int)(time(NULL) - ci->sampletime), SecureServ.sampletime);			
		irc_globops (ss_bot, "Warning, Possible Flood on %s. Closing Channel. (AJPP: %d/%d Sec, SampleTime %d)", ci->c->name, ci->ajpp, (int)(time(NULL) - ci->sampletime), SecureServ.sampletime);			
		irc_chanprivmsg (ss_bot, ci->c->name, "Temporarily closing channel due to possible floodbot attack. Channel will be re-opened in %d seconds", SecureServ.closechantime);
		/* uh oh, channel is under attack. Close it down. */
		irc_cmode (ss_bot, ci->c->name, "+ik", SecureServ.ChanKey);
		ci->locked = time(NULL);
	}		

	/* just some record keeping */
	if (ci->ajpp > SecureServ.MaxAJPP) {
		dlog (DEBUG1, "New AJPP record on %s at %d Joins in %d Seconds", c->name, ci->ajpp, (int)(time(NULL) - ci->sampletime));
		if (SecureServ.verbose) irc_chanalert (ss_bot, "New AJPP record on %s at %d Joins in %d Seconds", c->name, ci->ajpp, (int)(time(NULL) - ci->sampletime));
		SecureServ.MaxAJPP = ci->ajpp;
		strlcpy(SecureServ.MaxAJPPChan, c->name, MAXCHANLEN);
	}
	return 1;
}

/* delete the channel from our hash */
int JoinFloodDelChan(Channel *c) 
{
	ChanInfo *ci;
	hnode_t *cn;

	SET_SEGV_LOCATION();
	cn = hash_lookup(FC_Chans, c->name);
	if (cn) {
		ci = hnode_get(cn);
		hash_delete(FC_Chans, cn);
		ns_free (ci);
		hnode_destroy(cn);
#if 0		
	} else {
		/* ignore this, as it just means since we started SecureServ, no one has joined the channel, and now the last person has left. Was just flooding logfiles */
		//nlog (LOG_WARNING, "Can't Find Channel %s in our Hash", c->name);
#endif
	}
	return 1;
}

int CheckLockChan() 
{
	hscan_t cs;
	hnode_t *cn;
	ChanInfo *ci;
	
	SET_SEGV_LOCATION();
	/* scan through the channels */
	hash_scan_begin(&cs, FC_Chans);
	while ((cn = hash_scan_next (&cs)) != NULL) {
		ci = hnode_get(cn);
		/* if the locked time plus closechantime is greater than current time, then unlock the channel */
		if ((ci->locked > 0) && (ci->locked + SecureServ.closechantime < time(NULL))) {
			irc_cmode (ss_bot, ci->c->name, "-ik", SecureServ.ChanKey);
			irc_chanalert (ss_bot, "Unlocking %s after floodprotection timeout", ci->c->name);
			irc_globops (ss_bot, "Unlocking %s after flood protection timeout", ci->c->name);
			irc_chanprivmsg (ss_bot, ci->c->name, "Unlocking the channel now");
			ci->locked = 0;
		}					
	}
	return 1;
}

int InitNickFlood(void)
{
	SET_SEGV_LOCATION();
	/* init the nickflood hash */
	nickflood = hash_create(-1, 0, 0);
	return 1;
}

/* periodically clean up the nickflood hash so it doesn't grow to big */
int CleanNickFlood() 
{
	hscan_t nfscan;
	hnode_t *nfnode;
	nicktrack *nick;

	SET_SEGV_LOCATION();
    hash_scan_begin(&nfscan, nickflood);
    while ((nfnode = hash_scan_next(&nfscan)) != NULL) {
        nick = hnode_get(nfnode);
        if ((time(NULL) - nick->when) > 10) {
        	/* delete the nickname */
		dlog (DEBUG2, "Deleting %s out of NickFlood Hash", nick->nick);
        	hash_scan_delete(nickflood, nfnode);
        	ns_free (nick);
        }
    }
	return 1;
}       
	                
int CheckNickFlood(Client* u)
{
	hnode_t *nfnode;
	nicktrack *nick;

	SET_SEGV_LOCATION();
	nfnode = hash_lookup(nickflood, u->name);
	if (nfnode) {
		/* its already there */
		nick = hnode_get(nfnode);
		/* first, remove it from the hash, as the nick has changed */
		hash_delete(nickflood, nfnode);
		/* increment the nflood count */
		nick->changes++;
		dlog (DEBUG2, "NickFlood Check: %d in 10", nick->changes);
		if ((nick->changes > SecureServ.nfcount) && ((time(NULL) - nick->when) <= 10)) {
			/* its a bad bad bad flood */
			irc_chanalert (ss_bot, "NickFlood Detected on %s", u->name);
			/* XXX Do Something bad !!!! */
			
			/* ns_free the struct */
			hnode_destroy(nfnode);
			ns_free (nick);
		} else if ((time(NULL) - nick->when) > 10) {
			dlog (DEBUG2, "Resetting NickFlood Count on %s", u->name);
			strlcpy(nick->nick, u->name, MAXNICK);
			nick->changes = 1;
			nick->when = time(NULL);
			hash_insert(nickflood, nfnode, nick->nick);
		} else {			
			/* re-insert it into the hash */
			strlcpy(nick->nick, u->name, MAXNICK);
			hash_insert(nickflood, nfnode, nick->nick);
		}
	} else {
		/* this is because maybe we already have a record from a signoff etc */
		if (!hash_lookup(nickflood, u->name)) {
			/* this is a first */
			nick = ns_malloc (sizeof(nicktrack));
			strlcpy(nick->nick, u->name, MAXNICK);
			nick->changes = 1;
			nick->when = time(NULL);
			nfnode = hnode_create(nick);
			hash_insert(nickflood, nfnode, nick->nick);
			dlog (DEBUG2, "NF: Created New Entry");
		} else {
			dlog (DEBUG2, "Already got a record for %s in NickFlood", u->name);
		}
	}
	return 0;
}

int NickFloodSignOff(char * n)
{
	hnode_t *nfnode;
	nicktrack *nick;

	SET_SEGV_LOCATION();
	dlog (DEBUG2, "DelNick: looking for %s", n);
	nfnode = hash_lookup(nickflood, n);
	if (nfnode) {
		nick = hnode_get(nfnode);
		hash_delete(nickflood, nfnode);
       		hnode_destroy(nfnode);
		ns_free (nick);
	}
	dlog (DEBUG2, "DelNick: After nickflood Code");
	return 1;
}
