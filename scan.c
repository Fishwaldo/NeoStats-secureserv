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
#include "neostats.h"
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#include "SecureServ.h"

#define MAX_VIRI	-1

static void gotpositive(Client *u, virientry *ve, int type);

/* this is the list of viri */
static list_t *viri;

void InitScanner(void)
{
	SET_SEGV_LOCATION();
	/* init the virus lists */
	viri = list_create(MAX_VIRI);
	load_dat();
}

void ScanStatus (CmdParams *cmdparams)
{
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
}

int ViriCount(void)
{
	return(list_count(viri));
}

/* List of local dat files that we will load and process
*/

const char* DatFiles[NUM_DAT_FILES]=
{
	VIRI_DAT_NAME,
	CUSTOM_DAT_NAME,
};

/* This function will not load viri.dat then try to load custom.dat 
   For custom entries, the lack of file is of no importance and a flag is set
   in the viri entry to indicate the custom nature of the definition for use
   by SecureServ.
*/

void load_dat(void) 
{
	int i;
	FILE *fp;
	char buf[BUFSIZE];
	virientry *viridet;
	lnode_t *node;
	const char *error;
	int errofset;
	pcre *re;
	int rc;
	int ovector[24];
	const char **subs;

	SET_SEGV_LOCATION();
	/* if the list isn't empty, make it empty */
	if (!list_isempty(viri)) {
		node = list_first(viri);
		while (node) {
			viridet = lnode_get(node);
			if(viridet) {
				dlog (DEBUG1, "Deleting %s out of List", viridet->name);
				if (viridet->pattern) {
					ns_free (viridet->pattern);
				}
				if (viridet->patternextra) {
					ns_free (viridet->patternextra);
				}
				ns_free (viridet);
			}
			node = list_next(viri, node);
		} 
		list_destroy_nodes(viri);
	}
	
	for (rc = 0; rc < MAX_PATTERN_TYPES; rc++) {
		SecureServ.definitions[rc] = 0;
	}	

	/* first, add the dat for Fizzer (even if its not enabled!) */
	viridet = ns_malloc (sizeof(virientry));
	strlcpy(viridet->name, "FizzerBot", MAXVIRNAME);
	viridet->dettype = DET_BUILTIN;
	viridet->var1 = 0;
	viridet->var2 = 0;
	viridet->pattern = NULL;
	viridet->patternextra = NULL;
	strlcpy(viridet->recvmsg, "UserName is RealName Reversed", BUFSIZE);
	strlcpy(viridet->sendmsg, "You're Infected with the Fizzer Virus", BUFSIZE);
	viridet->action = ACT_AKILL;
	viridet->nofound = 0;
	SecureServ.definitions[DET_BUILTIN]++;
	node = lnode_create(viridet);
	list_prepend(viri, node);
	dlog (DEBUG1, "loaded %s (Detection %d, with %s, send %s and do %d", viridet->name, viridet->dettype, viridet->recvmsg, viridet->sendmsg, viridet->action);
	
	for(i = 0; i < NUM_DAT_FILES; i++)
	{
		fp = fopen(DatFiles[i], "r");
		if (!fp) {
			if(i)
			{
				/* We do not really care if the custom file is not present so don't report it except in debug */
				/* as the comment says, we don't care about custom.dat, so don't fool users into thinking SecureSer is disabled by telling them it is! */
				dlog (DEBUG1, "No custom.dat file found.");
			}
			else
			{
				/* we *HAVE* to have a viri.dat file. Otherwise, no go */
				nlog (LOG_WARNING, "Error, No viri.dat file found.", ss_bot->name);
			}
			return;
		} else {
			re = pcre_compile("^([a-zA-Z0-9]*) ([0-9]*) ([0-9]*) ([0-9]*) \"(.*)\" \"(.*)\" ([0-9]*).*" , 0, &error, &errofset, NULL);
			if (re == NULL) {
				nlog (LOG_CRITICAL, "PCRE_COMPILE of dat file format failed bigtime! %s at %d", error, errofset);		
				return;
			}
			/* only set version for first file */
			if(i==0) 
			{
				/* first fgets always returns the version number */
				fgets(buf, BUFSIZE, fp);
				SecureServ.viriversion = atoi(buf);
			}
			while (fgets(buf, BUFSIZE, fp)) {
				if (list_isfull(viri))
					break;
				viridet = ns_malloc (sizeof(virientry));
				rc = pcre_exec(re, NULL, buf, strlen(buf), 0, 0, ovector, 24);
				if (rc <= 0) {
					nlog (LOG_WARNING, "PCRE_EXEC didn't have enough space! %d", rc);
					nlog (LOG_WARNING, "Load Was: %s", buf);
					ns_free (viridet);
					continue;
				} else if (rc != 8) {
					nlog (LOG_WARNING, "Didn't get required number of Subs (%d)", rc);
					ns_free (viridet);
					continue;
				}
				
				pcre_get_substring_list(buf, ovector, rc, &subs);		
				strlcpy(viridet->name, subs[1], MAXVIRNAME);
				viridet->dettype = atoi(subs[2]);
				viridet->var1 = atoi(subs[3]);
				viridet->var2 = atoi(subs[4]);
				strlcpy(viridet->recvmsg, subs[5], BUFSIZE);
				strlcpy(viridet->sendmsg, subs[6], BUFSIZE);
				viridet->action = atoi(subs[7]);
				viridet->nofound = 0;
				viridet->pattern = pcre_compile(viridet->recvmsg, 0, &error, &errofset, NULL);
				if (viridet->pattern == NULL) {
					/* it failed for some reason */
					nlog (LOG_WARNING, "Regular Expression Compile of %s Failed: %s at %d", viridet->name, error, errofset);
					ns_free (subs);
					ns_free (viridet);
					continue;
				}	
				viridet->iscustom=i;
				viridet->patternextra = pcre_study(viridet->pattern, 0, &error);
				if (error != NULL) {
					nlog (LOG_WARNING, "Regular Expression Study for %s failed: %s", viridet->name, error);
					/* don't exit */
				}
				SecureServ.definitions[viridet->dettype]++;
				node = lnode_create(viridet);
				list_prepend(viri, node);
				dlog (DEBUG1, "loaded %s (Detection %d, with %s, send %s and do %d", viridet->name, viridet->dettype, viridet->recvmsg, viridet->sendmsg, viridet->action);
				ns_free (subs);
			}
			ns_free (re);
			fclose(fp);
		}
	}	
}

int do_reload(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	irc_prefmsg (ss_bot, cmdparams->source, "Reloading virus definition files");
   	irc_chanalert (ss_bot, "Reloading virus definition files at request of %s", cmdparams->source->name);
	load_dat();
	return 1;
}

int do_list(CmdParams *cmdparams) 
{
	lnode_t *node;
	virientry *ve;
	char type[LOCALBUFSIZE];
	char action[LOCALBUFSIZE];
	int i;

	SET_SEGV_LOCATION();

	i = 0;
	node = list_first(viri);
	if (node) {
		irc_prefmsg (ss_bot, cmdparams->source, "Virus List:");
		irc_prefmsg (ss_bot, cmdparams->source, "===========");
		do {
			ve = lnode_get(node);
			i++;
			switch (ve->dettype) {
				case DET_CTCP:
					strlcpy(type, "Version", LOCALBUFSIZE);
					break;
				case DET_MSG:
					strlcpy(type, "PM", LOCALBUFSIZE);
					break;
				case DET_NICK:
					strlcpy(type, "Nick", LOCALBUFSIZE);
					break;
				case DET_IDENT:
					strlcpy(type, "Ident", LOCALBUFSIZE);
					break;
				case DET_REALNAME:
					strlcpy(type, "RealName", LOCALBUFSIZE);
					break;
				case DET_CHAN:
					strlcpy(type, "Chan", LOCALBUFSIZE);
					break;
				case DET_BUILTIN:
					strlcpy(type, "Built-In", LOCALBUFSIZE);
					break;
				case DET_CHANMSG:
					strlcpy(type, "Channel Message", LOCALBUFSIZE);
					break;
				default:
					ircsnprintf(type, LOCALBUFSIZE, "Unknown(%d)", ve->dettype);
			}
			switch (ve->action) {
				case ACT_SVSJOIN:
					strlcpy(action, "SVSjoin", LOCALBUFSIZE);
					break;
				case ACT_AKILL:
					strlcpy(action, "Akill", LOCALBUFSIZE);
					break;
				case ACT_KILL:
					strlcpy(action, "Kill", LOCALBUFSIZE);
					break;
				case ACT_WARN:
					strlcpy(action, "OpersWarn", LOCALBUFSIZE);
					break;
				default:
					strlcpy(action, "ClientWarn", LOCALBUFSIZE);
			}
			irc_prefmsg (ss_bot, cmdparams->source, "%d) Virus: %s. Detection: %s. Action: %s Hits: %d", i, ve->name, type, action, ve->nofound);
		} while ((node = list_next(viri, node)) != NULL);
		irc_prefmsg (ss_bot, cmdparams->source, "End of List.");
	} else {
		irc_prefmsg (ss_bot, cmdparams->source, "No definitions found.");
	}
	return 1;
}

int ScanFizzer(Client *u) 
{
	lnode_t *node;
	virientry *viridetails;
	char username[10];
	char *s1, *s2, *user;

	SET_SEGV_LOCATION();
							
	/* fizzer requires realname info, which we don't store yet. */
	user = ns_malloc (MAXREALNAME);
	strlcpy(user, u->info, MAXREALNAME); 
	s1 = strtok(user, " ");
	s2 = strtok(NULL, "");
	ircsnprintf(username, 10, "%s%s%s", u->user->username[0] == '~' ? "~" : "",  s2, s1);
	ns_free (user);
#ifdef DEBUG
	dlog (DEBUG2, "Fizzer RealName Check %s -> %s", username, u->user->username);
#endif
	SecureServ.trigcounts[DET_BUILTIN]++;
	if (!strcmp(username, u->user->username)) {
		nlog (LOG_NOTICE, "Fizzer Bot Detected: %s (%s -> %s)", u->name, u->user->username, u->info);
		/* do kill */
		node = list_first(viri);
		if (node) {
			do {
				viridetails = lnode_get(node);
				if (!strcasecmp(viridetails->name, "FizzerBot")) {
					gotpositive(u, viridetails, DET_BUILTIN);
					return 1;
				}
			} while ((node = list_next(viri, node)) != NULL);
		}
		return 1;
	}
	return 0;
}

int ScanUser(Client *u, unsigned flags) 
{
	int positive = 0;
	lnode_t *node;
	virientry *viridetails;
	int rc;

	SET_SEGV_LOCATION();

	node = list_first(viri);
	if (node) {
		do {
			viridetails = lnode_get(node);
			if ((flags & SCAN_NICK) && (viridetails->dettype == DET_NICK)) {
				SecureServ.trigcounts[DET_NICK]++;
#ifdef DEBUG
				dlog (DEBUG1, "Checking Nick %s against %s", u->name, viridetails->recvmsg);
#endif
				rc = pcre_exec(viridetails->pattern, viridetails->patternextra, u->name, strlen(u->name), 0, 0, NULL, 0);
				if (rc < -1) {
					nlog (LOG_WARNING, "PatternMatch Nick Failed: (%d)", rc);
				} else if (rc > -1) {					
					nlog (LOG_NOTICE, "Got positive nick %s for %s against %s", u->name, viridetails->name, viridetails->recvmsg);
					gotpositive(u, viridetails, DET_NICK);
					positive++;
					if (SecureServ.breakorcont != 0) {
						return 1;
					}
				}
			} else if ((flags & SCAN_IDENT) && (viridetails->dettype == DET_IDENT)) {
				SecureServ.trigcounts[DET_IDENT]++;
#ifdef DEBUG
				dlog (DEBUG1, "Checking ident %s against %s", u->user->username, viridetails->recvmsg);
#endif
				rc = pcre_exec(viridetails->pattern, viridetails->patternextra, u->user->username, strlen(u->user->username), 0, 0, NULL, 0);
				if (rc < -1) {
					nlog (LOG_WARNING, "PatternMatch UserName Failed: (%d)", rc);
				} else if (rc > -1) {					
					nlog (LOG_NOTICE, "Got positive ident %s for %s against %s", u->user->username, viridetails->name, viridetails->recvmsg);
					gotpositive(u, viridetails, DET_IDENT);
					positive++;
					if (SecureServ.breakorcont != 0) {
						return 1;
					}
				}
			} else if ((flags & SCAN_REALNAME) && (viridetails->dettype == DET_REALNAME)) {
				SecureServ.trigcounts[DET_REALNAME]++;
#ifdef DEBUG
				dlog (DEBUG1, "Checking Realname %s against %s", u->info, viridetails->recvmsg);
#endif
				rc = pcre_exec(viridetails->pattern, viridetails->patternextra, u->info, strlen(u->info), 0, 0, NULL, 0);
				if (rc < -1) {
					nlog (LOG_WARNING, "PatternMatch RealName Failed: (%d)", rc);
				} else if (rc > -1) {					
					nlog (LOG_NOTICE, "Got positive realname %s for %s against %s", u->info, viridetails->name, viridetails->recvmsg);
					gotpositive(u, viridetails, DET_REALNAME);
					positive++;
					if (SecureServ.breakorcont != 0) {
						return 1;
					}
				}
			}
		} while ((node = list_next(viri, node)) != NULL);
	}
	return positive;
}

int ScanCTCP(Client *u, char* buf) 
{
	int positive = 0;
	lnode_t *node;
	virientry *viridetails;
	int rc;

	SET_SEGV_LOCATION();
	node = list_first(viri);
	if (node) {
		do {
			viridetails = lnode_get(node);
			if (((viridetails->dettype == DET_CTCP) || (viridetails->dettype > MAX_PATTERN_TYPES))) {
				SecureServ.trigcounts[DET_CTCP]++;
#ifdef DEBUG
				dlog (DEBUG1, "Checking Version %s against %s", buf, viridetails->recvmsg);
#endif
				rc = pcre_exec(viridetails->pattern, viridetails->patternextra, buf, strlen(buf), 0, 0, NULL, 0);
				if (rc < -1) {
					nlog (LOG_WARNING, "PatternMatch CTCP Version Failed: (%d)", rc);
				} else if (rc > -1) {					
					nlog (LOG_NOTICE, "Got positive CTCP %s for %s against %s", buf, viridetails->name, viridetails->recvmsg);
					gotpositive(u, viridetails, DET_CTCP);
					positive++;
					if (SecureServ.breakorcont != 0) {
						return 1;
					}
				}
			}
		} while ((node = list_next(viri, node)) != NULL);
	}
	return positive;
}

int ScanMsg(Client *u, char* buf, int chanmsg) 
{
	int positive = 0;
	lnode_t *node;
	virientry *viridetails;
	int rc;
	int doscan;

	SET_SEGV_LOCATION();
	node = list_first(viri);
	if (node) {
		do {
			doscan = 0;
			viridetails = lnode_get(node);
			rc = -1;
			if (viridetails->dettype == DET_MSG) {
				if ((chanmsg == 0) || (SecureServ.treatchanmsgaspm == 1)) {
					SecureServ.trigcounts[DET_MSG]++;
					doscan = 1;
				}
			} else if ((viridetails->dettype == DET_CHANMSG) && (chanmsg == 1)) {
				SecureServ.trigcounts[DET_CHANMSG]++;
				doscan = 1;
			}			
			
			if (doscan == 1) {
				rc = pcre_exec(viridetails->pattern, viridetails->patternextra, buf, strlen(buf), 0, 0, NULL, 0);
				if (rc < -1) {
					nlog (LOG_WARNING, "PatternMatch PrivateMessage Failed: (%d)", rc);
				} else if (rc > -1) {					
					gotpositive(u, viridetails, chanmsg ? DET_CHANMSG : DET_MSG);
					positive++;
					if (SecureServ.breakorcont != 0) {
						return 1;
					}
				}
			}	
		} while ((node = list_next(viri, node)) != NULL);
	}
	return positive;
}

int ScanChan(Client* u, Channel *c) 
{
	int positive = 0;
	lnode_t *node;
	virientry *viridetails;
	int rc;

	SET_SEGV_LOCATION();

	node = list_first(viri);
	if (node) {
		do {
			viridetails = lnode_get(node);
			if (viridetails->dettype == DET_CHAN) {
				SecureServ.trigcounts[DET_CHAN]++;
#ifdef DEBUG
				dlog (DEBUG1, "Checking Chan %s against %s", c->name, viridetails->recvmsg);
#endif
				rc = pcre_exec(viridetails->pattern, viridetails->patternextra, c->name, strlen(c->name), 0, 0, NULL, 0);
				if (rc < -1) {
					nlog (LOG_WARNING, "PatternMatch Chan Failed: (%d)", rc);
				} else if (rc > -1) {
					gotpositive(u, viridetails, DET_CHAN);
					positive++;
					if (SecureServ.breakorcont != 0) {
						return positive;
					}
				}
			}
		} while ((node = list_next(viri, node)) != NULL);
	}
	return positive;
}

void gotpositive(Client *u, virientry *ve, int type) 
{
	char chan[MAXCHANLEN];
	char buf[1400];
	char buf2[3];
	UserDetail *ud;
	int i;

	SET_SEGV_LOCATION();
	if (!u) /* User not found */
		return;
	/* Initial message is based on an assumption that the action determines the threat level */
	switch(ve->action) {
		case ACT_SVSJOIN:
			irc_prefmsg (ss_bot, u, "%s has detected that your client is an infected IRC client called %s", ss_bot->name, ve->name);
			break;
		case ACT_AKILL:
			irc_prefmsg (ss_bot, u, "%s has detected that your client is a Trojan or War Script called %s", ss_bot->name, ve->name);
			break;
		case ACT_KILL:
			irc_prefmsg (ss_bot, u, "%s has detected that your client is a Trojan or War Script called %s", ss_bot->name, ve->name);
			break;
		case ACT_WARN:
			irc_prefmsg (ss_bot, u, "%s has detected that you or your client is sending unsolicted messages to other users", ss_bot->name);
			break;
		case ACT_NOTHING:
			irc_prefmsg (ss_bot, u, "%s has detected that your client is a vulnerable script or client called %s", ss_bot->name, ve->name);
			break;
	} 		
	irc_prefmsg (ss_bot, u, ve->sendmsg);
	/* Do not generate a URL for local custom definitions since it will not exist*/
	if(!ve->iscustom)
		irc_prefmsg (ss_bot, u, "For More Information Please Visit http://secure.irc-chat.net/info.php?viri=%s", ve->name);
	ve->nofound++;
	SecureServ.actioncounts[type]++;
	switch (ve->action) {
		case ACT_SVSJOIN:
			if (SecureServ.dosvsjoin > 0) {
				if (SecureServ.helpcount > 0) {		
					ud = ns_malloc (sizeof(UserDetail));
					ud->type = USER_INFECTED;
					ud->data = (void *)ve;
					SetUserModValue (u, (void *)ud);
					irc_chanalert (ss_bot, "SVSJoining %s to %s for Virus %s", u->name, SecureServ.HelpChan, ve->name);
					if(ve->iscustom) {
						irc_globops (ss_bot, "SVSJoining %s for Virus %s", u->name, ve->name);
					} else {
						irc_globops (ss_bot, "SVSJoining %s for Virus %s (http://secure.irc-chat.net/info.php?viri=%s)", u->name, ve->name, ve->name);
					}
					if (!IsChannelMember(find_channel(SecureServ.HelpChan), u)) {
						irc_svsjoin (ss_bot, u, SecureServ.HelpChan);
					}
					nlog (LOG_NOTICE, "SVSJoining %s to %s for Virus %s", u->name, SecureServ.HelpChan, ve->name);
					ircsnprintf(chan, MAXCHANLEN, "@%s", SecureServ.HelpChan);
					if(ve->iscustom) {
						irc_chanprivmsg (ss_bot, chan, "%s is infected with %s.", u->name, ve->name);
					} else {
						irc_chanprivmsg (ss_bot, chan, "%s is infected with %s. More information at http://secure.irc-chat.net/info.php?viri=%s", u->name, ve->name, ve->name);
					}
					break;
				} else {
					irc_prefmsg (ss_bot, u, SecureServ.nohelp);
					irc_chanalert (ss_bot, "Akilling %s!%s@%s for Virus %s (No Helpers Logged in)", u->name, u->user->username, u->user->hostname, ve->name);
					if(ve->iscustom) {
						irc_globops (ss_bot, "Akilling %s for Virus %s (No Helpers Logged in)", u->name, ve->name);
					}
					else {
						irc_globops (ss_bot, "Akilling %s for Virus %s (No Helpers Logged in) (http://secure.irc-chat.net/info.php?viri=%s)", u->name, ve->name, ve->name);
					}
					irc_akill (ss_bot, u->user->hostname, u->user->username, SecureServ.akilltime, "SecureServ(SVSJOIN): %s", ve->name);
					nlog (LOG_NOTICE, "Akilling %s!%s@%s for Virus %s (No Helpers Logged in)", u->name, u->user->username, u->user->hostname, ve->name);
					break;
				}
			}
		case ACT_AKILL:
			if (SecureServ.doakill > 0) {
				irc_prefmsg (ss_bot, u, SecureServ.akillinfo);
				irc_chanalert (ss_bot, "Akilling %s!%s@%s for Virus %s", u->name, u->user->username, u->user->hostname, ve->name);
				if(ve->iscustom) {
					irc_akill (ss_bot, u->user->hostname, "*", SecureServ.akilltime, "Infected with: %s ", ve->name);
				} else {
					irc_akill (ss_bot, u->user->hostname, "*", SecureServ.akilltime, "Infected with: %s (See http://secure.irc-chat.net/info.php?viri=%s for more info)", ve->name, ve->name);
				}
				nlog (LOG_NOTICE, "Akilling %s!%s@%s for Virus %s", u->name, u->user->username, u->user->hostname, ve->name);
				break;
			}
		case ACT_KILL:
			irc_prefmsg (ss_bot, u, SecureServ.akillinfo);
			irc_chanalert (ss_bot, "Killing %s!%s@%s for Virus %s", u->name, u->user->username, u->user->hostname, ve->name);
			if(ve->iscustom) {
				irc_kill (ss_bot, u->name, "Infected with: %s ", ve->name);
			} else {
				irc_kill (ss_bot, u->name, "Infected with: %s (See http://secure.irc-chat.net/info.php?viri=%s for more info)", ve->name, ve->name);
			}
			nlog (LOG_NOTICE, "Killing %s!%s@%s for Virus %s", u->name, u->user->username, u->user->hostname, ve->name);
			break;
		case ACT_WARN:
			irc_chanalert (ss_bot, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken", u->name, ve->name);
			if(ve->iscustom) {
				irc_globops (ss_bot, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken ", u->name, ve->name);
			} else {
				irc_globops (ss_bot, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken (See http://secure.irc-chat.net/info.php?viri=%s for more info)", u->name, ve->name, ve->name);
			}
			if (SecureServ.helpcount > 0) {
				ircsnprintf(chan, MAXCHANLEN, "@%s", SecureServ.HelpChan);
				if(ve->iscustom) {
					irc_chanprivmsg (ss_bot, chan, "%s is infected with %s.", u->name, ve->name);
				} else {
					irc_chanprivmsg (ss_bot, chan, "%s is infected with %s. More information at http://secure.irc-chat.net/info.php?viri=%s", u->name, ve->name, ve->name);
				}
			}
			nlog (LOG_NOTICE, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken ", u->name, ve->name);
			break;
		case ACT_NOTHING:
			if (SecureServ.verbose) irc_chanalert (ss_bot, "SecureServ warned %s about %s Bot/Trojan/Virus", u->name, ve->name);
			nlog (LOG_NOTICE, "SecureServ warned %s about %s Bot/Trojan/Virus", u->name, ve->name);
			break;
	}
#ifndef WIN32
	/* send an update to secure.irc-chat.net */
	if ((SecureServ.sendtosock > 0) && (SecureServ.report == 1)) {
		ircsnprintf(buf2, 3, "%c%c", SecureServ.updateuname[0], SecureServ.updateuname[1]);
		ircsnprintf(buf, 1400, "%s\n%s\n%s\n%s\n%s\n%d\n", SecureServ.updateuname, crypt(SecureServ.updatepw, buf2), ve->name, u->user->hostname, "TODO", SecureServ.viriversion);
		i = sendto(SecureServ.sendtosock, buf, strlen(buf), 0,  (struct sockaddr *) &SecureServ.sendtohost, sizeof(SecureServ.sendtohost));
	}	
#endif
}
