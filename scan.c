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
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#else
#include <unistd.h>
#endif

#include "stats.h"
#include "dl.h"
#include "log.h"
#include "SecureServ.h"

#define MAX_VIRI	-1

static void gotpositive(User *u, virientry *ve, int type);

/* this is the list of viri */
static list_t *viri;

void InitScanner(void)
{
	SET_SEGV_LOCATION();
	/* init the virus lists */
	viri = list_create(MAX_VIRI);
	load_dat();
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
				nlog(LOG_DEBUG1, LOG_MOD, "Deleting %s out of List", viridet->name);
				if (viridet->pattern) {
					free(viridet->pattern);
				}
				if (viridet->patternextra) {
					free(viridet->patternextra);
				}
				free(viridet);
			}
			node = list_next(viri, node));
		} 
		list_destroy_nodes(viri);
	}
	
	for (rc = 0; rc < MAX_PATTERN_TYPES; rc++) {
		SecureServ.definitions[rc] = 0;
	}	

	/* first, add the dat for Fizzer (even if its not enabled!) */
	viridet = malloc(sizeof(virientry));
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
	nlog(LOG_DEBUG1, LOG_MOD, "loaded %s (Detection %d, with %s, send %s and do %d", viridet->name, viridet->dettype, viridet->recvmsg, viridet->sendmsg, viridet->action);
	
	for(i = 0; i < NUM_DAT_FILES; i++)
	{
		fp = fopen(DatFiles[i], "r");
		if (!fp) {
			if(i)
			{
				/* We do not really care if the custom file is not present so don't report it except in debug */
				/* as the comment says, we don't care about custom.dat, so don't fool users into thinking SecureSer is disabled by telling them it is! */
				nlog(LOG_DEBUG1, LOG_MOD, "No custom.dat file found.");
			}
			else
			{
				/* we *HAVE* to have a viri.dat file. Otherwise, no go */
				nlog(LOG_WARNING, LOG_MOD, "TS: Error, No viri.dat file found. %s is disabled", s_SecureServ);
				chanalert(s_SecureServ, "Error not viri.dat file found, %s is disabled", s_SecureServ);
			}
			return;
		} else {
			re = pcre_compile("^([a-zA-Z0-9]*) ([0-9]*) ([0-9]*) ([0-9]*) \"(.*)\" \"(.*)\" ([0-9]*).*" , 0, &error, &errofset, NULL);
			if (re == NULL) {
				nlog(LOG_CRITICAL, LOG_MOD, "PCRE_COMPILE of dat file format failed bigtime! %s at %d", error, errofset);		
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
				viridet = malloc(sizeof(virientry));
				rc = pcre_exec(re, NULL, buf, strlen(buf), 0, 0, ovector, 24);
				if (rc <= 0) {
					nlog(LOG_WARNING, LOG_MOD, "PCRE_EXEC didn't have enough space! %d", rc);
					nlog(LOG_WARNING, LOG_MOD, "Load Was: %s", buf);
					free(viridet);
					continue;
				} else if (rc != 8) {
					nlog(LOG_WARNING, LOG_MOD, "Didn't get required number of Subs (%d)", rc);
					free(viridet);
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
					nlog(LOG_WARNING, LOG_MOD, "Regular Expression Compile of %s Failed: %s at %d", viridet->name, error, errofset);
					free(subs);
					free(viridet);
					continue;
				}	
				viridet->iscustom=i;
				viridet->patternextra = pcre_study(viridet->pattern, 0, &error);
				if (error != NULL) {
					nlog(LOG_WARNING, LOG_MOD, "Regular Expression Study for %s failed: %s", viridet->name, error);
					/* don't exit */
				}
				SecureServ.definitions[viridet->dettype]++;
				node = lnode_create(viridet);
				list_prepend(viri, node);
				nlog(LOG_DEBUG1, LOG_MOD, "loaded %s (Detection %d, with %s, send %s and do %d", viridet->name, viridet->dettype, viridet->recvmsg, viridet->sendmsg, viridet->action);
				free(subs);
			}
			free(re);
			fclose(fp);
		}
	}	
}

int do_reload(User *u, char **av, int ac)
{
	SET_SEGV_LOCATION();
	if (UserLevel(u) < NS_ULEVEL_OPER) {
		prefmsg(u->nick, s_SecureServ, "Permission Denied");
		chanalert(s_SecureServ, "%s tried to reload, but Permission was denied", u->nick);
		return -1;
	}			
	prefmsg(u->nick, s_SecureServ, "Reloading virus definition files");
    chanalert(s_SecureServ, "Reloading virus definition files at request of %s", u->nick);
	load_dat();
	return 1;
}

int do_list(User *u, char **av, int ac) 
{
	lnode_t *node;
	virientry *ve;
	char type[LOCALBUFSIZE];
	char action[LOCALBUFSIZE];
	int i;

	SET_SEGV_LOCATION();
	if (UserLevel(u) < NS_ULEVEL_OPER) {
		prefmsg(u->nick, s_SecureServ, "Permission Denied");
		chanalert(s_SecureServ, "%s tried to list, but Permission was denied", u->nick);
		return -1;
	}			

	i = 0;
	node = list_first(viri);
	if (node) {
		prefmsg(u->nick, s_SecureServ, "Virus List:");
		prefmsg(u->nick, s_SecureServ, "===========");
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
				case ACT_WARN:
					strlcpy(action, "OpersWarn", LOCALBUFSIZE);
					break;
				default:
					strlcpy(action, "ClientWarn", LOCALBUFSIZE);
			}
			prefmsg(u->nick, s_SecureServ, "%d) Virus: %s. Detection: %s. Action: %s Hits: %d", i, ve->name, type, action, ve->nofound);
		} while ((node = list_next(viri, node)) != NULL);
		prefmsg(u->nick, s_SecureServ, "End of List.");
	} else {
		prefmsg(u->nick, s_SecureServ, "No definitions found.");
	}
	return 1;
}

int ScanFizzer(User *u) 
{
	lnode_t *node;
	virientry *viridetails;
	char username[10];
	char *s1, *s2, *user;

	SET_SEGV_LOCATION();
							
	/* fizzer requires realname info, which we don't store yet. */
	user = malloc(MAXREALNAME);
	strlcpy(user, u->realname, MAXREALNAME); 
	s1 = strtok(user, " ");
	s2 = strtok(NULL, "");
	ircsnprintf(username, 10, "%s%s%s", u->username[0] == '~' ? "~" : "",  s2, s1);
	free(user);
	nlog(LOG_DEBUG2, LOG_MOD, "Fizzer RealName Check %s -> %s", username, u->username);
	SecureServ.trigcounts[DET_BUILTIN]++;
	if (!strcmp(username, u->username)) {
		nlog(LOG_NOTICE, LOG_MOD, "Fizzer Bot Detected: %s (%s -> %s)", u->nick, u->username, u->realname);
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

int ScanUser(User *u, unsigned flags) 
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
				nlog(LOG_DEBUG1, LOG_MOD, "Checking Nick %s against %s", u->nick, viridetails->recvmsg);
				rc = pcre_exec(viridetails->pattern, viridetails->patternextra, u->nick, strlen(u->nick), 0, 0, NULL, 0);
				if (rc < -1) {
					nlog(LOG_WARNING, LOG_MOD, "PatternMatch Nick Failed: (%d)", rc);
				} else if (rc > -1) {					
					nlog(LOG_NOTICE, LOG_MOD, "Got positive nick %s for %s against %s", u->nick, viridetails->name, viridetails->recvmsg);
					gotpositive(u, viridetails, DET_NICK);
					positive++;
					if (SecureServ.breakorcont != 0) {
						return 1;
					}
				}
			} else if ((flags & SCAN_IDENT) && (viridetails->dettype == DET_IDENT)) {
				SecureServ.trigcounts[DET_IDENT]++;
				nlog(LOG_DEBUG1, LOG_MOD, "Checking ident %s against %s", u->username, viridetails->recvmsg);
				rc = pcre_exec(viridetails->pattern, viridetails->patternextra, u->username, strlen(u->username), 0, 0, NULL, 0);
				if (rc < -1) {
					nlog(LOG_WARNING, LOG_MOD, "PatternMatch UserName Failed: (%d)", rc);
				} else if (rc > -1) {					
					nlog(LOG_NOTICE, LOG_MOD, "Got positive ident %s for %s against %s", u->username, viridetails->name, viridetails->recvmsg);
					gotpositive(u, viridetails, DET_IDENT);
					positive++;
					if (SecureServ.breakorcont != 0) {
						return 1;
					}
				}
			} else if ((flags & SCAN_REALNAME) && (viridetails->dettype == DET_REALNAME)) {
				SecureServ.trigcounts[DET_REALNAME]++;
				nlog(LOG_DEBUG1, LOG_MOD, "Checking Realname %s against %s", u->realname, viridetails->recvmsg);
				rc = pcre_exec(viridetails->pattern, viridetails->patternextra, u->realname, strlen(u->realname), 0, 0, NULL, 0);
				if (rc < -1) {
					nlog(LOG_WARNING, LOG_MOD, "PatternMatch RealName Failed: (%d)", rc);
				} else if (rc > -1) {					
					nlog(LOG_NOTICE, LOG_MOD, "Got positive realname %s for %s against %s", u->realname, viridetails->name, viridetails->recvmsg);
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

int ScanCTCP(User *u, char* buf) 
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
				nlog(LOG_DEBUG1, LOG_MOD, "Checking Version %s against %s", buf, viridetails->recvmsg);
				rc = pcre_exec(viridetails->pattern, viridetails->patternextra, buf, strlen(buf), 0, 0, NULL, 0);
				if (rc < -1) {
					nlog(LOG_WARNING, LOG_MOD, "PatternMatch CTCP Version Failed: (%d)", rc);
				} else if (rc > -1) {					
					nlog(LOG_NOTICE, LOG_MOD, "Got positive CTCP %s for %s against %s", buf, viridetails->name, viridetails->recvmsg);
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

int ScanMsg(User *u, char* buf) 
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
			if (((viridetails->dettype == DET_MSG) || (viridetails->dettype > 20))) {
				SecureServ.trigcounts[DET_MSG]++;
				nlog(LOG_DEBUG1, LOG_MOD, "SecureServ: Checking Message %s (%s) against %s", buf, u->nick, viridetails->recvmsg);
				rc = pcre_exec(viridetails->pattern, viridetails->patternextra, buf, strlen(buf), 0, 0, NULL, 0);
				if (rc < -1) {
					nlog(LOG_WARNING, LOG_MOD, "PatternMatch PrivateMessage Failed: (%d)", rc);
				} else if (rc > -1) {					
					gotpositive(u, viridetails, DET_MSG);
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

int ScanChan(User* u, Chans *c) 
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
				nlog(LOG_DEBUG1, LOG_MOD, "Checking Chan %s against %s", c->name, viridetails->recvmsg);
				rc = pcre_exec(viridetails->pattern, viridetails->patternextra, c->name, strlen(c->name), 0, 0, NULL, 0);
				if (rc < -1) {
					nlog(LOG_WARNING, LOG_MOD, "PatternMatch Chan Failed: (%d)", rc);
				} else if (rc > -1) {
					gotpositive(u, viridetails, DET_CHAN);
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

void gotpositive(User *u, virientry *ve, int type) 
{
	char chan[CHANLEN];
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
			prefmsg(u->nick, s_SecureServ, "%s has detected that your client is an infected IRC client called %s", s_SecureServ, ve->name);
			break;
		case ACT_AKILL:
			prefmsg(u->nick, s_SecureServ, "%s has detected that your client is a Trojan or War Script called %s", s_SecureServ, ve->name);
			break;
		case ACT_WARN:
			prefmsg(u->nick, s_SecureServ, "%s has detected that you or your client is sending unsolicted messages to other users", s_SecureServ);
			break;
		case ACT_NOTHING:
			prefmsg(u->nick, s_SecureServ, "%s has detected that your client is a vulnerable script or client called %s", s_SecureServ, ve->name);
			break;
	} 		
	prefmsg(u->nick, s_SecureServ, ve->sendmsg);
	/* Do not generate a URL for local custom definitions since it will not exist*/
	if(!ve->iscustom)
		prefmsg(u->nick, s_SecureServ, "For More Information Please Visit http://secure.irc-chat.net/info.php?viri=%s", ve->name);
	ve->nofound++;
	SecureServ.actioncounts[type]++;
	switch (ve->action) {
		case ACT_SVSJOIN:
			if (SecureServ.dosvsjoin > 0) {
				if (SecureServ.helpcount > 0) {		
					ud = malloc(sizeof(UserDetail));
					ud->type = USER_INFECTED;
					ud->data = (void *)ve;
					u->moddata[SecureServ.modnum] = ud;					
					chanalert(s_SecureServ, "SVSJoining %s to %s for Virus %s", u->nick, SecureServ.HelpChan, ve->name);
					if(ve->iscustom) {
						globops(s_SecureServ, "SVSJoining %s for Virus %s", u->nick, ve->name);
					} else {
						globops(s_SecureServ, "SVSJoining %s for Virus %s (http://secure.irc-chat.net/info.php?viri=%s)", u->nick, ve->name, ve->name);
					}
					if (!IsChanMember(findchan(SecureServ.HelpChan), u)) {
#if defined(GOTSVSJOIN)
						ssvsjoin_cmd(u->nick, SecureServ.HelpChan);
#else 
						sinvite_cmd(s_SecureServ, u->nick, SecureServ.HelpChan);
#endif
					}
					nlog(LOG_NOTICE, LOG_MOD, "SVSJoining %s to %s for Virus %s", u->nick, SecureServ.HelpChan, ve->name);
					ircsnprintf(chan, CHANLEN, "@%s", SecureServ.HelpChan);
					if(ve->iscustom) {
						prefmsg(chan, s_SecureServ, "%s is infected with %s.", u->nick, ve->name);
					} else {
						prefmsg(chan, s_SecureServ, "%s is infected with %s. More information at http://secure.irc-chat.net/info.php?viri=%s", u->nick, ve->name, ve->name);
					}
#if !defined(GOTSVSJOIN)
					prefmsg(chan, s_SecureServ, "%s was invited to the Channel", u->nick);
#endif
					break;
				} else {
					prefmsg(u->nick, s_SecureServ, SecureServ.nohelp);
					chanalert(s_SecureServ, "Akilling %s!%s@%s for Virus %s (No Helpers Logged in)", u->nick, u->username, u->hostname, ve->name);
					if(ve->iscustom) {
						globops(s_SecureServ, "Akilling %s for Virus %s (No Helpers Logged in)", u->nick, ve->name);
					}
					else {
						globops(s_SecureServ, "Akilling %s for Virus %s (No Helpers Logged in) (http://secure.irc-chat.net/info.php?viri=%s)", u->nick, ve->name, ve->name);
					}
					sakill_cmd(u->hostname, u->username, s_SecureServ, SecureServ.akilltime, "SecureServ(SVSJOIN): %s", ve->name);
					nlog(LOG_NOTICE, LOG_MOD, "Akilling %s!%s@%s for Virus %s (No Helpers Logged in)", u->nick, u->username, u->hostname, ve->name);
					break;
				}
			}
		case ACT_AKILL:
			if (SecureServ.doakill > 0) {
				prefmsg(u->nick, s_SecureServ, SecureServ.akillinfo);
				chanalert(s_SecureServ, "Akilling %s!%s@%s for Virus %s", u->nick, u->username, u->hostname, ve->name);
				if(ve->iscustom) {
					sakill_cmd(u->hostname, "*", s_SecureServ, SecureServ.akilltime, "Infected with: %s ", ve->name);
				} else {
					sakill_cmd(u->hostname, "*", s_SecureServ, SecureServ.akilltime, "Infected with: %s (See http://secure.irc-chat.net/info.php?viri=%s for more info)", ve->name, ve->name);
				}
				nlog(LOG_NOTICE, LOG_MOD, "Akilling %s!%s@%s for Virus %s", u->nick, u->username, u->hostname, ve->name);
				break;
			}
		case ACT_WARN:
			chanalert(s_SecureServ, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken", u->nick, ve->name);
			if(ve->iscustom) {
				globops(s_SecureServ, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken ", u->nick, ve->name);
			} else {
				globops(s_SecureServ, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken (See http://secure.irc-chat.net/info.php?viri=%s for more info)", u->nick, ve->name, ve->name);
			}
			if (SecureServ.helpcount > 0) {
				ircsnprintf(chan, CHANLEN, "@%s", SecureServ.HelpChan);
				if(ve->iscustom) {
					prefmsg(chan, s_SecureServ, "%s is infected with %s.", u->nick, ve->name);
				} else {
					prefmsg(chan, s_SecureServ, "%s is infected with %s. More information at http://secure.irc-chat.net/info.php?viri=%s", u->nick, ve->name, ve->name);
				}
			}
			nlog(LOG_NOTICE, LOG_MOD, "Warning, %s is Infected with %s Trojan/Virus. No Action Taken ", u->nick, ve->name);
			break;
		case ACT_NOTHING:
			if (SecureServ.verbose) chanalert(s_SecureServ, "SecureServ warned %s about %s Bot/Trojan/Virus", u->nick, ve->name);
			nlog(LOG_NOTICE, LOG_MOD, "SecureServ warned %s about %s Bot/Trojan/Virus", u->nick, ve->name);
			break;
	}
	/* send an update to secure.irc-chat.net */
	if ((SecureServ.sendtosock > 0) && (SecureServ.report == 1)) {
		ircsnprintf(buf2, 3, "%c%c", SecureServ.updateuname[0], SecureServ.updateuname[1]);
		ircsnprintf(buf, 1400, "%s\n%s\n%s\n%s\n%s\n%d\n", SecureServ.updateuname, crypt(SecureServ.updatepw, buf2), ve->name, u->hostname, __module_info.module_version, SecureServ.viriversion);
		i = sendto(SecureServ.sendtosock, buf, strlen(buf), 0,  (struct sockaddr *) &SecureServ.sendtohost, sizeof(SecureServ.sendtohost));
	}	
}
