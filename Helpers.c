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
** $Id: Helpers.c,v 1.2 2003/08/07 15:02:19 fishwaldo Exp $
*/


#include <stdio.h>
#include <fnmatch.h>
#include "dl.h"
#include "log.h"
#include "stats.h"
#include "conf.h"
#include "SecureServ.h"

hash_t *helperhash;

struct hlpstr {
	char nick[MAXNICK];
	char pass[MAXNICK];
	User *u;
};

typedef struct hlpstr SSHelpers;

void Helpers_init() {
	char **data, path[255], *tmp;
	SSHelpers *helper;
	int i;
	hnode_t *node;
	
	helperhash = hash_create(-1, 0, 0);
	if (GetDir("Helper", &data) > 0) {
		for (i = 0; data[i] != NULL; i++) {	
			helper = malloc(sizeof(SSHelpers));
			strncpy(helper->nick, data[i], MAXNICK);
			snprintf(path, 255, "Helper/%s/Pass", helper->nick);
			if (GetConf((void *)&tmp, CFGSTR, path) <= 0) {
				free(helper);
				continue;
			} else {
				strncpy(helper->pass, tmp, MAXNICK);
				free(tmp);
			}
			helper->u = NULL;
			node = hnode_create(helper);
			hash_insert(helperhash, node, helper->nick);
		}
	}	

}

int Helpers_add(User *u, char **av, int ac) {
	SSHelpers *helper;
	hnode_t *node;
	char path[255];
	
	if (ac < 5) {
		prefmsg(u->nick, s_SecureServ, "Invalid Syntax. /msg SecureServ help helpers");
		return -1;
	}
	if (hash_lookup(helperhash, av[3])) {
		prefmsg(u->nick, s_SecureServ, "A Helper with login %s already exists", av[3]);
		return -1;
	}


	helper = malloc(sizeof(SSHelpers));
	snprintf(helper->nick, MAXNICK, "%s", av[3]);
	snprintf(helper->pass, MAXNICK, "%s", av[4]);
	helper->u = NULL;
	node = hnode_create(helper);
 	hash_insert(helperhash, node, helper->nick);

	/* ok, now save the helper */
	snprintf(path, 255, "Helper/%s/Pass", helper->nick);
	SetConf((void *)helper->pass, CFGSTR, path);

	prefmsg(u->nick, s_SecureServ, "Successfully added Helper %s with Password %s to Helpers List", helper->nick, helper->pass);
	return 1;
}

int Helpers_del(User *u, char *nick) {
	hnode_t *node;
	char path[255];
	
	node = hash_lookup(helperhash, nick);
	if (node) {
		hash_delete(helperhash, node);
		free(hnode_get(node));
		hnode_destroy(node);
		snprintf(path, MAXNICK, "Helper/%s", nick);
		DelConf(path);
		prefmsg(u->nick, s_SecureServ, "Deleted %s from Helpers List", nick);
	} else {
		prefmsg(u->nick, s_SecureServ, "Error, Could not find %s in helpers list. /msg %s helpers list", s_SecureServ);
	}
	return 1;
	
}

int Helpers_list(User *u) {
	hscan_t hlps;
	hnode_t *node;
	SSHelpers *helper;
	
	prefmsg(u->nick, s_SecureServ, "Helpers List (%d):", hash_count(helperhash));
	hash_scan_begin(&hlps, helperhash);
	while ((node = hash_scan_next(&hlps)) != NULL) {
		helper = hnode_get(node);
		prefmsg(u->nick, s_SecureServ, "%s (%s)", helper->nick, helper->u ? helper->u->nick : "Not Logged In");
	}
	prefmsg(u->nick, s_SecureServ, "End of List.");	
	return -1;
}

int Helpers_chpass(User *u, char **av, int ac) {

	return 1;

}

int Helpers_Login(User *u, char **av, int ac) {
	hnode_t *node;
	SSHelpers *helper;
	node = hash_lookup(helperhash, av[2]);
	if (node) {
		helper = hnode_get(node);
		if (!strcasecmp(helper->pass, av[3])) {
			helper->u = u;
			prefmsg(u->nick, s_SecureServ, "Login Successfull");
			if (IsChanMember(findchan(SecureServ.HelpChan), u) != 1) {
				prefmsg(u->nick, s_SecureServ, "Joining you to the Help Channel");
				ssvsjoin_cmd(u->nick, SecureServ.HelpChan);
			}
			chanalert(s_SecureServ, "%s Successfully Logged in", u->nick);
			SecureServ.helpcount++;
			return 1;
		}
		prefmsg(u->nick, s_SecureServ, "Login Failed");
		chanalert(s_SecureServ, "%s tried to login with %s, but got the pass wrong (%s)", u->nick, av[2], av[3]);
		return -1;
	} 
	prefmsg(u->nick, s_SecureServ, "Login Failed");
	chanalert(s_SecureServ, "%s tried to login with %s but that account does not exist", u->nick, av[2]);
	return -1;
}
int Helpers_Logout(User *u) {
	hscan_t hlps;
	hnode_t *node;
	SSHelpers *helper;
	
	hash_scan_begin(&hlps, helperhash);
	while ((node = hash_scan_next(&hlps)) != NULL) {
		helper = hnode_get(node);
		if (helper->u == u) {
			prefmsg(u->nick, s_SecureServ, "You have been logged out of %s", helper->nick);
			chanalert(u->nick, "%s logged out of account %s", u->nick, helper->nick);
			helper->u = NULL;
			SecureServ.helpcount--;
			if (SecureServ.helpcount < 0) {
				SecureServ.helpcount = 0;
			}
			return 1;
		}			
	}
	prefmsg(u->nick, s_SecureServ, "Error, You do not appear to be logged in");
	return -1;
}

