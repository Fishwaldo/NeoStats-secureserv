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
#include <fnmatch.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#else
#include <unistd.h>
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
                     
#include "stats.h"
#include "dl.h"
#include "log.h"
#include "conf.h"
#include "SecureServ.h"

void datver(void *data, int status, char *ver, int versize);
void datdownload(void *data, int status, char *ver, int versize);
void GotHTTPAddress(char *data, adns_answer *a);
int AutoUpdate(void);
static int DownLoadDat(void);

static char ss_buf[SS_BUF_SIZE];

/* @brief This is the list of possible errors for dat file updates. 
**
*/
char *downloaderror(int errcode) {
	switch (errcode) {
		case -1:
				return "Invalid UserName/Password.";
				break;
		case -2:
				return "Account Disabled. Please contact admin@lists.neostats.net";
				break;
		case -3:
				return "Your copy of SecureServ is too old. Please Upgrade";
				break;
		default:
				return "Unknown Reason.";
				break;
	}
}

/* @brief this is the automatic dat file updater callback function. Checks whats on the website with 
** whats local, and if website is higher, either prompts for an upgrade, or does an automatic one :)
** It just compares version numbers of the dat file, and if they are different, starts a new download. 
*/

void datver(void *data, int status, char *ver, int versize) 
{
	int myversion;
	User *u = (void *)data;
	
	SET_SEGV_LOCATION();
	SET_SEGV_INMODULE("SecureServ");
	/* check there was no error */
	if (status == NS_SUCCESS) {
		myversion = atoi(ver);
		if (myversion <= 0) {
			nlog(LOG_NORMAL, LOG_MOD, "When Trying to Check Dat File Version, we got Permission Denied: %d", myversion);
			chanalert(s_SecureServ, "Permission Denied when trying to check Dat File Version: %s", downloaderror(myversion));
			if (u) prefmsg(u->nick, s_SecureServ, "Permission Denied when trying to check Dat File Version: %s", downloaderror(myversion));
			printf("%d\n", (unsigned int) atoi(ver));
			return;
		}			
		nlog(LOG_DEBUG1, LOG_MOD, "LocalDat Version %d, WebSite %d", SecureServ.viriversion, myversion);
		if (myversion > SecureServ.viriversion) {
			if (SecureServ.autoupgrade > 0 || u) {
				SecureServ.doUpdate = 1;
				DownLoadDat();
				if (u) prefmsg(u->nick, s_SecureServ, "A new Dat file version %d is being downloaded. Please Monitor the Services Channel", myversion);
			 } else
				chanalert(s_SecureServ, "A new DatFile Version %d is available. You should /msg %s update", myversion, s_SecureServ);
				/* no need to send a prefmsg to a nick here as in most cases, this is probabably triggered by a timer */
			 } else {
			chanalert(s_SecureServ, "SecureServ is operating with the most recent Dat file. No Need to update");
			if (u) prefmsg(u->nick, s_SecureServ, "SecureServ is operating with the most recent Dat file. No need to update");
			}
		return;
	} else {
		nlog(LOG_DEBUG1, LOG_MOD, "Virus Definition check Failed. %s", ver);
		chanalert(s_SecureServ, "Virus Definition Check failed: %s", ver);
		if (u) prefmsg(u->nick, s_SecureServ, "Virus Definition Check failed. %s", ver);
		return;
	}
	CLEAR_SEGV_INMODULE();
}
static int DownLoadDat() 
{
	char *tmpname;

	SET_SEGV_LOCATION();
	/* dont keep trying to download !*/
	if (SecureServ.doUpdate == 1) {
		del_mod_timer("DownLoadNewDat");
		SecureServ.doUpdate = 2;
		bzero(ss_buf, SS_BUF_SIZE);
		ircsnprintf(ss_buf, SS_BUF_SIZE, "u=%s&p=%s", SecureServ.updateuname, SecureServ.updatepw);
		tmpname = tempnam(NULL, NULL);
		if (new_transfer("http://secure.irc-chat.net/defs.php", ss_buf, NS_MEMORY, "", NULL, datdownload) != NS_SUCCESS) {
			nlog(LOG_WARNING, LOG_MOD, "Definition download failed.");
			chanalert(s_SecureServ, "Definition Download failed. Check log files");
			return -1;
		}	

	} 
	return 1;
}

/* @brief this downloads a dat file and loads the new version into memory if required 
*/
void datdownload(void *unuseddata, int status, char *data, int datasize) 
{
	char tmpname[32];
	char *tmp, *tmp1;
	int i;
	
	SET_SEGV_LOCATION();
	/* if this is an automatic download, KILL the timer */
	if (SecureServ.doUpdate == 2) {
		/* clear this flag */
		SecureServ.doUpdate = 0;
	}
	if (status == NS_SUCCESS) {

		/* check response code */
		tmp = malloc(datasize);
		strlcpy(tmp, data, datasize);
		tmp1 = tmp;
		i = atoi(strtok(tmp, "\n"));
		free(tmp1);	
		if (i <= 0) {
			nlog(LOG_NORMAL, LOG_MOD, "When Trying to Download Dat File, we got Permission Denied: %d", i);
			chanalert(s_SecureServ, "Permission Denied when trying to Download Dat File : %d", i);
			return;
		}			
		
	
		/* make a temp file and write the contents to it */
		strlcpy(tmpname, "viriXXXXXX", 32);
		i = mkstemp(tmpname);
		write(i, data, datasize);
		close(i);
		/* rename the file to the datfile */
		rename(tmpname, VIRI_DAT_NAME);
		/* reload the dat file */
		load_dat();
		nlog(LOG_NOTICE, LOG_MOD, "Successfully Downloaded DatFile Version %d", SecureServ.viriversion);
		chanalert(s_SecureServ, "DatFile Version %d has been downloaded and installed", SecureServ.viriversion);
	} else {
		nlog(LOG_DEBUG1, LOG_MOD, "Virus Definition Download Failed. %s", data);
		chanalert(s_SecureServ, "Virus Definition Download Failed. %s", data);
		return;
	}
	
}
	
void GotHTTPAddress(char *data, adns_answer *a) 
{
	char *url;
	int i, len, ri;

	SET_SEGV_LOCATION();
	adns_rr_info(a->type, 0, 0, &len, 0, 0);
	for(i = 0; i < a->nrrs;  i++) {
		ri = adns_rr_info(a->type, 0, 0, 0, a->rrs.bytes +i*len, &url);
		if (!ri) {
			/* ok, we got a valid answer, lets maybe kick of the update check.*/
			SecureServ.sendtohost.sin_addr.s_addr = inet_addr(url);
			SecureServ.sendtohost.sin_port = htons(2334);
			SecureServ.sendtohost.sin_family = AF_INET;
			SecureServ.sendtosock = socket(AF_INET, SOCK_DGRAM, 0);
			strlcpy(SecureServ.updateurl, url, SS_BUF_SIZE);
			nlog(LOG_NORMAL, LOG_MOD, "Got DNS for Update Server: %s", url);
			if ((SecureServ.updateuname[0] != 0) && SecureServ.updatepw[0] != 0) {
				AutoUpdate();
			} else {
				if (SecureServ.autoupgrade == 1) chanalert(s_SecureServ, "No Valid Username/Password configured for update Checking. Aborting Update Check");
			}
		} else {
			chanalert(s_SecureServ, "DNS error Checking for Updates: %s", adns_strerror(ri));
		}
		free(url);
	}
	if (a->nrrs < 1) {
		chanalert(s_SecureServ,  "DNS Error checking for Updates");
	}
}

int AutoUpdate(void) 
{
	SET_SEGV_LOCATION();
	if ((SecureServ.autoupgrade > 0) && SecureServ.updateuname[0] != 0 && SecureServ.updatepw[0] != 0 ) {
		bzero(ss_buf, SS_BUF_SIZE);
		ircsnprintf(ss_buf, SS_BUF_SIZE, "u=%s&p=%s", SecureServ.updateuname, SecureServ.updatepw);
		if (new_transfer("http://secure.irc-chat.net/vers.php", ss_buf, NS_MEMORY, "", NULL, datver) != NS_SUCCESS) {
			nlog(LOG_WARNING, LOG_MOD, "Definition version check failed.");
			chanalert(s_SecureServ, "Definition version check failed. Check log files");
		}	
	}
	return 0;
}	

int do_update(User *u, char **av, int ac)
{
	SET_SEGV_LOCATION();
	bzero(ss_buf, SS_BUF_SIZE);
	ircsnprintf(ss_buf, SS_BUF_SIZE, "u=%s&p=%s", SecureServ.updateuname, SecureServ.updatepw);
	if (new_transfer("http://secure.irc-chat.net/vers.php", ss_buf, NS_MEMORY, "", u, datver) != NS_SUCCESS) {
		prefmsg(u->nick, s_SecureServ, "Definition Download Failed. Check Log Files");
		nlog(LOG_WARNING, LOG_MOD, "Definition Download failed.");
		chanalert(s_SecureServ, "Definition Download failed. Check log files");
		return NS_FAILURE;
	}	
	prefmsg(u->nick, s_SecureServ, "Requesting New Dat File.");
	chanalert(s_SecureServ, "%s requested an update to the Dat file", u->nick);
	return 1;
}
