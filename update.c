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

#include "stats.h"
#include "dl.h"
#include "log.h"
#include "conf.h"
#include "SecureServ.h"
#include "http.h"

void datver(HTTP_Response *response);
void datdownload(HTTP_Response *response);
void GotHTTPAddress(char *data, adns_answer *a);
int AutoUpdate(void);

static char ss_buf[SS_BUF_SIZE];

/* @brief this is the automatic dat file updater callback function. Checks whats on the website with 
** whats local, and if website is higher, either prompts for an upgrade, or does an automatic one :)
**
** NOTE: we can't call http_request from this function as its NOT recursive 
*/

void datver(HTTP_Response *response) {
	int myversion;
	/* check there was no error */
	if ((response->iError > 0) && (!strcasecmp(response->szHCode, "200"))) {
		myversion = atoi(response->pData);
		if (myversion <= 0) {
			nlog(LOG_NORMAL, LOG_MOD, "When Trying to Check Dat File Version, we got Permission Denied: %d", myversion);
			chanalert(s_SecureServ, "Permission Denied when trying to check Dat File Version: %d", myversion);
			return;
		}			
		nlog(LOG_DEBUG1, LOG_MOD, "LocalDat Version %d, WebSite %d", SecureServ.viriversion, myversion);
		if (myversion > SecureServ.viriversion) {
			if (SecureServ.autoupgrade > 0) {
				SecureServ.doUpdate = 1;
				add_mod_timer("DownLoadDat", "DownLoadNewDat", __module_info.module_name, 1);
			 } else
				chanalert(s_SecureServ, "A new DatFile Version %d is available. You should /msg %s update", myversion, s_SecureServ);
		}
	} else {
		nlog(LOG_DEBUG1, LOG_MOD, "Virus Definition check Failed. %s", response->szHCode);
		return;
	}
}
void DownLoadDat() 
{
	/* dont keep trying to download !*/
	if (SecureServ.doUpdate == 1) {
		del_mod_timer("DownLoadNewDat");
		SecureServ.doUpdate = 2;
		ircsnprintf(ss_buf, SS_BUF_SIZE, "http://%s%s?u=%s&p=%s", SecureServ.updateurl, DATFILE, SecureServ.updateuname, SecureServ.updatepw);
		http_request(ss_buf, 2, HFLAG_NONE, datdownload);
	} 
	return;
}


/* @brief this downloads a dat file and loads the new version into memory if required 
*/

void datdownload(HTTP_Response *response) {
	char tmpname[32];
	char *tmp, *tmp1;
	int i;
	
	/* if this is an automatic download, KILL the timer */
	if (SecureServ.doUpdate == 2) {
		/* clear this flag */
		SecureServ.doUpdate = 0;
	}
	if ((response->iError > 0) && (!strcasecmp(response->szHCode, "200"))) {

		/* check response code */
		tmp = malloc(response->lSize);
		strlcpy(tmp, response->pData, response->lSize);
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
		write(i, response->pData, response->lSize);
		close(i);
		/* rename the file to the datfile */
		rename(tmpname, VIRI_DAT_NAME);
		/* reload the dat file */
		load_dat();
		nlog(LOG_NOTICE, LOG_MOD, "Successfully Downloaded DatFile Version %d", SecureServ.viriversion);
		chanalert(s_SecureServ, "DatFile Version %d has been downloaded and installed", SecureServ.viriversion);
	} else {
		nlog(LOG_DEBUG1, LOG_MOD, "Virus Definition Download Failed. %s", response->szHCode);
		chanalert(s_SecureServ, "Virus Definition Download Failed. %s", response->szHCode);
		return;
	}
	
}
	
void GotHTTPAddress(char *data, adns_answer *a) 
{
	char *url;
	int i, len, ri;

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
				ircsnprintf(ss_buf, SS_BUF_SIZE, "http://%s%s?u=%s&p=%s", url, DATFILEVER, SecureServ.updateuname, SecureServ.updatepw);
				http_request(ss_buf, 2, HFLAG_NONE, datver); 
				/* add a timer for autoupdate. If its disabled, doesn't do anything anyway */
				add_mod_timer("AutoUpdate", "AutoUpdateDat", __module_info.module_name, 86400);
			} else {
				if (SecureServ.verbose) {
					chanalert(s_SecureServ, "No Valid Username/Password configured for update Checking. Aborting Update Check");
				}
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
	if ((SecureServ.autoupgrade > 0) && SecureServ.updateuname[0] != 0 && SecureServ.updatepw[0] != 0 ) {
		ircsnprintf(ss_buf, SS_BUF_SIZE, "http://%s%s?u=%s&p=%s", SecureServ.updateurl, DATFILEVER, SecureServ.updateuname, SecureServ.updatepw);
		http_request(ss_buf, 2, HFLAG_NONE, datver); 
	}
	return 0;
}	

int do_update(User *u, char **av, int ac)
{
	if (UserLevel(u) < NS_ULEVEL_ADMIN) {
		prefmsg(u->nick, s_SecureServ, "Permission Denied");
		chanalert(s_SecureServ, "%s tried to update, but Permission was denied", u->nick);
		return -1;
	}
	ircsnprintf(ss_buf, SS_BUF_SIZE, "http://%s%s?u=%s&p=%s", SecureServ.updateurl, DATFILE, SecureServ.updateuname, SecureServ.updatepw);
	http_request(ss_buf, 2, HFLAG_NONE, datdownload);
	prefmsg(u->nick, s_SecureServ, "Requesting New Dat File. Please Monitor the Services Channel for Success/Failure");
	chanalert(s_SecureServ, "%s requested an update to the Dat file", u->nick);
	return 1;
}

