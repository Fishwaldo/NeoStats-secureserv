/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2005 Adam Rutter, Justin Hammond, Mark Hetherington
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

#ifdef WIN32
#include "modconfigwin32.h"
#else
#include "modconfig.h"
#endif
                     
#include "neostats.h"
#include "SecureServ.h"

void datver(void *data, int status, char *ver, int versize);
void datdownload(void *data, int status, char *ver, int versize);
static int DownLoadDat(void);

static char ss_buf[SS_BUF_SIZE];

/* @brief This is the list of possible errors for dat file updates. 
**
*/
char *downloaderror(int errcode) {
	switch (errcode) {
		case -1:
				return "Invalid username or password.";
				break;
		case -2:
				return "Account disabled. Please contact admin@lists.neostats.net";
				break;
		case -3:
				return "Your copy of SecureServ is too old. Please upgrade";
				break;
		default:
				return "Unknown reason.";
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
	Client *u = (void *)data;
	
	SET_SEGV_LOCATION();
	/* check there was no error */
	if (status == NS_SUCCESS) {
		myversion = atoi(ver);
		if (myversion <= 0) {
			nlog (LOG_WARNING, "Permission Denied trying to check Dat file version: %s", downloaderror(myversion));
			irc_chanalert (ss_bot, "Permission Denied trying to check Dat file version: %s", downloaderror(myversion));
			if (u) irc_prefmsg (ss_bot, u, "Permission Denied trying to check Dat file version: %s", downloaderror(myversion));
			return;
		}			
		dlog (DEBUG1, "LocalDat Version %d, WebSite %d", SecureServ.datfileversion, myversion);
		if (myversion > SecureServ.datfileversion) {
			if (SecureServ.autoupgrade > 0 || u) {
				SecureServ.doUpdate = 1;
				DownLoadDat();
				if (u) irc_prefmsg (ss_bot, u, "A new Dat file version %d is being downloaded. Please Monitor the Services Channel", myversion);
			 } else
				irc_chanalert (ss_bot, "A new Dat file version %d is available. You should /msg %s update", myversion, ss_bot->name);
				/* no need to send a prefmsg to a nick here as in most cases, this is probabably triggered by a timer */
			 } else {
			irc_chanalert (ss_bot, "SecureServ is operating with the most recent Dat file. No update required.");
			if (u) irc_prefmsg (ss_bot, u, "SecureServ is operating with the most recent Dat file. No need required.");
			}
		return;
	} else {
		nlog (LOG_WARNING, "Virus definition check failed. %s", ver);
		irc_chanalert (ss_bot, "Virus definition check failed: %s", ver);
		if (u) irc_prefmsg (ss_bot, u, "Virus definition check failed. %s", ver);
		return;
	}
}
static int DownLoadDat() 
{
	SET_SEGV_LOCATION();
	/* dont keep trying to download !*/
	if (SecureServ.doUpdate == 1) {
#if 0
bugid: 154
		del_mod_timer("DownLoadNewDat");
#endif
		SecureServ.doUpdate = 2;
		os_memset (ss_buf, 0, SS_BUF_SIZE);
		ircsnprintf(ss_buf, SS_BUF_SIZE, "u=%s&p=%s", SecureServ.updateuname, SecureServ.updatepw);
		if (new_transfer("http://secure.irc-chat.net/defs.php", ss_buf, NS_MEMORY, "", NULL, datdownload) != NS_SUCCESS) {
			nlog (LOG_WARNING, "Definition download failed.");
			irc_chanalert (ss_bot, "Definition download failed. Check log files");
			return -1;
		}	

	} 
	return NS_SUCCESS;
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
		tmp = ns_malloc (datasize);
		strlcpy(tmp, data, datasize);
		tmp1 = tmp;
		i = atoi(strtok(tmp, "\n"));
		ns_free (tmp1);	
		if (i <= 0) {
			nlog (LOG_NORMAL, "Permission denied trying to download Dat file: %d", i);
			irc_chanalert (ss_bot, "Permission denied trying to download Dat file: %d", i);
			return;
		}	
		/* make a temp file and write the contents to it */
		strlcpy(tmpname, "viriXXXXXX", 32);
		os_write_temp_file( tmpname, data, datasize );
		/* rename the file to the datfile */
		os_rename(tmpname, VIRI_DAT_NAME);
		/* reload the dat file */
 		load_dat();
		nlog (LOG_NOTICE, "Dat file version %d has been downloaded and installed", SecureServ.datfileversion);
		irc_chanalert (ss_bot, "Dat file version %d has been downloaded and installed", SecureServ.datfileversion);
	} else {
		dlog (DEBUG1, "Virus definition download failed. %s", data);
		irc_chanalert (ss_bot, "Virus definition download failed. %s", data);
		return;
	}
}
	
void GotHTTPAddress(void *data, adns_answer *a) 
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
			nlog (LOG_NORMAL, "Got DNS for Update Server: %s", url);
			if ((SecureServ.updateuname[0] != 0) && SecureServ.updatepw[0] != 0) {
				AutoUpdate();
			} else {
				if (SecureServ.autoupgrade == 1) irc_chanalert (ss_bot, "No valid Username/Password configured for update checking. Aborting update check");
			}
		} else {
			irc_chanalert (ss_bot, "DNS error Checking for updates: %s", adns_strerror(ri));
		}
		ns_free (url);
	}
	if (a->nrrs < 1) {
		irc_chanalert (ss_bot, "DNS Error checking for updates");
	}
}

int AutoUpdate(void) 
{
	SET_SEGV_LOCATION();
	if ((SecureServ.autoupgrade > 0) && SecureServ.updateuname[0] != 0 && SecureServ.updatepw[0] != 0 ) {
		os_memset (ss_buf, 0, SS_BUF_SIZE);
		ircsnprintf(ss_buf, SS_BUF_SIZE, "u=%s&p=%s", SecureServ.updateuname, SecureServ.updatepw);
		if (new_transfer("http://secure.irc-chat.net/vers.php", ss_buf, NS_MEMORY, "", NULL, datver) != NS_SUCCESS) {
			nlog (LOG_WARNING, "Definition version check failed.");
			irc_chanalert (ss_bot, "Definition version check failed. Check log files");
		}	
	}
	return NS_SUCCESS;
}	

int ss_cmd_update(CmdParams *cmdparams)
{
	SET_SEGV_LOCATION();
	os_memset (ss_buf, 0, SS_BUF_SIZE);
	ircsnprintf(ss_buf, SS_BUF_SIZE, "u=%s&p=%s", SecureServ.updateuname, SecureServ.updatepw);
	if (new_transfer("http://secure.irc-chat.net/vers.php", ss_buf, NS_MEMORY, "", cmdparams->source, datver) != NS_SUCCESS) {
		irc_prefmsg (ss_bot, cmdparams->source, "Definition Download Failed. Check Log Files");
		nlog (LOG_WARNING, "Definition Download failed.");
		irc_chanalert (ss_bot, "Definition Download failed. Check log files");
		return NS_FAILURE;
	}	
	irc_prefmsg (ss_bot, cmdparams->source, "Requesting New Dat File.");
	irc_chanalert (ss_bot, "%s requested an update to the Dat file", cmdparams->source->name);
	return NS_SUCCESS;
}

int ss_cmd_set_autoupdate_cb(CmdParams *cmdparams, SET_REASON reason) 
{
	switch( reason )
	{
		case SET_VALIDATE:
			if( !SecureServ.updateuname[0] )
			{
				irc_prefmsg (ss_bot, cmdparams->source, "You can not enable AutoUpdate without setting the update user name");
				return NS_FAILURE;
			}
			if( !SecureServ.updatepw[0] )
			{
				irc_prefmsg (ss_bot, cmdparams->source, "You can not enable AutoUpdate without setting the update password");
				return NS_FAILURE;
			}
			break;
		case SET_CHANGE:
			if (SecureServ.autoupgrade == 1) 
			{
				AddTimer (TIMER_TYPE_INTERVAL, AutoUpdate, "AutoUpdate", SecureServ.autoupgradetime);
			} 
			else 
			{
				DelTimer ("AutoUpdate");
			}
			break;
		default:
			break;
	}
	return NS_SUCCESS;
}

int ss_cmd_set_autoupdatetime_cb(CmdParams *cmdparams, SET_REASON reason) 
{
	if( reason == SET_CHANGE )
	{
		if ((SecureServ.autoupgrade == 1) && (SecureServ.updateuname[0]) && (SecureServ.updatepw[0])) {
			SetTimerInterval("AutoUpdate", SecureServ.autoupgradetime);
		}
	}
	return NS_SUCCESS;
}
