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
** $Id: SecureServ_help.c,v 1.5 2003/07/13 12:50:17 fishwaldo Exp $
*/

#include "stats.h"

const char *ts_help[] = {
"\2SecureServ HELP\2",
"",
" This is a Network Service that scans the IRC client for",
" Insecure IRC clients, Trojans, and Virus's. For more Information",
" Please contact the Network Staff",
"",
"COMMANDS:",
"     LOGIN    LOGOUT",
"",
NULL
};

const char *ts_help_oper[] = {
"OPERTATOR COMMANDS:",
"     CHECKCHAN STATUS    SET    EXCLUDE",
"     CYCLE     LIST      UPDATE"
"",
NULL
};

const char *ts_help_login[] = {
"Usage: \2LOGIN <username> <password>\2",
"",
"This command allows AntiVirus users to Login to SecureServ",
"By Logging into SecureServ, it allows SecureServ to Notify you",
"and Direct any user infected with a Virus to the Help Channel",
"",
"SecureServ will monitor your availability, and if you set away, quit, or part",
"the Help Channel, it will automatically log you out"
"",
"The UserName and Password will be provided by the Network Administration",
NULL
};

const char *ts_help_logout[] = {
"Usage: \2LOGOUT\2",
"",
"This command logs you out of SecureServ's Antivirus Helper System.",
"You should issue this command if you are logged in, and are unable to",
"provide any Antivirus help at this time.",
NULL
};

const char *ts_help_checkchan[] = {
"Usage: \2CHECKCHAN <channel>\2",
"",
"This option will scan a Channel for Trojans. Use this if you suspect",
"a channel contains Trojans",
"",
NULL
};

const char *ts_help_cycle[] = {
"Usage: \2CYCLE\2",
"",
"This option will Force SecureServ to part the current channel it is checking",
"and move onto the next random channel",
"",
NULL
};

const char *ts_help_update[] = {
"Usage: \2UPDATE\2",
"",
"This option will Force SecureServ to check the Definitions file version and ",
"automatically update them to the latest version if required"
"",
"A valid Username and Password have to be set via the SET interface for this to function",
NULL
};

const char *ts_help_list[] = {
"Usage: \2LIST\2",
"",
"View Detailed information about what SecureServ's Defintion Database currently Contains",
"",
NULL
};


const char *ts_help_exclude[] = {
"Usage: \2EXCLUDE <LIST/ADD/DEL>\2",
"",
"This command lets you view or manipulate the exception list.",
"Exception lists are used to exclude users, channels, or servers from scanning",
"You should at least add a server entry for your services irc name, to stop",
"SecureServ from scanning Nickserv, Chanserv etc",
"The Options are:",
"    \2LIST\2         - This will list the current exceptions and the positions in the list",
"                       If you wish to remove a entry, you must exaime the list position first",
"    \2ADD <hostname> <2/1/0> <reason>\2",
"                     - This option will add a entry of <hostname> to the exception list",
"                       a Value of 2 after the hostname indicates a Channel Name (eg, #services)",
"                       a Value of 1 after the hostname indicates a Servername (eg, services.irc-chat.net)",
"                       a Value of 0 after the hostname indicates a hostname (eg, *.adsl.home.com)",
"                       The final portion of the string is a description of the exclusion for future reference",
"                       Wildcards such as * and ? may be used in the hostname portion",
"    \2DEL <NUM>\2    - This will delete entry numbered <NUM> in the list from the exclusions"
"",
NULL
};


const char *ts_help_status[] = {
"Usage: \2STATUS\2",
"",
"This command will provide you with the Current Status of SecureServ.",
"",
NULL
};









const char *ts_help_set[] = {
"Usage: \2SET <OPTIONS> <SETTING>\2",
"",
"This command will set various options relating to SecureServ.",
"You can view the settings by typing \2SET LIST\2",
"The Settings take effect straight away",
"The Options are:",
"    \2VERSION <on/off>\2       - This option turns CTCP Version Checking on and Off",
"    \2CHECKFIZZER <on/off>\2   - This turns on and off FizzerChecking. Disable if your network is not affected by Fizzer",
"    \2DOONJOIN <on/off>\2      - This turns on and off the Onjoin Virus Checking.",
"    \2AKILL <on/off>\2         - This option tells SecureServ to never issue a Akill on your Network. A warning message is sent to the operators instead",
"    \2AKILLTIME <seconds>\2	- Sets the time a AKILL will last for.",
"    \2DOJOIN <on/off>\2        - This option tells SecureServ to never issue a SVSJOIN when a virus is detected. The User is Akilled instead",
"    \2DOPRIVCHAN <on/off>\2	- This option tells SecureServ not to join Private Channels",
"    \2UPDATEINFO <username> <password>\2",
"                               - This Option Sets the Username and Password required for updating the SecureServ",
"                                 Definitions file. See the Readme file for more info",
"\2Advanced Settings\2          - These settings should not be changed unless you know the effects in full",
"    \2MULTICHECK <on/off>\2    - This makes SecureServ check all Patterns when a infected User is found.",
"                                 Please Read the Readme file for important Performance information",
"    \2VERBOSE <on/off>\2       - This option Turns on Verbose Mode. Prepare to be flooded!",
"    \2CYCLETIME <seconds>\2    - How Often Should SecureServ check new channels for infections.",
"                                 See the Readme file for recomended Settings",
"    \2AUTOUPDATE <on/off>\2    - Should SecureServ automatically update the Definitions file daily, if required?",
"    \2SAMPLETIME <seconds> <joins>\2",
"                               - This Sets the threshold for FloodChecking. Read the Readme File for more information",
"    \2NFCOUNT <number>\2       - This Sets the threshold for NickFloods. <number> is number of changes in 10 seconds.",
"    \2SIGNONMSG <message>\2    - This changes the message sent to users when they connect if Version Checking is enabled",
"    \2AKILLMSG <message>\2     - This changes the message sent to users when they are akilled",
"    \2NOHELPMSG <message>\2    - This changes the message sent to users when their are no helpers logged in",
"    \2HELPCHAN <channel>\2     - This changes the Channel that Virus's infected users are joined to if there are helpers logged in",
NULL
};

