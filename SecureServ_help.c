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

const char *ts_help_helper[] = {
"HELPER COMMANDS:",
"     ASSIST",
"",
NULL
};

const char *ts_help_oper[] = {
"OPERTATOR COMMANDS:",
"     CHECKCHAN STATUS    SET     EXCLUDE",
"     CYCLE     LIST      UPDATE  BOTS",
"     MONCHAN   HELPERS",
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
const char *ts_help_monchan[] = {
"Usage: \2MONCHAN <LIST/ADD/DEL>\2",
"",
"This command lets your assign a bot to stay in Specific channels",
"to monitor for PrivateMessage type virus's",
"You must specify a Bot to use with /msg SecureServ set monbot <nick>",
"See /msg SecureServ help set for more info",
"The Options are:",
"    \2LIST\2         - This will list the current channels that will be monitored",
"                       Should a channel listed here not exist when you start SecureServ",
"                       it will be automatically deleted from the channel",
"    \2ADD <channel>\2 - This option will add a entry of <channel> to the list of Monitored channels",
"                       The channel has to exist when you use this command.",
"    \2DEL <channel>\2 - This will delete <channel> from the monitored channels list"
"",
NULL
};

const char *ts_help_bots[] = {
"Usage: \2BOTS <LIST/ADD/DEL>\2",
"",
"This command lets you view or manipulate the random Bot list.",
"Bots from this list are randomly selected to join channels, scanning for Onjoin based virus's",
"You should try to use names/hosts etc that look real, and if possible, should change this list often.",
"The Options are:",
"    \2LIST\2         - This will list the current bots and the positions in the list",
"                       If you wish to remove a entry, you must exaime the list position first",
"    \2ADD <nick> <ident> <host> <info>\2",
"                     - This option will add a entry of bot with the particular details to the bot list",
"    \2DEL <NUM>\2    - This will delete entry numbered <NUM> in the list from the exclusions"
"",
NULL
};

const char *ts_help_helpers[] = {
"Usage: \2HELPERS <LIST/ADD/DEL>\2",
"",
"This command lets you view or manipulate the helpers list.",
"Helpers can be normal users that maintain your AntiVirus channels and can help users with Virus Infections",
"Helpers have special privledges that allow them to kill infected users, or release users after the user has been identified as a infected user",
"The Options are:",
"    \2LIST\2         - This will list the current helpers and the positions in the list",
"                       If a nickname is listed after the login name, it means that that nick is logged in",
"    \2ADD <login> <pass>\2",
"                     - This option will add a helper entry with the login name and password provided",
"    \2DEL <login>\2  - This will delete a helper entry with the login name from the helpers list."
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

const char *ts_help_assist[] = {
"Usage: \2ASSIST <RELEASE/KILL> <target>\2",
"",
"This command allows Helpers to Release or akill infected users that have been joined to the",
"help channel",
"This command is only available to Helpers that are logged in",
"     \2RELEASE\2     - Releases SecureServ's Hold on <target> so they may rejoin channel",
"     \2KILL\2        - Kills <target> from the network. Should only be used when the helper",
"                       is unable to clean/help the <target> user",
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
"    \2FLOODPROT <on/off>\2     - Enable Channel Flood Protection Scanning.",
"    \2CHANKEY <key>\2          - When Flood Protection for a Channel is active, this is the key we will use to lock the channel",
"    \2CHANLOCKTIME <seconds>\2 - How long (Aprox) do we lock a Channel for. Time in seconds",
"    \2UPDATEINFO <username> <password>\2",
"                               - This Option Sets the Username and Password required for updating the SecureServ",
"                                 Definitions file. See the Readme file for more info",
"    \2MONBOT <bot>\2           - Assign <bot> (from /msg SecureServ bots list) to be used for Channel Monitoring",
"\2Advanced Settings\2          - These settings should not be changed unless you know the effects in full",
"    \2REPORT <on/off>\2        - Enable Reporting to Secure.irc-chat.net of infected users.",
"    \2AUTOSIGNOUT <on/off>\2   - Automatically sign out helpers if they set away.",
"    \2JOINHELPCHAN <on/off>\2	- Should SecureServ join the help channel when there is at least one helper logged in",
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

