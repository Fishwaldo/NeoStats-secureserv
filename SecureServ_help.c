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
	"\2SecureServ\2 is a Network Service that scans the IRC",
	"client for Insecure IRC clients, Trojans, and Viruses.",
	"For more Information, please contact the Network Staff",
	"",
	"The following commands can be used with SecureServ",
	"",
	"    LOGIN      Login as a helper",
	"    LOGOUT     Logout as a helper",
	"    CHPASS     Change your Helper Password",
	NULL
};

const char *ts_help_helper[] = {
	"",
	"Additional commands for Helpers",
	"",
	"    ASSIST     Release/Akill infected user",
	NULL
};

const char *ts_help_oper[] = {
	"",
	"Additional commands for Operators",
	"",
	"    CHECKCHAN  Scan a Channel", 
	"    STATUS     Current Status of SecureServ",
	"    SET        Configure SecureServ",
	"    EXCLUDE    Exclude users/channels/servers from scans",
	"    CYCLE      Scan next channel",
	"    LIST       Current list of virus definitions",
	"    UPDATE     Download latest definitions",
	"    BOTS       Manage random Bot list",
	"    MONCHAN    Set channel monitor bot",
	"    HELPERS    Manage helper list",
	"    RELOAD     Reload virus defintions",
	NULL
};

const char *ts_help_on_help[] = {
	"",
	"To use a command, type",
	"    \2/msg SecureServ command\2",
	"For for more information on a command, type", 
	"    \2/msg SecureServ HELP command\2.",
	NULL
};

const char *ts_help_login[] = {
	"Syntax: \2LOGIN <username> <password>\2",
	"",
	"This command allows Antivirus users to login to SecureServ",
	"By Logging into SecureServ, it allows SecureServ to notify",
	"you and direct any user infected with a Virus to the Help",
	"Channel",
	"",
	"SecureServ will monitor your availability, and if you set",
	"away, quit, or part the Help Channel, it will"
	"automatically log you out",
	"",
	"The username and password will be provided by the",
	"Network Administration",
	NULL
};

const char *ts_help_logout[] = {
	"Syntax: \2LOGOUT\2",
	"",
	"This command logs you out of SecureServ's Antivirus Helper",
	"System. You should issue this command if you are logged in"
	"and are unable to provide any Antivirus help at this time.",
	NULL
};
const char *ts_help_chpass[] = {
	"Syntax: \2CHPASS <newpassword>\2",
	"",
	"This command changes your Helper Password.",
	"You must be logged into the SecureServ Helper System to use this command",
	NULL
};

const char *ts_help_checkchan[] = {
	"Syntax: \2CHECKCHAN <channel>\2",
	"",
	"This option will scan a channel for Trojans. Use this if",
	"you suspect a channel contains Trojans",
	NULL
};

const char *ts_help_cycle[] = {
	"Syntax: \2CYCLE\2",
	"",
	"This option will force SecureServ to part the current",
	"channel it is checking and move onto the next random",
	"channel",
	NULL
};

const char *ts_help_update[] = {
	"Syntax: \2UPDATE\2",
	"",
	"This option will force SecureServ to check the definitions",
	"file version and automatically update them to the latest"
	"version if required",
	"",
	"A valid username and password have to be set via the SET",
	"interface for this to function",
	NULL
};

const char *ts_help_list[] = {
	"Syntax: \2LIST\2",
	"",
	"View detailed information about what SecureServ's",
	"definition database currently contains",
	NULL
};

const char *ts_help_exclude[] = {
	"Syntax: \2EXCLUDE LIST\2",
	"        \2EXCLUDE ADD <hostname> <flag> <reason>\2",
	"        \2EXCLUDE DEL <index>\2",
	"",
	"This command lets you view or manipulate the exception",
	"list. Exception lists are used to exclude users, or",
	"servers from scanning. You should at least add a server",
	"entry for your services IRC name, to stop SecureServ from",
	"scanning Nickserv, Chanserv etc",
	"",
	"\2LIST\2 will list the current exceptions together with an",
	"ID number for use in removing entries.",
	"",
	"\2ADD\2 will add an entry of <hostname> to the exception",
	"list. Possible flags are:",
	"2 to indicate a channel name (eg, #help)",
	"1 to indicate a server name (eg, services.irc-chat.net)",
	"0 to indicate a hostname (eg, *.adsl.home.com).",
	"Reason allows you to set a",
	"reason for the exclusion for future reference",
	"Wildcards such as * and ? may be used in the hostname.",
	"",
	"\2DEL\2 will delete entry <index> from the list of",
	"exclusions. Use the LIST command to find the index.",
	"scanning NickServ, ChanServ etc",
	NULL
};

const char *ts_help_monchan[] = {
	"Syntax: \2MONCHAN LIST\2",
	"        \2MONCHAN ADD <channel>\2",
	"        \2MONCHAN DEL <channel>\2",
	"",
	"This command lets you assign a bot to stay in Specific",
	"channels to monitor for private message type viruses.",
	"You must specify a bot to use with",
	"/msg SecureServ set monbot <nick>",
	"See /msg SecureServ help set for more info",
	"",
	"\2LIST\2 will list the current channels that will be",
	"monitored. Should a channel listed here not exist when you", 
	"start SecureServ it will be automatically deleted from the",
	"list.",
	"\2ADD will add an entry of <channel> to the list of",
	"monitored channels. The channel has to exist when you",
	"use this command.",
	"\2DEL will delete the <channel> from the monitored",
	"channels list.",
	NULL
};

const char *ts_help_bots[] = {
	"Syntax: \2BOTS LIST\2",
	"        \2BOTS ADD <nick> <ident> <host> <info>\2",
	"        \2BOTS DEL <index>\2",
	"",
	"This command lets you view or manipulate the random Bot",
	"list. Bots from this list are randomly selected to join",
	"channels, scanning for on join based viruses",
	"You should try to use names/hosts etc that look real, and",
	"if possible, should change this list often.",
	"",
	"\2LIST\2 will list the current bots together with an",
	"ID number for use in removing entries.",
	"",
	"\2ADD\2 will add an entry with these details to the bot",
	"list.",
	"",
	"\2DEL\2 will delete entry <index> from the list.",
	"Use the LIST command to find the index.",
	NULL
};

const char *ts_help_helpers[] = {
	"Syntax: \2HELPERS LIST\2",
	"        \2HELPERS ADD <username> <password>\2",
	"        \2HELPERS DEL <username>\2",
	"",
	"Allows you to view or manipulate the helpers list.",
	"Helpers can be normal users that maintain your antivirus", 
	"channels and can help users with virus infections.",
	"Helpers have special privileges that allow them to kill",
	"infected users, or release users after the user has been",
	"identified as an infected user",
	"",
	"\2LIST\2 will list the current helpers. If a",
	"nickname is listed after the username, they are",
	"currently logged in.",
	"\2ADD\2 will add a helper entry with the username",
	"and password provided.",
	"\2DEL\2 will delete the helper entry with the",
	"username provided.",
	NULL
};


const char *ts_help_status[] = {
	"Syntax: \2STATUS\2",
	"",
	"Provide you with the Current Status of SecureServ.",
	NULL
};

const char *ts_help_assist[] = {
	"Syntax: \2ASSIST RELEASE <target>\2",
	"        \2ASSIST KILL <target>\2",
	"",
	"Allows Helpers to Release or akill infected users that",
	"have been joined to the help channel",
	"This command is only available to Helpers while logged in",
	"\2RELEASE\2 will releases SecureServ's hold on",
	"<target> so that they may rejoin channels",
	"\2KILL\2 will kill <target> from the network.",
	"Should only be used when the helper",
	"is unable to clean/help the user",
	NULL
};

const char *ts_help_set[] = {
	"Syntax: \2SET <OPTION> <SETTING>\2",
	"",
	"This command will set various options relating to SecureServ.",
	"You can view the settings by typing \2SET LIST\2",
	"The Settings take effect straight away",
	"The Options are:",
	"    \2VERSION <on/off>\2       - Turns CTCP Version Checking on and Off",
	"    \2CHECKFIZZER <on/off>\2   - Turns on and off Fizzer Checking. Disable if your network is not affected by Fizzer",
	"    \2DOONJOIN <on/off>\2      - Turns on and off the On join Virus Checking.",
	"    \2AKILL <on/off>\2         - Tells SecureServ to never issue an Akill on your Network. A warning message is sent to the operators instead",
	"    \2AKILLTIME <seconds>\2	- Sets the time an AKILL will last for.",
	"    \2DOJOIN <on/off>\2        - Tells SecureServ to never issue a SVSJOIN when a virus is detected. The User is Akilled instead",
	"    \2DOPRIVCHAN <on/off>\2	- Tells SecureServ not to join Private Channels",
	"    \2FLOODPROT <on/off>\2     - Enable Channel Flood Protection Scanning.",
	"    \2CHANKEY <key>\2          - When Flood Protection for a Channel is active, this is the key we will use to lock the channel",
	"    \2CHANLOCKTIME <seconds>\2 - How long (Approx) do we lock a Channel for. Time in seconds",
	"    \2UPDATEINFO <username> <password>\2",
	"                               - Sets the Username and Password required for updating the SecureServ",
	"                                 Definitions file. See the Readme file for more info",
	"    \2MONBOT <bot>\2           - Assign <bot> (from /msg SecureServ bots list) to be used for Channel Monitoring",
	"    \2BOTECHO <on/off>\2       - Make the onjoin bots echo messages recieved to the services channel regardless of the verbose setting",
	"\2Advanced Settings\2          - These settings should not be changed unless you know the effects in full",
	"    \2REPORT <on/off>\2        - Enable Reporting to Secure.irc-chat.net of infected users.",
	"    \2AUTOSIGNOUT <on/off>\2   - Automatically sign out helpers if they set away.",
	"    \2JOINHELPCHAN <on/off>\2	- Should SecureServ join the help channel when there is at least one helper logged in",
	"    \2MULTICHECK <on/off>\2    - Makes SecureServ check all Patterns when an infected User is found.",
	"                                 Please Read the Readme file for important Performance information",
	"    \2MONCHANCYCLE <on/off>\2  - Should the monitor bot cycle the channels occasionally",
	"    \2MONCHANCYCLETIME <seconds>\2 ",
	"                               - How often should the Monitor bot cycle a single channel",
	"    \2VERBOSE <on/off>\2       - Turn on Verbose Mode. Prepare to be flooded!",
	"    \2CYCLETIME <seconds>\2    - How Often Should SecureServ check new channels for infections.",
	"                                 See the Readme file for recommended Settings",
	"    \2AUTOUPDATE <on/off>\2    - Should SecureServ automatically update the Definitions file daily, if required?",
	"    \2SAMPLETIME <seconds> <joins>\2",
	"                               - Sets the threshold for Flood Checking. Read the Readme File for more information",
	"    \2NFCOUNT <number>\2       - Sets the threshold for Nick Floods. <number> is number of changes in 10 seconds.",
	"    \2SIGNONMSG <message>\2    - Changes the message sent to users when they connect if Version Checking is enabled",
	"    \2AKILLMSG <message>\2     - Changes the message sent to users when they are akilled",
	"    \2NOHELPMSG <message>\2    - Changes the message sent to users when their are no helpers logged in",
	"    \2HELPCHAN <channel>\2     - Changes the Channel that Virus infected users are joined to if there are helpers logged in",
	"    \2TREATCHANMSGASPM <on/off>\2",
	"                               - This option makes SecureServ check all channel messages against the virus signatures listed only for PM",
	"                                 This option will consume \2LOTS\2 of CPU time. You Shouldn't need to enable this under normal circumstances",
	"                                 as the Virus Database has a seperate list of signatures for channels",
	NULL
};

const char *ts_help_reload[] = {
	"Syntax: \2RELOAD\2",
	"",
	"Force SecureServ to reload the virus definition files.",
	"Used after manual updates to viri.dat or customviri.dat.",
	NULL
};
