/* NeoStats - IRC Statistical Services Copyright 
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
** $Id$
*/
/***************************************************************************
 *
 *     Library: http
 *
 * Description: header for libhttp
 *
 ***************************************************************************
 *
 * Copyright (C) 1994 by Sami Tikka <sti@iki.fi>
 * Copyright (C) 2001 by Alan DuBoff <aland@SoftOrchestra.com>
 *
 * The right to use, modify and redistribute this code is allowed
 * provided the above copyright notice and the below disclaimer appear
 * on all copies.
 *
 * This file is provided AS IS with no warranties of any kind.  The author
 * shall have no liability with respect to the infringement of copyrights,
 * trade secrets or any patents by this file or any part thereof.  In no
 * event will the author be liable for any lost revenue or profits or
 * other special, indirect and consequential damages.
 *
 ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <memory.h>
#include <errno.h>


/* this is the DATFILE location */
#define DATFILE "/defs.php"
/* this is the DATFILE Version Location */
#define DATFILEVER "/vers.php"
/* this is the HostName */
#define HTTPHOST "secure.irc-chat.net"


/* Compile time options.
 * Allow you to disable library functionality you don't need. - Jean II
 */
#define HF_FIND_HEADER		/* find_header() function */
#undef HF_DO_FILE		/* do_file() function & functionality */

#define BUFLEN 8192
#define GETLEN 8192
#define XFERLEN 65536
#define HCODESIZE 4
#define HMSGSIZE 32

/* Flags is a mask with the xor of the various options - Jean II */
#define HFLAG_NONE		0x0000		/* No flags */
#define HFLAG_RETURN_HEADER	0x0001		/* Return HTTP headers */
#define HFLAG_POST_USER_TYPE	0x0002		/* Do not add post type */
/* Maybe FORCE_PROXY/FORCE_NO_PROXY , and HFLAG_USER_ACCEPT */

#ifdef __cplusplus
 extern "C" {
#endif

typedef struct
{
    char *pData;                            //  pointer to data
    long lSize;                             //  size of data allocated
    char *pHdr;                             //  pointer to header, if requested
    int  iError;                            //  error upon failures
    char *pError;                           //  text description of error
    char szHCode[HCODESIZE];                //  http response code
    char szHMsg[HMSGSIZE];                  //  message/description of http code
} HTTP_Response, *PHTTP_Response;

typedef enum 
{
    kHMethodOptions = 1,
    kHMethodGet,
    kHMethodHead,
    kHMethodPost,
    kHMethodPut,
    kHMethodDelete,
    kHMethodTrace
}HTTP_Method;
                    
char *find_header_end( char *buf, int bytes );
char *parse_url( char *url, char *scheme, char *host, int *port );
int http_request( char *in_URL, HTTP_Method in_Method, unsigned long in_Flags,void (*callback)(HTTP_Response *response) );
#ifdef HF_DO_FILE
int do_file(char *in_URL);
#endif /* HF_DO_FILE */
#ifdef HF_FIND_HEADER
char *find_header( char *buf, int bytes, char *type, char *value, int maxv );
#endif /*  HF_FIND_HEADER */

#ifdef __cplusplus
}
#endif

