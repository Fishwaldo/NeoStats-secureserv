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
** $Id: http.c,v 1.8 2003/08/19 14:16:35 fishwaldo Exp $
*/
/***************************************************************************
 *
 *     Library: libhttp
 *
 * Description: library for generic http data transfers
 *
 ***************************************************************************
 *
 * HTTPGET/libhttp
 *
 * Copyright (C) 1994 by Sami Tikka <sti@iki.fi>
 * Copyright (C) 2001 by Alan DuBoff <aland@SoftOrchestra.com>
 *
 * Last change: 8/27/2001
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
 * Compile with (g)cc -o httpget httpget.c (-lsocket)
 *
 ***************************************************************************/

#include <ctype.h>
#include "stats.h"
#include "log.h"
#include "http.h"

#ifdef DEBUG
 #define debug(path, args...) fprintf(path, ## args)
 #define debug2(ptr, args...) fwrite(ptr, ## args)
#else
 #define debug(path, args...)
 #define debug2(ptr, args...)
#endif

typedef struct http_details {
	char path[8192];
	int port;
	char host[MAXHOST];
	HTTP_Response *response;
	int method;
	char *pRequest;
	void (*callback)(HTTP_Response *response);
    	struct sockaddr_in addr;
	char *pData;
	char *pBase;
        unsigned long total_bytes;
        unsigned long bytes;
        unsigned long data_size;
        unsigned long alloc_size;
        int in_header;
} http_details;

struct http_details *hd;

char *find_header_end( char *buf, int bytes )
{
    char *end = buf + bytes;

    while( buf < end && !(*buf++ == '\n'
                          && (*buf == '\n'
                              || (*buf++ == '\r'
                                  && *buf == '\n'))) ) ;
    if( *buf == '\n' )
        return( buf + 1 );
    return( NULL );
}

#ifdef HF_FIND_HEADER
/*
 * This function try to find the HTTP header specified and return its value.
 * The 'buf' contains the header is assumed to be terminated by a blank line.
 * The 'type' must be terminated by a colon, such as "Content-Type:".
 */
char *find_header( char *buf, int buflen, char *type, char *value, int vsize )
{
    char *end;
    char *eol;
    int tl = strlen(type);

    /* Find the end (in case input is not NULL terminated) */
    if(buflen <= 0)
      buflen = strlen(buf);
    end = buf + buflen;

    do      /* For each line of header */
    {
        /* Note : 'type' *must* be terminated by a ':', otherwise you may
     * match the wrong header */
        if( ! strncasecmp( buf, type, tl ) )
    {
        buf += tl;          /* Skip header type */
        while( isspace( *buf ) )    /* Skip spaces */
            buf++;
        /* We keep the blank line at the end of the header, we are safe */
        eol = strchr(buf, '\r');
        /* Unlikely to fail, but let be safe */
        if( ( eol != NULL ) && ( (eol - buf) < (vsize - 1) ) )
        {
            /* Copy, NULL terminate, return */
            memcpy( value, buf, (eol - buf) );
        value[(eol - buf)] = '\0';
        debug( stderr, "Found header %s: %s\n", type, value );
        return( value );
        }
    }
    }       /* Go to start of next line, if any */
    while( ( ( buf = strchr( buf, '\n' ) ) != NULL ) && ( ++buf < end ) );

    return( NULL );
}
#endif  /* HF_FIND_HEADER */

/* Separate an URL in its different components.
 * Note that GET/POST form data is not removed from the "path", and therefore
 * it can be quite big. That's why we return it and don't copy it.
 * Jean II */
char *parse_url( char *url, char *scheme, char *host, int *port )
{
    char *slash, *colon;
    char *delim;
    char *turl;
    char *t;
	char *pRet;

    /* All operations on turl so as not to mess contents of url */

	turl = (char *)calloc( 1, strlen( url ) + 1 );
	if( turl == NULL )
		return (char *)"";

    strcpy( turl, url );

    delim = "://";

    if( (colon = strstr( turl, delim )) == NULL )
    {
        debug( stderr, "Warning: URL is not in format <scheme>://<host>/<path>.\nAssuming scheme = http.\n" );
        strcpy( scheme, "http" );
        t = turl;
    }
    else
    {
        *colon = '\0';
        strcpy( scheme, turl );
        t = colon + strlen( delim );
    }

    /* Now t points to the beginning of host name */

    if( (slash = strchr( t, '/' )) == NULL )
    {
        /* If there isn't even one slash, the path must be empty */
        debug( stderr, "Warning: no slash character after the host name.  Empty path.  Adding slash.\n" );
        strcpy( host, t );
    slash = "/";
    }
    else
    {
    memcpy( host, t, slash - t);
    host[slash - t] = '\0';
    }

    /* Check if the hostname includes ":portnumber" at the end */

    if( (colon = strchr( host, ':' )) == NULL )
    {
        *port = 80;                         /* HTTP standard */
    }
    else
    {
        *colon = '\0';
        *port = atoi( colon + 1 );
    }

	pRet = (char *)calloc( 1, strlen( slash ) + 1 );
	strcpy( pRet, slash );
	
	if( turl ) free( turl );

    /* Return the path + arguments */
    return( pRet );
}


/*
 * Function Name:   http_request
 *
 * Parameters:      char *in_URL        http URL to request
 *                  int in_Method       enum for method type
 *                  (see http.h)
 * Description:     handle a request to an http server. this is being kept
 *                  simple for a purpose, call the function with an http URL
 *                  and have return the response inside HTTP_Response.
 *
 * Returns:         HTTP_Response struct
 *
 *                  NOTE: the memory is allocated for the data transfered,
 *                        and it is the responsibility of the *CALLER* to free
 *                        the memory. it's very easy to accumulate several
 *                        megabytes of data.
 *
 */
int http_request( char *in_URL, HTTP_Method in_Method, unsigned long in_Flags, void (*callback)(HTTP_Response *response))
{
    char scheme[50], host[MAXPATHLEN];
    char *proxy;
    char *path;
    int port;
    struct sockaddr_in addr;




#ifdef HF_DO_FILE
// CRH  It's a file or directory
    if(in_Method == kHMethodGet && !strncasecmp(in_URL, "file://", 7))
        return do_file( in_URL );
#endif /* HF_DO_FILE */

    hd = malloc(sizeof(http_details));
    hd->response = malloc(sizeof(HTTP_Response));
    hd->response->lSize = 0;
    hd->response->iError = 1;
    memset( hd->response->szHCode, '\0', HCODESIZE );
    memset( hd->response->szHMsg, '\0', HMSGSIZE );
#if 0

    memset( hd->host, '\0', MAXPATHLEN );
    memset( scheme, '\0', 50 );
#endif
    hd->method = in_Method;
    hd->callback = callback;    
                                            //  the GET and POST as of 9/4/2001
    if( in_Method == kHMethodPost )
    {
                                            //  add 1024 bytes for the header
        hd->pRequest = (char *)calloc( 1, strlen( in_URL ) + 1024 );
        if( hd->pRequest == NULL )
        {
            hd->response->iError = errno;
            hd->response->pError = strerror( errno );
	    hd->callback(hd->response);
	    free(hd->response);
            return(-1);
        }
    }
    else                                    //  allocate enough for the 
    {
        if( strlen( in_URL ) < GETLEN )     //  compare against max request
        {
                                            //  allocate the size of the URL
                                            //  add 1024 bytes for the header
            hd->pRequest = (char *)calloc( 1, strlen( in_URL ) + 1024 );
            if( hd->pRequest == NULL )
            {
                hd->response->iError = errno;
                hd->response->pError = strerror( errno );
	        hd->callback(hd->response);
	        free(hd->response);
                return(-1);
            }
        }
        else 
        {
            *(in_URL + 8192) = '\0';
            hd->pRequest = (char *)calloc( 1, GETLEN + 1024 );
            if( hd->pRequest == NULL )
            {
                hd->response->iError = errno;
                hd->response->pError = strerror( errno );
	        hd->callback(hd->response);
		free(hd->response);
                return(-1);
            }
        }
    }

    //  the http_proxy environment setting is common use for a proxy server,
    //  and the way it was setup per httpget.
    if( (proxy = getenv( "http_proxy" )) == NULL )
    {
        path = parse_url( in_URL, scheme, host, &port );
//	if (path) free(path);
        //  check for http scheme to be safe.
        if( strcasecmp(scheme, "http") != 0 )
        {
            nlog(LOG_WARNING, LOG_MOD, "http_request cannot operate on %s URLs without a proxy\n", scheme );
            hd->response->iError = -1 ;
            hd->callback(hd->response);
	    free(hd->response);
            if( path ) free( path );
            if( hd->pRequest ) free( hd->pRequest );
            return(-1);
        }
    }
    else
    {
        path = parse_url( proxy, scheme, host, &port );
//	if( path ) free( path );            // 	free it, in_URL will be assigned to it
        // add jjsa 2/17/2002
	path = (char *)calloc( 1, strlen( in_URL) + 1 );
	if( path == NULL )
	{
            hd->response->iError = errno;
            hd->response->pError = strerror( errno );
            hd->callback(hd->response);
            free(hd->response);
            if( hd->pRequest ) free( hd->pRequest );
            return(-1);
	}
        path = in_URL;
        
    }
    /* -- Note : --
     * After this point, in_URL is no longer used and you should only
     * use "path". - Jean II
     */
    strncpy(hd->path, path, 8192);
    strncpy(hd->host, host, MAXHOST);
    hd->port = port;
    nlog(LOG_DEBUG1, LOG_MOD, "HTTP_Request: %s:%d/%s and Request %s", hd->host, hd->port, hd->path, hd->pRequest);


    addr.sin_addr.s_addr = inet_addr( host );
    if( (int)addr.sin_addr.s_addr == -1 )
        {
	nlog(LOG_CRITICAL, LOG_MOD, "Host %s is not a valid IP address", hd->host);
        hd->response->iError = -1;
	hd->callback(hd->response);
	free(hd->response);
        if( hd->pRequest ) free( hd->pRequest );
	return(-1);
    } else {
    	/* do connect, as the host, was a IP address */
	sock_connect(SOCK_STREAM, addr.sin_addr.s_addr, hd->port, "SecureServ", "SecureServ", "http_read", "http_write", "http_error");
    } 
    return(1);
}


extern int http_read(int socknum, char *sockname) {
	int i;
	char buf[BUFLEN];
    	char *h_end_ptr, *pHCode, *pHMsgEnd;
    	unsigned long header_size = 0UL;
	
//	buf = malloc(BUFLEN);
	bzero(buf, BUFLEN);
	i = recv(socknum, buf, BUFLEN, 0);
	if (i < 0) {
		nlog(LOG_NOTICE, LOG_MOD, "HttpGet Error in Read %s", strerror(errno));
	        hd->response->iError = errno;
                hd->response->pError = strerror( errno );
                hd->callback(hd->response);
		if (hd->pRequest) free(hd->pRequest);
        	sock_disconnect(sockname);
		free(hd->response);
//		free(buf);
        	return -1;
        } else if (i == 0) {
//		free(buf);
        	nlog(LOG_DEBUG1, LOG_MOD, "HttpGet Successfull");

	    	h_end_ptr = find_header_end( hd->pBase, hd->total_bytes );

    		if( h_end_ptr != NULL )
    		{
        		//  we'll get response and response message
		        pHCode = strchr( hd->pBase, ' ' );
		        if( pHCode != NULL )
		        {
		            pHCode++;
		            strncpy( hd->response->szHCode, pHCode, 3 );
		            //  now get message
		            pHCode += 4;            //  increment past code
		            //  and search for new line
		            pHMsgEnd = strchr( pHCode, '\n' );
		            if( pHMsgEnd != NULL )  //  get the rest of line for the response message
		            {
		                strncpy( hd->response->szHMsg, pHCode, 
		                (pHMsgEnd - pHCode) <= (HMSGSIZE - 1) ? (pHMsgEnd - pHCode ) : (HMSGSIZE - 1) );
		            }
		        }
	    	}
	    	else
    		{
		        header_size = hd->total_bytes;
		        h_end_ptr = hd->pBase + hd->total_bytes;
    		}

    		//  now we'll store the size of the header, since we'll need to
    		//  subtract that from the total of bytes downloaded to get the
    		//  real size of the data.
    		header_size = (unsigned long)(h_end_ptr - hd->pBase);
    		if( hd->method == kHMethodHead )
    		{
			if( hd->path ) free( hd->path );
        		if( hd->pRequest ) free( hd->pRequest );
        		hd->pBase = realloc( hd->pBase, header_size );
        		if( hd->pBase == NULL ) {
				sock_disconnect(sockname);
		                hd->response->iError = errno;
            			hd->response->pError = strerror( errno );
            			hd->callback(hd->response);
            			if( hd->pBase ) free( hd->pBase );
				if( hd->path ) free( hd->path );
            			if( hd->pRequest ) free( hd->pRequest );
            			free(hd->response);
//				free(buf);
	            		return(-1);
	            	}
        		hd->response->lSize = (long)header_size;
        		hd->response->pData = hd->pBase;
			sock_disconnect(sockname);
	                hd->response->iError = errno;
       			hd->response->pError = strerror( errno );
       			hd->callback(hd->response);
       			if( hd->pBase ) free( hd->pBase );
			if( hd->path ) free( hd->path );
        		if( hd->pRequest ) free( hd->pRequest );
       			free(hd->response);
//        		free(buf);
			/* callback */
        		return(-1);
    		}

	    	/* Delete HTTP headers */
    		memcpy(hd->pBase, h_end_ptr, hd->total_bytes - header_size);
		hd->pBase[hd->total_bytes - header_size] = '\0';
    		//  realloc the data if we've gotten anything. chances are
    		//  we'll have more allocated than we've transfered. ajd 8/27/2001
    		if( (hd->total_bytes - header_size) > 0 )
    		{
        		hd->pBase = realloc( hd->pBase, (hd->total_bytes - header_size) +1);
        		if( hd->pBase == NULL )
        		{
            			hd->response->iError = errno;
            			hd->response->pError = strerror( errno );
	       			hd->callback(hd->response);
            			if( hd->pBase ) free( hd->pBase );
				if( hd->path ) free( hd->path );
            			if( hd->pRequest ) free( hd->pRequest );
				sock_disconnect(sockname);
       				free(hd->response);
//				free(buf);
				/* callback */
            			return( -1);
        		}                                   
    		}                                       //  now, if we've gotten this far we must
                                            //  have our data, so store the size and
                                            //  the pointer to the data in our response
                                            //  structure for return.
    		if( hd->method != kHMethodHead )         //  HEAD would be set already
    		{
        		hd->response->lSize = (long)(hd->total_bytes - header_size);
        		hd->response->pData = hd->pBase;
    		}
#ifdef DEBUG
//		printf("HTTP Data:\n%s\n %d = %d\n", hd->response->pData, hd->response->lSize, strlen(hd->response->pData));
#endif
        	hd->callback(hd->response);
         	if( hd->pBase ) free( hd->pBase );
		if( hd->path ) free( hd->path );
            	if( hd->pRequest ) free( hd->pRequest );
		if ( hd->response) free(hd->response);
        	sock_disconnect(sockname);
        	return -1;
	/* end of succesfull get */
	}                		


	/* if we are here, we wer still downloading */
        hd->total_bytes += i;

        if( (hd->data_size + i ) > hd->alloc_size )
        {
            /* make sure that pBase has a enough memory for the file */
            hd->pBase = realloc( hd->pBase, (hd->alloc_size + XFERLEN) );
            if( hd->pBase == NULL )
            {
                                        //  get outta dodge and free the
                                        //  the allocated memory...there
                                        //  could be a chance that we ran
                                        //  out of resource, and we'll
                                        //  free it.
                hd->response->iError = errno;
                hd->response->pError = strerror( errno );
		hd->callback(hd->response);
		free(hd->response);                
		if( hd->path ) free( hd->path );
                if( hd->pBase ) free( hd->pBase );
                if( hd->pRequest ) free( hd->pRequest );
//		free(buf);
                sock_disconnect(sockname);
                return(-1);
            }
            hd->pData = hd->pBase + hd->data_size;
            hd->alloc_size += XFERLEN;
        }

        memcpy( hd->pData, buf, i );   //  copy data
        hd->pData += i;                 //  increment pointer
        hd->data_size += i;             //  increment size of data
//	free(buf);
    	/* we are continuing, so just return 1 */
    	return 1;
}
extern int http_write(int socknum, char *sockname) {
    int i;
    char szContent[32];
    char *pContent;

    if (strlen(hd->pRequest) > 0) {
    	return 1;
    }



    //  at this point we can construct our actual request. I'm trying to 
    //  incorporate more methods than the GET method supported by httpget

    switch( hd->method )
    {
        case kHMethodPost:
        {
        int pathlen;
            debug( stderr, "top of post\n" );
                                            //  a post URL should include some type of
                                            //  data appended with a '?', so we will
                                            //  require a '?' be present to continue.
            pContent = strchr( hd->path, '?' );
            if( pContent != NULL )
            {
            /* Real lenght of the path.
         * We will split the "path" into two parts.
         * The arguments (after '?') will go in the body of the
         * request. It's size will be in Content-Length
         * The real "path" will go in the first line of the request.
         * Jean II */
            pathlen = pContent - hd->path;

                pContent++;                 //  increment to first char of content
            }
            else
            {
                hd->response->iError = errno;
                hd->response->pError = "ERROR, invalid URL for POST request";
                hd->callback(hd->response);
		free(hd->response);
                if( hd->pRequest ) free( hd->pRequest );
                return(1);
            }

            sprintf( hd->pRequest, "POST %.*s HTTP/1.0\r\nHost: %s\r\n",
             pathlen, hd->path, HTTPHOST );
                                            //  the following Content-Type may need to be changed
                                            //  depending on what type of data you are sending,
                                            //  and/or if the data is encoded. ajd 8/28/2001
            sprintf( szContent, "%s%d\r\n", "Content-Length: ", strlen( pContent ) );
            strcat( hd->pRequest, szContent );
            strcat( hd->pRequest, "User-Agent: SecureServ/0.9.1\r\n" );
            strcat( hd->pRequest, "Pragma: no-cache\r\n" );
            strcat( hd->pRequest, "Accept: */*\r\n\r\n" );
            strcat( hd->pRequest, pContent );
            break;
        }
        case kHMethodHead:
        {
            sprintf( hd->pRequest, "HEAD %s HTTP/1.0\r\nHost: %s\r\n", hd->path, HTTPHOST );
            strcat( hd->pRequest, "User-Agent: SecureServ/0.9.1\r\n" );
            strcat( hd->pRequest, "Pragma: no-cache\r\n" );
            strcat( hd->pRequest, "Accept: */*\r\n\r\n" );
            break;
        }
        case kHMethodGet:
        default:                            //  currently GET is default!
        {
                                            //  added in the Host: header entity
                                            //  as that was preventing some servers
                                            //  from responding properly.
            sprintf( hd->pRequest, "GET %s HTTP/1.0\r\nHost: %s\r\n", hd->path, HTTPHOST );
            strcat( hd->pRequest, "User-Agent: SecureServ/0.9.1\r\n" );
            strcat( hd->pRequest, "Pragma: no-cache\r\n" );
            strcat( hd->pRequest, "Accept: */*\r\n\r\n" );
            break;
        }
    }

    nlog(LOG_DEBUG2, LOG_MOD, "HTTP Request: %s", hd->pRequest);
    i = write( socknum, hd->pRequest, strlen( hd->pRequest) );
    if (i < 0) {
    	nlog(LOG_NOTICE, LOG_MOD, "HTTP_Get: Write Error: %s", strerror(errno));
        hd->response->iError = errno;
        hd->response->pError = strerror( errno );
        hd->callback(hd->response);
	free(hd->response);
        if( hd->pRequest ) free( hd->pRequest );
       	sock_disconnect(sockname);
       	return -1;
    }

    /* if we get here, we can allocate some space, and setup the temp buffer */
    hd->in_header = 1;

    hd->total_bytes = 0UL;

    //  first we'll allocate a 64k chunk of memory. we don't know the exact size of the
    //  response. Most web pages fit in 64k of memory, and the is practical. for larger
    //  transfer I typically like to allocate more up front. Alter to your preference.
    //  I have tested this transfering a 32mb image using 64k allocations of memory and
    //  8k of read buffer.
    //  ajd 8/27/2001

    hd->data_size = 0UL;
    hd->pBase = (char *)malloc( XFERLEN );
    if( hd->pBase == NULL )
    {
        hd->response->iError = errno;
        hd->response->pError = strerror( errno );
        
	if( hd->path ) free( hd->path );
        if( hd->pRequest ) free( hd->pRequest );
	hd->callback(hd->response);
	free(hd->response);
	sock_disconnect(sockname);
        return(-1);
    }
    hd->pData = hd->pBase;
    hd->alloc_size = XFERLEN;



    return 1;
}

extern int http_error(int socknum, char *sockname) {
printf("error\n");
}


#ifdef HF_DO_FILE
/*
 * Function Name:   do_file
 *
 * Parameters:      char *in_URL        file://URL to request
 *
 * Description:     read and format a file or directory as HTML
 *
 * Returns:         HTTP_Response struct
 *
 *                  NOTE: the memory is allocated for the data transfered,
 *                        and it is the responsibility of the *CALLER* to free
 *                        the memory. it's very easy to accumulate several
 *                        megabytes of data.
 *
 */
int do_file(char *in_URL)
    {
    HTTP_Response   hResponse = { 0,0,0,0,"","" };
    struct stat status;
    char temp[BUFLEN];
    char *buff;
    FILE *doit;
    int path;
    int count;
    int size;
    int i;

    memset( hResponse.szHCode, '\0', HCODESIZE );
    memset( hResponse.szHMsg, '\0', HMSGSIZE );

    in_URL += 7;

    if(stat(in_URL, &status) || !status.st_mode & S_IRGRP)
        {
        hResponse.iError = errno;
        hResponse.pError = strerror(errno);
        return(hResponse);
        }


    if(S_ISREG(status.st_mode) || S_ISLNK(status.st_mode))
        {
        buff = (char *)malloc(status.st_size);
        if(buff == NULL)
            return(hResponse);

        if(-1 == (path = open(in_URL, O_RDONLY)))
            {
            if(buff) free(buff);
            hResponse.iError = errno;
            hResponse.pError = strerror(errno);
            return(hResponse);
            }
        read(path, buff, status.st_size);
        close(path);

        buff = realloc(buff, status.st_size);
        hResponse.lSize = (long)(status.st_size);
        hResponse.pData = buff;
        return(hResponse);
        }

    if(S_ISDIR(status.st_mode))
        {
        buff = (char *)malloc(XFERLEN);
        if(buff == NULL)
            return(hResponse);
        size = XFERLEN;

        count = sprintf(buff, "<HTML><HEAD><TITLE>Index of %s</TITLE></HEAD>\n<BODY BGCOLOR=\"#99cc99\"><H4>Index of %s</H4>\n<PRE>\n", in_URL, in_URL);

        strcpy(temp, in_URL);
        i = strlen(temp) - 2;
        while(temp[i] != '/' && i > 0)
            temp[i--] = '\0';

        count += sprintf(&buff[count], "<A HREF=\"file://%s\">Parent Directory</A><P>\n", temp);

        (void) sprintf(temp, "ls -lgF '%s' | tail +2 | sed -e 's/^\\([^ ][^ ]*  *[^ ][^ ]*  *[^ ][^ ]*  *[^ ][^ ]*  *[^ ][^ ]*  *[^ ][^ ]*  *[^ ][^ ]*  *[^ ][^ ]*\\)  *\\(.*\\)$/\\1 |\\2/' -e '/ -> /!s,|\\([^*]*\\)$,|<A HREF=\"\\1\">\\1</A>,' -e '/ -> /!s,|\\(.*\\)\\([*]\\)$,|<A HREF=\"\\1\">\\1</A>\\2,' -e '/ -> /s,|\\([^@]*\\)\\(@* -> \\),|<A HREF=\"\\1\">\\1</A>\\2,' -e 's/|//'", in_URL);
        doit = popen(temp, "r");
        while((i = fread(temp, 1, BUFLEN - 1, doit)) > 0)
            {
            if(count + i > size)
                {
                buff = realloc(buff, size + XFERLEN);
                if(buff == NULL)
                    {
                    hResponse.iError = errno;
                    hResponse.pError = strerror( errno );
                    fprintf(stderr, "ERROR (realloc): (errno = %d = %s)\n",
                                                     errno, strerror(errno));
                    fflush( stderr );
                    return( hResponse );
                    }
                size += XFERLEN;
                }
            memcpy(&buff[count], temp, i);   //  copy data
            count += i;
            }
        pclose(doit);

        count += sprintf(&buff[count], "</PRE>\n</BODY></HTML>\n");

        buff = realloc(buff, count);
        hResponse.lSize = count;
        hResponse.pData = buff;
        return(hResponse);
        }
    return(hResponse);
    }
#endif /* HF_DO_FILE */

