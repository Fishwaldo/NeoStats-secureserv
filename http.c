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
#include "http.h"

#ifdef DEBUG
 #define debug(path, args...) fprintf(path, ## args)
 #define debug2(ptr, args...) fwrite(ptr, ## args)
#else
 #define debug(path, args...)
 #define debug2(ptr, args...)
#endif

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
HTTP_Response http_request( char *in_URL, char *in_ReqAddition, HTTP_Method in_Method, unsigned long in_Flags )
{
    char *pBuf;
    char *pRequest;
	char *path;
    char scheme[50], host[MAXPATHLEN];
    char *pData, *pBase, *pContent, *pHCode, *pHMsgEnd; // *pScheme, *pHost, *pPath, 
    char szContent[32];
    char *proxy;
    int port;
    struct hostent *nameinfo;
    int s;
    struct sockaddr_in addr;
    struct timeval from_request, from_reply, end;
    unsigned long total_bytes, bytes, header_size = 0UL, data_size = 0UL, alloc_size = 0UL;
    fd_set set;
    int in_header;
    char *h_end_ptr;
#ifdef DEBUG
    long secs, usecs, bytes_per_sec;
#endif
    HTTP_Response   hResponse = { 0,0,0,0,0,"","" };

#ifdef HF_DO_FILE
// CRH  It's a file or directory
    if(in_Method == kHMethodGet && !strncasecmp(in_URL, "file://", 7))
        return do_file( in_URL );
#endif /* HF_DO_FILE */

    memset( hResponse.szHCode, '\0', HCODESIZE );
    memset( hResponse.szHMsg, '\0', HMSGSIZE );
	memset( host, '\0', MAXPATHLEN );
    memset( scheme, '\0', 50 );
    memset( szContent, '\0', 32 );

    pBuf = (char *)calloc( 1, BUFLEN + 1 );
    if( pBuf == NULL )
        return( hResponse );
                                            //  the GET and POST as of 9/4/2001
    if( in_Method == kHMethodPost )
    {
                                            //  add 1024 bytes for the header
        pRequest = (char *)calloc( 1, strlen( in_URL ) + 1024 );
        if( pRequest == NULL )
        {
			if( pBuf ) free( pBuf );
            hResponse.iError = errno;
            hResponse.pError = strerror( errno );
            return( hResponse );
        }
    }
    else                                    //  allocate enough for the 
    {
        if( strlen( in_URL ) < GETLEN )     //  compare against max request
        {
                                            //  allocate the size of the URL
                                            //  add 1024 bytes for the header
            pRequest = (char *)calloc( 1, strlen( in_URL ) + 1024 );
            if( pRequest == NULL )
            {
                hResponse.iError = errno;
                hResponse.pError = strerror( errno );
                return( hResponse );
            }
        }
        else 
        {
            debug( stderr, "*** Request too large, truncating to 8192 max size\n*** will try request anyway...\n" );
            *(in_URL + 8192) = '\0';
            pRequest = (char *)calloc( 1, GETLEN + 1024 );
            if( pRequest == NULL )
            {
                hResponse.iError = errno;
                hResponse.pError = strerror( errno );
                return( hResponse );
            }
        }
    }

    //  the http_proxy environment setting is common use for a proxy server,
    //  and the way it was setup per httpget.
    if( (proxy = getenv( "http_proxy" )) == NULL )
    {
        path = parse_url( in_URL, scheme, host, &port );
        debug( stderr, "URL scheme = %s\n", scheme );
        debug( stderr, "URL host = %s\n", host );
        debug( stderr, "URL port = %d\n", port );
        debug( stderr, "URL path = %s\n", path );
                                     //  check for http scheme to be safe.
        if( strcasecmp(scheme, "http") != 0 )
        {
            fprintf( stderr, "http_request cannot operate on %s URLs without a proxy\n", scheme );
			if( path ) free( path );
            if( pBuf ) free( pBuf );
            if( pRequest ) free( pRequest );
            return( hResponse );
        }
    }
    else
    {
        path = parse_url( proxy, scheme, host, &port );
		if( path ) free( path );            // 	free it, in_URL will be assigned to it
        debug( stderr, "Using proxy server at %s:%d\n", host, port );
        // add jjsa 2/17/2002
		path = (char *)calloc( 1, strlen( in_URL) + 1 );
		if( path == NULL )
		{
            if( pBuf ) free( pBuf );
            if( pRequest ) free( pRequest );
            return( hResponse );
		}
        path = in_URL;
    }
    /* -- Note : --
     * After this point, in_URL is no longer used and you should only
     * use "path". - Jean II
     */

    /* Find out the IP address */

    if( (nameinfo = gethostbyname( host )) == NULL )
    {
        addr.sin_addr.s_addr = inet_addr( host );
        if( (int)addr.sin_addr.s_addr == -1 )
        {
            hResponse.iError = errno;
            hResponse.pError = strerror( errno );
            
            fprintf( stderr, "Unknown host %s\n", host );
			if( path ) free( path );
            if( pBuf ) free( pBuf );
            if( pRequest ) free( pRequest );
            return( hResponse );
        }
    }
    else
    {
        memcpy( (char *)&addr.sin_addr.s_addr, nameinfo->h_addr, nameinfo->h_length );
    }

    /* Create socket and connect */

    if( (s = socket( PF_INET, SOCK_STREAM, 0 )) == -1 )
    {
        hResponse.iError = errno;
        hResponse.pError = strerror( errno );
		if( path ) free( path );
        if( pBuf ) free( pBuf );
        if( pRequest ) free( pRequest );
        return( hResponse );
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons( port );

    if( connect( s, (struct sockaddr *)&addr, sizeof(addr) ) == -1 )
    {
        hResponse.iError = errno;
        hResponse.pError = strerror( errno );
		if( path ) free( path );
        if( pBuf ) free( pBuf );
        if( pRequest ) free( pRequest );
        return( hResponse );
    }

    debug( stderr, "Connected to %s:%d\n", host, port );

    //  at this point we can construct our actual request. I'm trying to 
    //  incorporate more methods than the GET method supported by httpget

    switch( in_Method )
    {
        case kHMethodPost:
        {
        int pathlen;
            debug( stderr, "top of post\n" );
                                            //  a post URL should include some type of
                                            //  data appended with a '?', so we will
                                            //  require a '?' be present to continue.
            pContent = strchr( path, '?' );
            if( pContent != NULL )
            {
            /* Real lenght of the path.
         * We will split the "path" into two parts.
         * The arguments (after '?') will go in the body of the
         * request. It's size will be in Content-Length
         * The real "path" will go in the first line of the request.
         * Jean II */
            pathlen = pContent - path;

                pContent++;                 //  increment to first char of content
                debug( stderr, "path: %.*s\n", pathlen, path );
                debug( stderr, "content: %s\n", pContent );
            }
            else
            {
                hResponse.iError = errno;
                hResponse.pError = "ERROR, invalid URL for POST request";
                fprintf( stderr, "ERROR: invalid URL for POST request, no content found\n" );
                if( pBuf ) free( pBuf );
                if( pRequest ) free( pRequest );
                return( hResponse );
            }

            sprintf( pRequest, "POST %.*s HTTP/1.0\r\nHost: %s\r\n",
             pathlen, path, host );
                                            //  the following Content-Type may need to be changed
                                            //  depending on what type of data you are sending,
                                            //  and/or if the data is encoded. ajd 8/28/2001
        /* If the caller provides already a Content-Type header, no need
         * to do it ourselves - Jean II */
        if( ! (in_Flags & HFLAG_POST_USER_TYPE) )
                strcat( pRequest, "Content-Type: application/x-www-form-urlencoded\r\n");
            sprintf( szContent, "%s%d\r\n", "Content-Length: ", strlen( pContent ) );
            strcat( pRequest, szContent );
            if( strlen( in_ReqAddition ) )            //  add any additional entities
            {
                strcat( pRequest, in_ReqAddition );
                strcat( pRequest, "\r\n" );
            }
            strcat( pRequest, "User-Agent: hget/0.5\r\n" );
            strcat( pRequest, "Pragma: no-cache\r\n" );
            strcat( pRequest, "Accept: */*\r\n\r\n" );
            strcat( pRequest, pContent );
            break;
        }
        case kHMethodHead:
        {
            sprintf( pRequest, "HEAD %s HTTP/1.0\r\nHost: %s\r\n", path, host );
            strcat( pRequest, "User-Agent: hget/0.5\r\n" );
            if( strlen( in_ReqAddition ) )
            {
                strcat( pRequest, in_ReqAddition );
                strcat( pRequest, "\r\n" );
            }
            strcat( pRequest, "Pragma: no-cache\r\n" );
            strcat( pRequest, "Accept: */*\r\n\r\n" );
            break;
        }
        case kHMethodGet:
        default:                            //  currently GET is default!
        {
                                            //  added in the Host: header entity
                                            //  as that was preventing some servers
                                            //  from responding properly.
            sprintf( pRequest, "GET %s HTTP/1.0\r\nHost: %s\r\n", path, host );
            strcat( pRequest, "User-Agent: hget/0.5\r\n" );
            if( strlen( in_ReqAddition ) )
            {
                strcat( pRequest, in_ReqAddition );
                strcat( pRequest, "\r\n" );
            }
            strcat( pRequest, "Pragma: no-cache\r\n" );
            strcat( pRequest, "Accept: */*\r\n\r\n" );
            break;
        }
    }

    gettimeofday( &from_request, NULL );

    debug( stderr, "----- HTTP request follows -----\n" );
    debug( stderr, "%s\n", pRequest );
    debug( stderr, "----- HTTP request end -----\n" );
    write( s, pRequest, strlen( pRequest) );

    FD_ZERO( &set );
    FD_SET( s, &set );

    if( select( FD_SETSIZE, &set, NULL, NULL, NULL ) == -1 )
    {
        hResponse.iError = errno;
        hResponse.pError = strerror( errno );
		if( path ) free( path );
        if( pBuf ) free( pBuf );
        if( pRequest ) free( pRequest );
        return( hResponse );
    }

    gettimeofday( &from_reply, NULL );

    in_header = 1;

    total_bytes = 0UL;

    //  first we'll allocate a 64k chunk of memory. we don't know the exact size of the
    //  response. Most web pages fit in 64k of memory, and the is practical. for larger
    //  transfer I typically like to allocate more up front. Alter to your preference.
    //  I have tested this transfering a 32mb image using 64k allocations of memory and
    //  8k of read buffer.
    //  ajd 8/27/2001

    data_size = 0UL;
    pBase = (char *)malloc( XFERLEN );
    if( pBase == NULL )
    {
        hResponse.iError = errno;
        hResponse.pError = strerror( errno );
        
        fprintf(stderr, "ERROR (malloc): recv (errno = %d = %s)\n",
                                                     errno, strerror(errno));
        fflush( stderr );
		if( path ) free( path );
        if( pBuf ) free( pBuf );
        if( pRequest ) free( pRequest );
        return( hResponse );
    }
    alloc_size = XFERLEN;
    pData = pBase;                          //  assign the data ptr as base to start

                                            //  for better or worse I've
                                            //  decided to allocate 64k chunks
                                            //  and use 8k for a working buffer.
    while( (bytes = read( s, pBuf, BUFLEN )) != 0 )
    {
        total_bytes += bytes;

        debug( stderr, "data_size: %ld, alloc_size: %ld, total_bytes: %ld\n", data_size, alloc_size, total_bytes );

        if( (data_size + bytes ) > alloc_size )
        {
            pBase = realloc( pBase, (alloc_size + XFERLEN) );
            if( pBase == NULL )
            {
                                        //  get outta dodge and free the
                                        //  the allocated memory...there
                                        //  could be a chance that we ran
                                        //  out of resource, and we'll
                                        //  free it.
                hResponse.iError = errno;
                hResponse.pError = strerror( errno );
                
                fprintf(stderr, "ERROR (realloc): (errno = %d = %s)\n",
                                                     errno, strerror(errno));
                fflush( stderr );
				if( path ) free( path );
                if( pBase ) free( pBase );
                if( pBuf ) free( pBuf );
                if( pRequest ) free( pRequest );
                return( hResponse );
            }
            pData = pBase + data_size;
            alloc_size += XFERLEN;
            debug( stderr, "." );
        }

        memcpy( pData, pBuf, bytes );   //  copy data
        pData += bytes;                 //  increment pointer
        data_size += bytes;             //  increment size of data
    }

    gettimeofday( &end, NULL );
    close( s );
    debug( stderr, "\nConnection closed.\n" );

#ifdef DEBUG
    if( end.tv_usec < from_reply.tv_usec )
    {
        end.tv_sec -= 1;
        end.tv_usec += 1000000;
    }

    usecs = end.tv_usec - from_reply.tv_usec;
    secs = end.tv_sec - from_reply.tv_sec;

    debug( stderr, "Total of %ld bytes read in %ld.%ld seconds\n",
            total_bytes, secs, usecs );
    if( secs != 0 )
    {
        bytes_per_sec = (int)((total_bytes / (float)secs) + 0.5);
        debug( stderr, "%ld bytes per second\n", bytes_per_sec );
        fflush( stderr );
    }
#endif

    h_end_ptr = find_header_end( pBase, total_bytes );

    if( h_end_ptr != NULL )
    {
        //  we'll get response and response message
        pHCode = strchr( pBase, ' ' );
        if( pHCode != NULL )
        {
            pHCode++;
            strncpy( hResponse.szHCode, pHCode, 3 );
            //  now get message
            pHCode += 4;            //  increment past code
            //  and search for new line
            pHMsgEnd = strchr( pHCode, '\n' );
            if( pHMsgEnd != NULL )  //  get the rest of line for the response message
            {
                strncpy( hResponse.szHMsg, pHCode, 
                (pHMsgEnd - pHCode) <= (HMSGSIZE - 1) ? (pHMsgEnd - pHCode ) : (HMSGSIZE - 1) );
            }
        }
    }
    else
    {
        header_size = total_bytes;
        h_end_ptr = pBase + total_bytes;
    }

    //  now we'll store the size of the header, since we'll need to
    //  subtract that from the total of bytes downloaded to get the
    //  real size of the data.
    header_size = (unsigned long)(h_end_ptr - pBase);

    /* Found, print up to delimiter to stderr and rest to stdout */
    debug( stderr, "----- HTTP reply header follows -----\n" );
    debug2( pBase, h_end_ptr - pBase, 1, stderr );
    debug( stderr, "----- HTTP reply header end -----\n" );
    debug( stderr, "Header size: %d\n", header_size );

    if( in_Method == kHMethodHead )
    {
		if( path ) free( path );
        if( pBuf ) free( pBuf );
        if( pRequest ) free( pRequest );
        pBase = realloc( pBase, header_size );
        if( pBase == NULL )
            return( hResponse );
        hResponse.lSize = (long)header_size;
        hResponse.pData = pBase;
        return( hResponse );
    }

    /* Does the client wants the header ? - Jean II */
    if( in_Flags & HFLAG_RETURN_HEADER )
    {
    /* Allocate it => client will cleanup */
    hResponse.pHdr = malloc( header_size + 1 );
    /* Don't make a big deal if it fails */
    if( hResponse.pHdr != NULL )
    {
        memcpy( hResponse.pHdr, pBase, header_size );
        /* Be nice to client : NULL terminate it */
        hResponse.pHdr[header_size] = '\0';
    }
    }

    /* Delete HTTP headers */
    memcpy(pBase, h_end_ptr, total_bytes - header_size);

    //  realloc the data if we've gotten anything. chances are
    //  we'll have more allocated than we've transfered. ajd 8/27/2001
    if( (total_bytes - header_size) > 0 )
    {
        pBase = realloc( pBase, (total_bytes - header_size) + 1 );
        if( pBase == NULL )
        {
            hResponse.iError = errno;
            hResponse.pError = strerror( errno );

            fprintf(stderr, "ERROR (realloc): (errno = %d = %s)\n",
                                                     errno, strerror(errno));
            fflush( stderr );
            if( pBase ) free( pBase );
			if( path ) free( path );
            if( pBuf ) free( pBuf );
            if( pRequest ) free( pRequest );
            return( hResponse );
        }                                   
    }                                       //  now, if we've gotten this far we must
                                            //  have our data, so store the size and
                                            //  the pointer to the data in our response
                                            //  structure for return.
    if( in_Method != kHMethodHead )         //  HEAD would be set already
    {
        hResponse.lSize = (long)(total_bytes - header_size);
        hResponse.pData = pBase;
    }
	if( path ) free( path );
    if( pBuf ) free( pBuf );
    if( pRequest ) free( pRequest );
    return( hResponse );
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
HTTP_Response do_file(char *in_URL)
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

