/* net.c */

/*    Copyright 2009-2011 10gen Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/* Implementation for generic version of net.h */
#include "net.h"
#include <string.h>
#include <errno.h>

int mongo_write_socket( mongo *conn, const void *buf, size_t len ) {
    const char *cbuf = buf;
    while ( len ) {
        size_t sent = send( conn->sock, cbuf, len, 0 );
        if ( sent == -1 ) {
            conn->err = MONGO_IO_ERROR;
            return MONGO_ERROR;
        }
        cbuf += sent;
        len -= sent;
    }

    return MONGO_OK;
}

int mongo_read_socket( mongo *conn, void *buf, size_t len ) {
    char *cbuf = buf;
    while ( len ) {
        size_t sent = recv( conn->sock, cbuf, len, 0 );
        if ( sent == 0 || sent == -1 ) {
            conn->err = MONGO_IO_ERROR;
            return MONGO_ERROR;
        }
        cbuf += sent;
        len -= sent;
    }

    return MONGO_OK;
}

/* This is a no-op in the generic implementation. */
int mongo_set_socket_op_timeout( mongo *conn, int millis ) {
    return MONGO_OK;
}

static int mongo_create_socket( mongo *conn, int domain, int type, int protocol ) {
    int fd;

    if( ( fd = socket( domain, type, protocol ) ) == -1 ) {
        conn->err = MONGO_CONN_NO_SOCKET;
        return MONGO_ERROR;
    }
    conn->sock = fd;

    return MONGO_OK;
}

static void print_ip_from_address( struct addrinfo *ans )
{
    char *proto_arr[] = { "IPv4","IPv6","UNIX" };
    char *service=NULL;
    int err;
    struct sockaddr *sa;
    int size;
    int proto;
    int nameinfoflags = NI_NUMERICHOST;
    
    char hostbuf[NI_MAXHOST];
    char servbuf[NI_MAXSERV];
    
    
    sa=ans->ai_addr;
    size=0;
    switch ( sa->sa_family ) {
        case PF_INET:
            size=sizeof( struct sockaddr_in );
            proto=0;
            break;
        case PF_INET6:
            size=sizeof( struct sockaddr_in6 );
            proto=1;
            break;
        default:
            fprintf( stderr, "Unknown protocol family in result: %d\n", sa->sa_family );
    }
    if ( size ) {
        if ( (err = getnameinfo( sa, size, hostbuf, sizeof(hostbuf), servbuf, sizeof(servbuf), nameinfoflags ) ) ) {
            fprintf( stderr,"%s\n", gai_strerror( err ) );
        } else {
            if ( service )
                printf( "%s %s %s\n", proto_arr[proto], hostbuf, servbuf );
            else
                printf( "%s %s\n", proto_arr[proto], hostbuf );
        }
    }
}

int mongo_socket_connect( mongo *conn, const char *host, int port ) {
    struct addrinfo req, *ans, *ans_cursor;
    int flag = 1;
    char serviceName[256];

    snprintf( serviceName, sizeof( serviceName ), "%d", port );
    req.ai_flags = AI_NUMERICSERV;
    req.ai_family = AF_UNSPEC;
    req.ai_socktype = SOCK_STREAM;
    req.ai_protocol = IPPROTO_TCP;
    
    req.ai_protocol = 0;
    if ( getaddrinfo( host, serviceName, &req, &ans ) != 0 ) {
        printf( "cannot get address info, error %d\n", errno );
        perror( "getaddrinfo error" );
        conn->err = MONGO_CONN_ADDR_FAIL;
        freeaddrinfo( ans );
        return MONGO_ERROR;
    }
    
    // test all ips that match the host (this is useful when entering localhost, since it will match 127.0.0.1 and ::1
    // but the mongo server might listen only to 127.0.0.1 or ::1, so we need to try all ips).
    ans_cursor = ans;
    while ( ans_cursor ) {
        if ( mongo_create_socket( conn, ans_cursor->ai_family, ans_cursor->ai_socktype, ans_cursor->ai_protocol ) != MONGO_OK ) {
            printf( "cannot create socket, error %d\n", errno );
            perror( "mongo_create_socket error" );
        } else if ( connect( conn->sock, ans_cursor->ai_addr, ans_cursor->ai_addrlen ) == -1 ) {
            print_ip_from_address( ans_cursor );
            printf( "can not connect to %s:%d with socket %d, error number %d \n", host, port, conn->sock, errno );
            perror( "connect error" );
            mongo_close_socket( conn->sock );
        } else {
            break;
        }
        ans_cursor = ans_cursor->ai_next;
    }

    freeaddrinfo( ans );
    if ( ans_cursor ) {
        setsockopt( conn->sock, IPPROTO_TCP, TCP_NODELAY, ( char * ) &flag, sizeof( flag ) );
        if ( conn->op_timeout_ms > 0 )
            mongo_set_socket_op_timeout( conn, conn->op_timeout_ms );

        conn->connected = 1;
        return MONGO_OK;
    } else {
        conn->connected = 0;
        conn->sock = 0;
        conn->err = MONGO_CONN_FAIL;
        return MONGO_ERROR;
    }
}
