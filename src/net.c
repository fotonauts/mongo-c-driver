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

int mongo_socket_connect( mongo *conn, const char *host, int port ) {
    struct addrinfo req, *ans;
    int code;
    int flag = 1;
    char serviceName[256];

    snprintf(serviceName, sizeof(serviceName), "%d", port);
    req.ai_flags = AI_NUMERICSERV;
    req.ai_family = AF_UNSPEC;
    req.ai_socktype = SOCK_STREAM;
    req.ai_protocol = IPPROTO_TCP;
    
    req.ai_protocol = 0;
    if ( ( code = getaddrinfo( host, serviceName, &req, &ans ) ) != 0 ) {
        conn->err = MONGO_CONN_ADDR_FAIL;
        freeaddrinfo( ans );
        return MONGO_ERROR;
    }
    
    if( mongo_create_socket( conn, ans->ai_family, ans->ai_socktype, ans->ai_protocol ) != MONGO_OK ) {
        freeaddrinfo( ans );
        return MONGO_ERROR;
    }

    if ( connect( conn->sock, ans->ai_addr, ans->ai_addrlen ) == -1 ) {
        printf( "can not connect to %s:%d with socket %d\n", host, port, conn->sock );
        mongo_close_socket( conn->sock );
        freeaddrinfo( ans );
        conn->connected = 0;
        conn->sock = 0;
        conn->err = MONGO_CONN_FAIL;
        return MONGO_ERROR;
    }

    freeaddrinfo( ans );
    setsockopt( conn->sock, IPPROTO_TCP, TCP_NODELAY, ( char * ) &flag, sizeof( flag ) );
    if( conn->op_timeout_ms > 0 )
        mongo_set_socket_op_timeout( conn, conn->op_timeout_ms );

    conn->connected = 1;

    return MONGO_OK;
}
