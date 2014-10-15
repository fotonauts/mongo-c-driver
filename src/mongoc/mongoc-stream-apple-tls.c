/*
 * Copyright 2013 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <bson.h>

#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

#include "mongoc-counters-private.h"
#include "mongoc-errno-private.h"
#include "mongoc-stream-tls.h"
#include "mongoc-stream-private.h"
#include "mongoc-ssl-private.h"
#include "mongoc-trace.h"
#include "mongoc-log.h"

#undef MONGOC_LOG_DOMAIN
#define MONGOC_LOG_DOMAIN "apple_ssl"

#define SSL_LOG             0
#define FAKE_SSL            0

static char charFromInt(unsigned char value)
{
    if (value <= 9) {
        return '0' + value;
    } else if (value <= 0xF) {
        return 'A' + value - 10;
    } else {
        return '.';
    }
}

static void hexLine(char *line, const unsigned char *buffer, size_t size, size_t group)
{
    size_t ii;
    
    for (ii = 0; ii < size; ii++) {
        if (buffer[ii] <= 0x0F) {
            line[0] = '0';
        } else {
            line[0] = charFromInt(buffer[ii] >> 4);
        }
        line++;
        line[0] = charFromInt(buffer[ii] & 0xF);
        line++;
        if (group > 0 && ((ii + 1) % group) == 0) {
            line[0] = ' ';
            line++;
        }
    }
    line[0] = 0;
}

static void charLine(char *line, const unsigned char *buffer, size_t size, size_t group)
{
    size_t ii;
    
    for (ii = 0; ii < size; ii++) {
        if (buffer[ii] <= ' ' || buffer[ii] >= 0x80) {
            line[0] = '.';
        } else {
            line[0] = buffer[ii];
        }
        line++;
        if (group > 0 && ((ii + 1) % group) == 0) {
            line[0] = ' ';
            line++;
        }
    }
    line[0] = 0;
}

static void print_buffer(const char *prefix, const unsigned char *buffer, size_t size, size_t charPerLine)
{
    char line[128];
    char padding[64];
    size_t ii;
    
    if (charPerLine == 0) {
        charPerLine = 16;
    }
    for (ii = 0; ii < size; ii += charPerLine) {
        if (prefix) {
            printf("%s ", prefix);
        }
        printf("%c", charFromInt((ii / 0x1000) & 0xF));
        printf("%c", charFromInt((ii / 0x100) & 0xF));
        printf("%c", charFromInt((ii / 0x10) & 0xF));
        printf("%c", charFromInt((ii / 0x1) & 0xF));
        printf(" ");
        hexLine(line, buffer + ii, ((size - ii) > charPerLine)?charPerLine:(size - ii), 4);
        sprintf(padding, "%%-%lds", charPerLine * 2 + (charPerLine / 4));
        printf(padding, line);
        charLine(line, buffer + ii, ((size - ii) > charPerLine)?charPerLine:(size - ii), 4);
        printf("%s\n", line);
    }
}

static void print_iov(const char *action, mongoc_iovec_t *iov, size_t iovcnt)
{
    size_t ii;
    size_t total = 0;
    struct timeval current_time;
    
    gettimeofday(&current_time, NULL);
    printf("=> %s (%ld):                   %ld %d\n", action, iovcnt, current_time.tv_sec, current_time.tv_usec);
    for (ii = 0; ii < iovcnt; ii++) {
        char buffer[256];
        
        sprintf(buffer, "iov #%zu (%zu)", ii, iov[ii].iov_len);
        print_buffer(buffer, iov[ii].iov_base, iov[ii].iov_len, 16);
        total += iov[ii].iov_len;
    }
    printf("total %ld\n", total);
}

/**
 * mongoc_stream_apple_tls_t:
 *
 * Private storage for handling callbacks from mongoc_stream and BIO_*
 *
 * The one funny wrinkle comes with timeout, which we use statefully to
 * statefully pass timeouts through from the mongoc-stream api.
 *
 * TODO: is there a cleaner way to manage that?
 */
typedef struct
{
   mongoc_stream_t  parent;
   mongoc_stream_t *base_stream;
   SSLContextRef    context;
   int32_t          timeout_msec;
   bool             weak_cert_validation;
} mongoc_stream_apple_tls_t;


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_tls_destroy --
 *
 *       Cleanup after usage of a mongoc_stream_apple_tls_t. Free all allocated
 *       resources and ensure connections are closed.
 *
 * Returns:
 *       None.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static void
_mongoc_stream_tls_destroy (mongoc_stream_t *stream)
{
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

   BSON_ASSERT (tls);

   CFRelease(tls->context);

   mongoc_stream_destroy (tls->base_stream);
   tls->base_stream = NULL;

   bson_free (stream);

   mongoc_counter_streams_active_dec();
   mongoc_counter_streams_disposed_inc();
}


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_tls_close --
 *
 *       Close the underlying socket.
 *
 *       Linus dictates that you should not check the result of close()
 *       since there is a race condition with EAGAIN and a new file
 *       descriptor being opened.
 *
 * Returns:
 *       0 on success; otherwise -1.
 *
 * Side effects:
 *       The BIO fd is closed.
 *
 *--------------------------------------------------------------------------
 */

static int
_mongoc_stream_tls_close (mongoc_stream_t *stream)
{
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

   BSON_ASSERT (tls);

   return mongoc_stream_close (tls->base_stream);
}


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_tls_flush --
 *
 *       Flush the underlying stream.
 *
 * Returns:
 *       0 if successful; otherwise -1.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static int
_mongoc_stream_tls_flush (mongoc_stream_t *stream)
{
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

   return mongoc_stream_flush(tls->base_stream);
}


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_tls_writev --
 *
 *       Write the iovec to the stream. This function will try to write
 *       all of the bytes or fail. If the number of bytes is not equal
 *       to the number requested, a failure or EOF has occurred.
 *
 * Returns:
 *       -1 on failure, otherwise the number of bytes written.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static ssize_t
_mongoc_stream_tls_writev (mongoc_stream_t *stream,
                           mongoc_iovec_t  *iov,
                           size_t           iovcnt,
                           int32_t          timeout_msec)
{
    mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;
    size_t total;
    
#if FAKE_SSL
    total = mongoc_stream_writev(tls->base_stream, iov, iovcnt, timeout_msec);
#else
    OSStatus error;
    size_t ii, read_ret;
    
    tls->timeout_msec = timeout_msec;
    total = 0;
    for (ii = 0; ii < iovcnt; ii++) {
        error = SSLWrite(tls->context, iov[ii].iov_base, iov[ii].iov_len, &read_ret);
        if (noErr != error) {
            MONGOC_ERROR("write error %d errno %d", (int)error, errno);
            return -1;
        } else {
            total += read_ret;
        }
    }
#endif
#if SSL_LOG
    print_iov("write" , iov, iovcnt);
#endif
    return total;
}


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_tls_readv --
 *
 *       Read from the stream into iov. This function will try to read
 *       all of the bytes or fail. If the number of bytes is not equal
 *       to the number requested, a failure or EOF has occurred.
 *
 * Returns:
 *       -1 on failure, 0 on EOF, otherwise the number of bytes read.
 *
 * Side effects:
 *       iov buffers will be written to.
 *
 *--------------------------------------------------------------------------
 */

static ssize_t
_mongoc_stream_tls_readv (mongoc_stream_t *stream,
                          mongoc_iovec_t  *iov,
                          size_t           iovcnt,
                          size_t           min_bytes,
                          int32_t          timeout_msec)
{
    mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;
    size_t total;
    
#if FAKE_SSL
    total = mongoc_stream_readv(tls->base_stream, iov, iovcnt, min_bytes, timeout_msec);
#else
    size_t ii, read_ret;
    OSStatus error;
    
    total = 0;
    for (ii = 0; ii < iovcnt; ii++) {
        size_t read_for_iov = 0;
        
        // make sure we totally fill up each buffer before going for the next one
        // and read data as long as we are under the min_byte
        while (total < min_bytes && read_for_iov < iov[ii].iov_len) {
            size_t iov_size_available = iov[ii].iov_len - read_for_iov;
            
            if (iov_size_available > min_bytes - total) {
                // don't ask more than the minimum to avoid being blocked
                // SSL will try to fill up the rest (even if there is not enough)
                iov_size_available = min_bytes - total;
            }
            error = SSLRead(tls->context, iov[ii].iov_base + read_for_iov, iov_size_available, &read_ret);
            if (noErr != error) {
                MONGOC_ERROR("read error %d errno %d", (int)error, errno);
            } else {
                total += read_ret;
                read_for_iov += read_ret;
                if (total >= min_bytes) {
                    // if we have enough, don't call again read
                    // the SSL lib might wait for more data
                    break;
                }
            }
        }
    }
#endif
#if SSL_LOG
    print_iov("read" , iov, iovcnt);
    printf("read min %zu => total %zu\n", min_bytes, total);
#endif
    return total;
}


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_tls_setsockopt --
 *
 *       Perform a setsockopt on the underlying stream.
 *
 * Returns:
 *       -1 on failure, otherwise opt specific value.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static int
_mongoc_stream_tls_setsockopt (mongoc_stream_t *stream,
                               int              level,
                               int              optname,
                               void            *optval,
                               socklen_t        optlen)
{
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

   BSON_ASSERT (tls);

   return mongoc_stream_setsockopt (tls->base_stream,
                                    level,
                                    optname,
                                    optval,
                                    optlen);
}


/**
 * mongoc_stream_tls_do_handshake:
 *
 * force an ssl handshake
 *
 * This will happen on the first read or write otherwise
 */
bool
mongoc_stream_tls_do_handshake (mongoc_stream_t *stream,
                                int32_t          timeout_msec)
{
#if FAKE_SSL
   return true;
#else
   OSStatus error;
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

   BSON_ASSERT (tls);

   tls->timeout_msec = timeout_msec;

   error = SSLHandshake(tls->context);
   if (error == noErr) {
      return true;
   }

   MONGOC_ERROR("handshake error %d", (int)error);
   if (!errno) {
      errno = ETIMEDOUT;
   }

   return false;
#endif
}

/**
 * mongoc_stream_tls_check_cert:
 *
 * check the cert returned by the other party
 */
bool
mongoc_stream_tls_check_cert (mongoc_stream_t *stream,
                              const char      *host)
{
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

   BSON_ASSERT (tls);
   BSON_ASSERT (host);

    if (tls->weak_cert_validation) {
        return true;
    }
    
    bool result = false;
    SecCertificateRef leaf_cert = NULL;
    SecTrustRef trust = NULL;
    OSStatus ret = SSLCopyPeerTrust(tls->context, &trust);
    CFStringRef cfHost = CFStringCreateWithCString(kCFAllocatorDefault, host, kCFStringEncodingUTF8);
    
    if (ret != noErr || trust == NULL) {
        MONGOC_ERROR("error getting certifictate chain");
        goto out;
    }
    
    /* enable default root / anchor certificates */
    ret = SecTrustSetAnchorCertificates(trust, NULL);
    if (ret != noErr) {
        MONGOC_ERROR("error setting anchor certificates");
        goto out;
    }
    
    SecTrustResultType trust_eval_result = 0;
    
    ret = SecTrustEvaluate(trust, &trust_eval_result);
    if (ret != noErr) {
        MONGOC_ERROR("error calling SecTrustEvaluate");
        goto out;
    }
    
    switch (trust_eval_result) {
            case kSecTrustResultUnspecified:
            case kSecTrustResultProceed:
            result = true;
            goto out;
            
            case kSecTrustResultRecoverableTrustFailure:
            case kSecTrustResultDeny:
        default:
            MONGOC_ERROR("cerfificate verification failed, result is %d", trust_eval_result);
    }
    
    if (SecTrustGetCertificateCount(trust) == 0) {
        result = false;
        goto out;
    }
    
    leaf_cert = SecTrustGetCertificateAtIndex(trust, 0);
    CFRetain(leaf_cert);
    
out:
    if (trust) CFRelease(trust);
    
    if (cfHost) CFRelease(cfHost);
    if (leaf_cert) CFRelease(leaf_cert);
    
    return result;
}


static mongoc_stream_t *
_mongoc_stream_tls_get_base_stream (mongoc_stream_t *stream)
{
   return ((mongoc_stream_apple_tls_t *)stream)->base_stream;
}


static OSStatus mongocSSLReadFunc(SSLConnectionRef connection, void *data, size_t *dataLength)
{
    mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)connection;
    mongoc_iovec_t iov;
    ssize_t readLength;
    
    iov.iov_base = data;
    iov.iov_len = *dataLength;
    readLength = mongoc_stream_readv(tls->base_stream, &iov, 1, *dataLength, tls->timeout_msec);
    *dataLength = readLength;
    return noErr;
}

static OSStatus mongocSSLWriteFunc(SSLConnectionRef connection, const void *data, size_t *dataLength)
{
    mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)connection;
    mongoc_iovec_t iov;
    ssize_t writeLength;
    
    iov.iov_base = (char *)data;
    iov.iov_len = *dataLength;
    writeLength = mongoc_stream_writev(tls->base_stream, &iov, 1, tls->timeout_msec);
    *dataLength = writeLength;
    return noErr;
}

/*
 *--------------------------------------------------------------------------
 *
 * mongoc_stream_tls_new --
 *
 *       Creates a new mongoc_stream_apple_tls_t to communicate with a remote
 *       server using a TLS stream.
 *
 *       @base_stream should be a stream that will become owned by the
 *       resulting tls stream. It will be used for raw I/O.
 *
 *       @trust_store_dir should be a path to the SSL cert db to use for
 *       verifying trust of the remote server.
 *
 * Returns:
 *       NULL on failure, otherwise a mongoc_stream_t.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

mongoc_stream_t *
mongoc_stream_tls_new (mongoc_stream_t  *base_stream,
                       mongoc_ssl_opt_t *opt,
                       int               client)
{
   mongoc_stream_apple_tls_t *tls;

   BSON_ASSERT(base_stream);
   BSON_ASSERT(opt);

   tls = bson_malloc0 (sizeof *tls);
   tls->base_stream = base_stream;
   tls->parent.type = MONGOC_STREAM_TLS;
   tls->parent.destroy = _mongoc_stream_tls_destroy;
   tls->parent.close = _mongoc_stream_tls_close;
   tls->parent.flush = _mongoc_stream_tls_flush;
   tls->parent.writev = _mongoc_stream_tls_writev;
   tls->parent.readv = _mongoc_stream_tls_readv;
   tls->parent.setsockopt = _mongoc_stream_tls_setsockopt;
   tls->parent.get_base_stream = _mongoc_stream_tls_get_base_stream;
   tls->weak_cert_validation = opt->weak_cert_validation;
   tls->timeout_msec = -1;

   tls->context = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
   SSLSetIOFuncs(tls->context, mongocSSLReadFunc, mongocSSLWriteFunc);
   SSLSetSessionOption(tls->context, kSSLSessionOptionBreakOnClientAuth, opt->weak_cert_validation);
   SSLSetConnection(tls->context, tls);

   mongoc_counter_streams_active_inc();

   return (mongoc_stream_t *)tls;
}
