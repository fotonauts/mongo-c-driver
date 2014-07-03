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
#define MONGOC_LOG_DOMAIN "stream-tls"

#define NO_MAC_SSL 0

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

static void print_buffer(const unsigned char *buffer, size_t size, size_t charPerLine)
{
    char line[128];
    char padding[64];
    size_t ii;
    
    for (ii = 0; ii < size; ii += charPerLine) {
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
    
    printf("=> %s (%ld):\n", action, iovcnt);
    for (ii = 0; ii < iovcnt; ii++) {
        print_buffer(iov[ii].iov_base, iov[ii].iov_len, 16);
    }
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
    print_iov("write", iov, iovcnt);
#if NO_MAC_SSL
    mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;
    ssize_t writeLength;
    
    writeLength = mongoc_stream_writev(tls->base_stream, iov, iovcnt, timeout_msec);
    return writeLength;
#elif 1
    mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;
    size_t ii, read_ret, total;
    
    total = 0;
    for (ii = 0; ii < iovcnt; ii++) {
        if (noErr != SSLWrite(tls->context, iov[ii].iov_base, iov[ii].iov_len, &read_ret)) {
            print_iov("write error1 ", iov, iovcnt);
            return -1;
        } else {
            total += read_ret;
        }
    }
    print_iov("write ", iov, iovcnt);
    return total;
#else
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;
   ssize_t ret = 0;
   size_t i;
   size_t iov_pos = 0;
   size_t write_ret;

   int64_t now;
   int64_t expire = 0;

   BSON_ASSERT (tls);
   BSON_ASSERT (iov);
   BSON_ASSERT (iovcnt);

   tls->timeout_msec = timeout_msec;

   if (timeout_msec >= 0) {
      expire = bson_get_monotonic_time () + (timeout_msec * 1000UL);
   }

   for (i = 0; i < iovcnt; i++) {
      iov_pos = 0;

      while (iov_pos < iov[i].iov_len) {
          OSStatus status;
          
          status = SSLWrite(tls->context, (char *)iov[i].iov_base + iov_pos, (int)(iov[i].iov_len - iov_pos), &write_ret);
//          printf("SSL did write: asked %d read %ld status %d (i %ld iov_len %ld iov_pos %ld)\n", (int)(iov[i].iov_len - iov_pos), write_ret, (int)status, i, iov[i].iov_len, iov_pos);

          if (status != noErr) {
              return -1;
          }

         if (expire) {
            now = bson_get_monotonic_time ();

            if ((expire - now) < 0) {
               if (write_ret == 0) {
                  mongoc_counter_streams_timeout_inc();
#ifdef _WIN32
                  errno = WSAETIMEDOUT;
#else
                  errno = ETIMEDOUT;
#endif
                  return -1;
               }

               tls->timeout_msec = 0;
            } else {
               tls->timeout_msec = (int32_t)(expire - now);
            }
         }

         ret += write_ret;
         iov_pos += write_ret;
      }
   }

   if (ret >= 0) {
      mongoc_counter_streams_egress_add(ret);
   }

   return ret;
#endif
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
#if NO_MAC_SSL
    mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;
    ssize_t readLength;
    
    readLength = mongoc_stream_readv(tls->base_stream, iov, iovcnt, min_bytes, timeout_msec);
    print_iov("read", iov, iovcnt);
    return readLength;
#elif 1
    mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;
    size_t ii, read_ret, total;
    
    total = 0;
    for (ii = 0; ii < iovcnt; ii++) {
        if (noErr != SSLRead(tls->context, iov[ii].iov_base, iov[ii].iov_len, &read_ret)) {
            print_iov("read error1 ", iov, iovcnt);
            return -1;
        } else {
            total += read_ret;
        }
    }
    print_iov("read", iov, iovcnt);
    return total;
#else
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;
   ssize_t ret = 0;
   size_t i;
   size_t read_ret;
   size_t iov_pos = 0;
   int64_t now;
   int64_t expire = 0;

   BSON_ASSERT (tls);
   BSON_ASSERT (iov);
   BSON_ASSERT (iovcnt);

   tls->timeout_msec = timeout_msec;

   if (timeout_msec >= 0) {
      expire = bson_get_monotonic_time () + (timeout_msec * 1000UL);
   }

   for (i = 0; i < iovcnt; i++) {
      iov_pos = 0;

      while (iov_pos < iov[i].iov_len) {
          OSStatus status;
          
          status = SSLRead(tls->context, (char *)iov[i].iov_base + iov_pos, (int)(iov[i].iov_len - iov_pos), &read_ret);
          printf("SSL did read: asked %d read %ld status %d\n", (int)(iov[i].iov_len - iov_pos), read_ret, (int)status);

         if (status != noErr) {
            print_iov("read error1 ", iov, iovcnt);
            return -1;
         }

         if (expire) {
            now = bson_get_monotonic_time ();

            if ((expire - now) < 0) {
               if (read_ret == 0) {
                  mongoc_counter_streams_timeout_inc();
#ifdef _WIN32
                  errno = WSAETIMEDOUT;
#else
                  errno = ETIMEDOUT;
#endif
                  print_iov("read error2 ", iov, iovcnt);
                  return -1;
               }

               tls->timeout_msec = 0;
            } else {
               tls->timeout_msec = (int32_t)(expire - now);
            }
         }

         ret += read_ret;

         if ((size_t)ret >= min_bytes) {
            mongoc_counter_streams_ingress_add(ret);
            print_iov("read error3 ", iov, iovcnt);
            return ret;
         }

         iov_pos += read_ret;
      }
   }

   if (ret >= 0) {
      mongoc_counter_streams_ingress_add(ret);
   }

    print_iov("read", iov, iovcnt);
   return ret;
#endif
}


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_tls_cork --
 *
 *       This function is not supported on mongoc_stream_apple_tls_t.
 *
 * Returns:
 *       0 always.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static int
_mongoc_stream_tls_cork (mongoc_stream_t *stream)
{
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

   BSON_ASSERT (stream);

   return mongoc_stream_cork (tls->base_stream);
}


/*
 *--------------------------------------------------------------------------
 *
 * _mongoc_stream_tls_uncork --
 *
 *       The function is not supported on mongoc_stream_apple_tls_t.
 *
 * Returns:
 *       0 always.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

static int
_mongoc_stream_tls_uncork (mongoc_stream_t *stream)
{
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

   BSON_ASSERT (stream);

   return mongoc_stream_uncork (tls->base_stream);
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
#if NO_MAC_SSL
   return true;
#else
   OSStatus error;
   mongoc_stream_apple_tls_t *tls = (mongoc_stream_apple_tls_t *)stream;

   BSON_ASSERT (tls);

   tls->timeout_msec = timeout_msec;

   error = SSLHandshake(tls->context);
    printf("handshake error %d\n", (int)error);
   if (error == noErr) {
      return true;
   }

   if (!errno) {
#ifdef _WIN32
      errno = WSAETIMEDOUT;
#else
      errno = ETIMEDOUT;
#endif
   }

   return false;
#endif
}

static CFDataRef
createDataFromFilename(const char *filename)
{
    int fileDescriptor;
    CFDataRef result = NULL;
    
    fileDescriptor = open(filename, O_RDONLY, 0);
    if (fileDescriptor != -1) {
        struct stat fileStat;
        
        if (stat(filename, &fileStat) != -1) {
            unsigned char *fileContent;
            
            fileContent = mmap(0, (size_t)fileStat.st_size, PROT_READ, MAP_FILE|MAP_PRIVATE, fileDescriptor, 0);
            if (MAP_FAILED != fileContent) {
                result = CFDataCreate(NULL, fileContent, (CFIndex)fileStat.st_size);
                munmap(fileContent, (size_t)fileStat.st_size);
            }
        }
        close(fileDescriptor);
    }
    return result;
}

char *
_mongoc_ssl_extract_subject (const char *filename)
{
    CFDataRef data;
    char *result = NULL;
    
    data = createDataFromFilename(filename);
    if (data) {
        SecCertificateRef certificate;
        
        certificate = SecCertificateCreateWithData(NULL, data);
        if (certificate) {
            CFStringRef subject;
            
            subject = SecCertificateCopySubjectSummary(certificate);
            if (subject) {
                CFIndex length = CFStringGetMaximumSizeForEncoding(CFStringGetLength(subject), kCFStringEncodingUTF8) + 1;
                
                result = bson_malloc(length);
                if (!CFStringGetCString(subject, result, length, kCFStringEncodingUTF8)) {
                    bson_free(result);
                    result = NULL;
                }
                CFRelease(subject);
            }
            CFRelease(certificate);
        }
    }
    CFRelease(data);
    
    return result;
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
#if NO_MAC_SSL
   return true;
#else
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
        printf("error getting certifictate chain\n");
        goto out;
    }
    
    /* enable default root / anchor certificates */
    ret = SecTrustSetAnchorCertificates(trust, NULL);
    if (ret != noErr) {
        printf("error setting anchor certificates\n");
        goto out;
    }
    
    SecTrustResultType trust_eval_result = 0;
    
    ret = SecTrustEvaluate(trust, &trust_eval_result);
    if (ret != noErr) {
        printf("error calling SecTrustEvaluate\n");
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
            printf("cerfificate verification failed, result is %d\n", trust_eval_result);
    }
    
    if (SecTrustGetCertificateCount(trust) == 0) {
        result = false;
        goto out;
    }
    
    leaf_cert = SecTrustGetCertificateAtIndex(trust, 0);
    CFRetain(leaf_cert);
    
out:
    CFRelease(trust);
    
    if (cfHost) CFRelease(cfHost);
    if (leaf_cert) CFRelease(leaf_cert);
    
    return result;
#endif
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
    readLength = mongoc_stream_readv(tls->base_stream, &iov, 1, 0, tls->timeout_msec);
//    printf("SSL wants to read, asked: %ld got: %ld\n", *dataLength, readLength);
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
//    printf("SSL wants to write, asked: %ld got: %ld\n", *dataLength, writeLength);
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
   tls->parent.cork = _mongoc_stream_tls_cork;
   tls->parent.uncork = _mongoc_stream_tls_uncork;
   tls->parent.setsockopt = _mongoc_stream_tls_setsockopt;
   tls->parent.get_base_stream = _mongoc_stream_tls_get_base_stream;
   tls->weak_cert_validation = opt->weak_cert_validation;
   tls->timeout_msec = -1;

   tls->context = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
   SSLSetIOFuncs(tls->context, mongocSSLReadFunc, mongocSSLWriteFunc);
   SSLSetConnection(tls->context, tls);
   SSLSetSessionOption(tls->context, kSSLSessionOptionBreakOnClientAuth, opt->weak_cert_validation);

   mongoc_counter_streams_active_inc();

   return (mongoc_stream_t *)tls;
}
