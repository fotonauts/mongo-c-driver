/*
 * Copyright 2013 10gen Inc.
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


#include "mongoc-stream-gridfs.h"


typedef struct
{
   mongoc_stream_t  vtable;
   char            *collection;
   char            *filename;
} mongoc_stream_gridfs_t;


static void
mongoc_stream_gridfs_destroy (mongoc_stream_t *stream) /* IN */
{
   mongoc_stream_gridfs_t *gstream = (mongoc_stream_gridfs_t *)stream;

   bson_return_if_fail(stream);

   bson_free(gstream->collection);
   bson_free(gstream->filename);
   bson_free(gstream);
}


/*
 *--------------------------------------------------------------------------
 *
 * mongoc_stream_gridfs_new --
 *
 *       Creates a new mongoc_stream_t that can read and/or write from a
 *       GridFS file contained in a MongoDB collection.
 *
 * Returns:
 *       A newly allocated mongoc_stream_t that should be freed with
 *       mongoc_stream_destroy().
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

mongoc_stream_t *
mongoc_stream_gridfs_new (const mongoc_gridfs_file_t *file, /* IN */
                          int                         mode) /* IN */
{
   mongoc_stream_gridfs_t *stream;

   bson_return_val_if_fail(file, NULL);
   bson_return_val_if_fail((mode & O_RDWR), NULL);

   stream = bson_malloc0(sizeof *stream);

#if 0
   stream.vtable.readv = mongoc_stream_gridfs_readv;
#endif

   return (mongoc_stream_t *)stream;
}
