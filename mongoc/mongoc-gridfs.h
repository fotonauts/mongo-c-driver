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


#ifndef MONGOC_GRIDFS_H
#define MONGOC_GRIDFS_H


#include <bson.h>

#include "mongoc-stream.h"


BSON_BEGIN_DECLS


typedef struct _mongoc_gridfs_t       mongoc_gridfs_t;
typedef struct _mongoc_gridfs_chunk_t mongoc_gridfs_chunk_t;
typedef struct _mongoc_gridfs_file_t  mongoc_gridfs_file_t;


mongoc_gridfs_file_t *mongoc_gridfs_create_file (mongoc_gridfs_t *gridfs);


void mongoc_gridfs_file_set_filename     (mongoc_gridfs_file_t *file,
                                          const char           *filename);
void mongoc_gridfs_file_set_content_type (mongoc_gridfs_file_t *file,
                                          const char           *content_type);


mongoc_stream_t *mongoc_gridfs_file_write (mongoc_gridfs_file_t *file);
mongoc_stream_t *mongoc_gridfs_file_read  (mongoc_gridfs_file_t *file);


void mongoc_gridfs_destroy       (mongoc_gridfs_t      *gridfs);
void mongoc_gridfs_chunk_destroy (mongoc_gridfs_t      *gridfs);
void mongoc_gridfs_file_destroy  (mongoc_gridfs_file_t *file);


BSON_END_DECLS


#endif /* MONGOC_GRIDFS_H */
