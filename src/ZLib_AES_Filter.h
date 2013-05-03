/*
  Copyright (C) 2013 Convey Compliance Systems, Inc.  All rights reserved.

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Jose Sebastian Battig
  jsbattig@gmail.com
  jsbattig@convey.com

*/

/*
  
  This module provides a sample of how to hook Compression and/or Encryption to GridFS chunks
  using GridFS feature to register "filters" with GridFS files

  To use this software as written you need to obtain ZLib libraries from https://github.com/madler/zlib.git 
  and fast AES encryption algorithm from  https://github.com/Convey-Compliance/fast-aes.git 

  Feel free to use this software as a template to create your own filtering capabilities

*/

#ifndef PREPOSTCHUNKPROCESSING_H_
#define PREPOSTCHUNKPROCESSING_H_

MONGO_EXTERN_C_START

#include "bson.h"

#define GRIDFILE_COMPRESS 2
#define GRIDFILE_ENCRYPT 4

#define AES_BLOCK_SIZE 16
#define AES_CRYPTO_KEY_SIZE 16

typedef struct {
  FILTER_CONTEXT_CALLBACKS; /* Base "Class" expansion */
  void* targetBuffer; /* Special general purpose buffer, for Zlib and Decryption on certain cases */
  size_t targetBuffer_size; /* Allocated buffer size */
  void* targetDecryptBuffer; /* Dedicated buffer for decryption operations */ 
  char crypto_key[AES_CRYPTO_KEY_SIZE]; /* AES 128bits Encryption vector */
} ZLib_AES_filterContext;

/**
 *  Use this function to initialize ZLib & AES filtering as default filtering schema.
 *  Be careful when using this option!! The code is not thread safe. In multi-threaded solutions
 *  filtering must be local and set to the GridFile level, never at a global level
 *  Returns error state. Zero means success
 *  @param flags - flags can be used for any purpose. In the case of this extension it has no use 
 */
MONGO_EXPORT int init_ZLib_AES_filtering( int flags );
/**
 *  Returns a pointer to a ZLib_AES filtering object
 *  @param flags - custom use flags. No use for this function
 */
MONGO_EXPORT void* create_ZLib_AES_filter_context( int flags );
/**
 *  Destroys a ZlibAES filtering object freeing also all cached buffer memory 
 *  @param context - pointer to the ZlibAES filtering object
 *  @param flags - no use in this context 
 */
MONGO_EXPORT void destroy_ZLib_AES_filter_context( void* context, int flags );
/**
 *  Initialized initial encryption vector with an MD5 hash obtained from the passphrase 
 *  @param context - pointer to the ZlibAES filtering object
 *  @param passphrase - string used to create the initial encryption vector for AES algorihtm
 */
MONGO_EXPORT void ZLib_AES_filter_context_set_encryption_key( void* context, const char* passphrase );

MONGO_EXTERN_C_END
#endif