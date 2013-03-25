#include "gridfs.h"
#include "prepostChunkProcessing.h"
#include "zlib.h"

static int ZlibPreProcessChunk(char** targetBuf, size_t* targetLen, const char* srcBuf, size_t srcLen, int flags) {
  uLongf tmpLen = compressBound( DEFAULT_CHUNK_SIZE );
  if( flags & GRIDFILE_COMPRESS ) {    
    if( *targetBuf == NULL ) {
      *targetBuf = (char*)bson_malloc( tmpLen );
    }
    if( compress2( (Bytef*)(*targetBuf), &tmpLen, (Bytef*)srcBuf, (uLong)srcLen, Z_BEST_SPEED ) != Z_OK ) {
      return -1;
    }    
    *targetLen = (size_t)tmpLen;
  } else {
    *targetBuf = (char*)srcBuf;
    *targetLen = srcLen;
  }
  return 0;
}

static int ZlibPostProcessChunk(char** targetBuf, size_t* targetLen, const char* srcData, size_t srcLen, int flags) {   
  uLongf tmpLen = DEFAULT_CHUNK_SIZE;
  if( flags & GRIDFILE_COMPRESS ) {  
    if( *targetBuf == NULL ) {
      *targetBuf = (void*)bson_malloc( tmpLen );
    }  
    if (uncompress( (Bytef*)(*targetBuf), &tmpLen, (Bytef*)srcData, (uLong)srcLen ) != Z_OK ) {
      return -1;
    }
    *targetLen = (size_t)tmpLen;
  } else {
    *targetBuf = (char*)srcData;
    *targetLen = srcLen;
  }
  return 0;
}

static size_t ZlibPendingDataNeededSize (int flags) {
  if( flags & GRIDFILE_COMPRESS ) {
    return compressBound( DEFAULT_CHUNK_SIZE );
  } else {
    return DEFAULT_CHUNK_SIZE;
  }
}

MONGO_EXPORT int initPrepostChunkProcessing( int flags ){
  gridfs_set_chunk_filter_funcs( ZlibPreProcessChunk, ZlibPostProcessChunk, ZlibPendingDataNeededSize );  
  return 0;
}

