#include "bson.h"
#include "md5.h"
#include "gridfs.h"
#include "ZLib_AES_Filter.h"

/* ZLib libraries @ https://github.com/madler/zlib.git */
#include "zlib.h"
/* Fast rijndael @ https://github.com/Convey-Compliance/fast-aes.git */
#include "rijndael-alg-fst.h"

#define ALIGN_TO_AES_BLOCK_SIZE(N) N = ( (N + AES_BLOCK_SIZE - 1) & ~(AES_BLOCK_SIZE - 1) )
#define AES_128BITSKEY_ROUNDS 10
#define AES_MONGO_KEY_SIZE 128

/* ----------------- */
/* Private functions */
/* ----------------- */

static char* bufferFromContext( void* context, size_t tmpLen, int flags ) {
  if( ((ZLib_AES_filterContext*)context)->targetBuffer_size < tmpLen ) ((ZLib_AES_filterContext*)context)->reset_context( context, flags );
  if( !((ZLib_AES_filterContext*)context)->targetBuffer ) {
    ((ZLib_AES_filterContext*)context)->targetBuffer = bson_malloc( tmpLen );
  }
  return (char*)((ZLib_AES_filterContext*)context)->targetBuffer;
}

#define XOR_AES_BLOCK(TARGET, SOURCE) {\
  *(__int64*)(TARGET) ^= *(__int64*)(SOURCE); \
  *(__int64*)((TARGET) + sizeof(__int64)) ^= *(__int64*)((SOURCE) + sizeof(__int64)); \
}

static int Zlib_AES_PreProcessChunk(void* context, char** targetBuf, size_t* targetLen, const char* srcBuf, size_t srcLen, int flags) {
  uLongf tmpLen = compressBound( DEFAULT_CHUNK_SIZE ) + AES_BLOCK_SIZE;
  
  ALIGN_TO_AES_BLOCK_SIZE( tmpLen ); /* Let's make sure we have enough space for AES encryption of full blocks */
  if( flags & GRIDFILE_COMPRESS || flags & GRIDFILE_ENCRYPT ) {    
    *targetBuf = bufferFromContext( context, tmpLen, flags );    
    
    if( flags & GRIDFILE_COMPRESS ) {
      if( compress2( (Bytef*)(*targetBuf), &tmpLen, (Bytef*)srcBuf, (uLong)srcLen, Z_BEST_SPEED ) != Z_OK ) return -1;
    } else {
      tmpLen = (uLongf)srcLen;
      memmove( *targetBuf, srcBuf, srcLen ); /* We need to move the data to targetBuf to implement CBC encryption */
    }
    
    if( flags & GRIDFILE_ENCRYPT ) {
      u8* target = (u8*)*targetBuf;
      size_t loops = tmpLen / AES_BLOCK_SIZE; 
      u32 rk[4 * (AES_128BITSKEY_ROUNDS + 1)];
      u8 lastblock[AES_BLOCK_SIZE];
      u8 lastBlockLen = tmpLen % AES_BLOCK_SIZE;
      int r = rijndaelKeySetupEnc( rk, (const u8*)((ZLib_AES_filterContext*)context)->crypto_key, AES_MONGO_KEY_SIZE ); 
      
      do{
        rijndaelEncrypt( rk, r, target, target );        
        if( --loops > 0 ) XOR_AES_BLOCK( target + AES_BLOCK_SIZE, target ); /* CBC second block and on... */       
        target += AES_BLOCK_SIZE;
      } while( loops > 0 );      
      memset( lastblock + lastBlockLen, 0, sizeof( u8 ) * AES_BLOCK_SIZE - lastBlockLen );
      if( lastBlockLen > 0 ) {
        memmove( lastblock, target, lastBlockLen );
        lastblock[AES_BLOCK_SIZE - 1] = lastBlockLen;
      }
      XOR_AES_BLOCK( lastblock, target - AES_BLOCK_SIZE ); /* CBC last block before encrypting */
      rijndaelEncrypt( rk, r, lastblock, target ); 
      if( lastBlockLen == 0) tmpLen += AES_BLOCK_SIZE;
      else ALIGN_TO_AES_BLOCK_SIZE( tmpLen );
    }
    *targetLen = (size_t)tmpLen;
  } else {
    *targetBuf = (char*)srcBuf;
    *targetLen = srcLen;
  }
  return 0;
}

static void* decryptBufferFromContext( void* context, size_t bufLen ) {
  if( ((ZLib_AES_filterContext*)context)->targetDecryptBuffer == NULL ) ((ZLib_AES_filterContext*)context)->targetDecryptBuffer = bson_malloc( bufLen );  
  return ((ZLib_AES_filterContext*)context)->targetDecryptBuffer;
}

static int Zlib_AES_PostProcessChunk(void* context, char** targetBuf, size_t* targetLen, const char* srcData, size_t srcLen, int flags) {   
  uLongf tmpLen = DEFAULT_CHUNK_SIZE + AES_BLOCK_SIZE; 

  ALIGN_TO_AES_BLOCK_SIZE( tmpLen ); /* Let's make sure we have enough space for AES decryption of full blocks */
  if( flags & GRIDFILE_COMPRESS || flags & GRIDFILE_ENCRYPT ) {      
    *targetBuf = bufferFromContext( context, tmpLen, flags ); 
    if( flags & GRIDFILE_ENCRYPT ) {
      u8* target = (u8*)decryptBufferFromContext( context, tmpLen );
      u8* source = (u8*)*targetBuf;
      size_t n_loop = 0;
      size_t loops = srcLen / AES_BLOCK_SIZE; /* We KNOW the number of blocks is multiple of AES_BLOCK_SIZE */
      u32 rk[4 * (AES_128BITSKEY_ROUNDS + 1)];
      int r = rijndaelKeySetupDec( rk, (const u8*)((ZLib_AES_filterContext*)context)->crypto_key, AES_MONGO_KEY_SIZE ); 
      
      memmove( source, srcData, srcLen ); /* We need to move the source data to keep a copy to implement CBC decryption */      
      do{
        rijndaelDecrypt( rk, r, source, target );                  
        if( n_loop++ > 0 ) XOR_AES_BLOCK( target, source - AES_BLOCK_SIZE ); /* CBC second block and on... */           
        source += AES_BLOCK_SIZE;
        target += AES_BLOCK_SIZE;
      } while( n_loop < loops );
      srcLen -= AES_BLOCK_SIZE - *(target - 1); /* Let's obtain the REAL length of the last block from the last byte of the block and adjust srcLen */
    }
    
    if( flags & GRIDFILE_COMPRESS ) {
      Bytef* source = flags & GRIDFILE_ENCRYPT ? (Bytef*)((ZLib_AES_filterContext*)context)->targetDecryptBuffer : (Bytef*)srcData;  
      
      if (uncompress( (Bytef*)(*targetBuf), &tmpLen, source, (uLong)srcLen ) != Z_OK ) return -1;      
      *targetLen = (size_t)tmpLen;
    } else {
      *targetLen = srcLen;
      *targetBuf = (char*)((ZLib_AES_filterContext*)context)->targetDecryptBuffer; 
    }    
  } else {
    *targetBuf = (char*)srcData;
    *targetLen = srcLen;
  }
  return 0;
}

static size_t Zlib_AES_PendingDataNeededSize (void* context, int flags) {
  if( flags & GRIDFILE_COMPRESS ) return compressBound( DEFAULT_CHUNK_SIZE );
  else return DEFAULT_CHUNK_SIZE;  
}

static void ZLib_AES_reset_context(void* context, int flags){
  if( ((ZLib_AES_filterContext*)context)->targetBuffer ) {
    bson_free( ((ZLib_AES_filterContext*)context)->targetBuffer );
    ((ZLib_AES_filterContext*)context)->targetBuffer = NULL;
    ((ZLib_AES_filterContext*)context)->targetBuffer_size = 0;
  }
  if( ((ZLib_AES_filterContext*)context)->targetDecryptBuffer ) {
    bson_free( ((ZLib_AES_filterContext*)context)->targetDecryptBuffer );
    ((ZLib_AES_filterContext*)context)->targetDecryptBuffer = NULL;
  }
}

static ZLib_AES_filterContext default_zlib_filter;

static void ZLib_AES_init_context(ZLib_AES_filterContext* context) {
  context->pending_data_buffer_size = &Zlib_AES_PendingDataNeededSize;
  context->read_filter = &Zlib_AES_PostProcessChunk;
  context->write_filter = &Zlib_AES_PreProcessChunk;
  context->reset_context = &ZLib_AES_reset_context;
  context->targetBuffer = NULL;
  context->targetBuffer_size = 0;
  context->targetDecryptBuffer = NULL;
  memset(context->crypto_key, 0, sizeof(context->crypto_key));
}

/* -------------------- */
/*   Public functions   */
/* -------------------- */

MONGO_EXPORT int init_ZLib_AES_filtering( int flags ){
  ZLib_AES_init_context(&default_zlib_filter);
  set_global_filter_context( (filterContext*)&default_zlib_filter );  
  return 0;
}

MONGO_EXPORT void* create_ZLib_AES_filter_context( int flags ){
  ZLib_AES_filterContext* context = (ZLib_AES_filterContext*)bson_malloc( sizeof( ZLib_AES_filterContext ) );
  ZLib_AES_init_context( context );
  return context;
}

MONGO_EXPORT void destroy_ZLib_AES_filter_context( void* context, int flags ){
  ZLib_AES_reset_context( context, flags );  
  bson_free( context );
}

MONGO_EXPORT void ZLib_AES_filter_context_set_encryption_key( void* context, const char* passphrase ){
  mongo_md5_state_t md5_state;

  mongo_md5_init( &md5_state );
  mongo_md5_append( &md5_state, (const mongo_md5_byte_t *)passphrase, (int)strlen( passphrase ) );
  mongo_md5_finish( &md5_state, (mongo_md5_byte_t*)((ZLib_AES_filterContext*)context)->crypto_key );
}

