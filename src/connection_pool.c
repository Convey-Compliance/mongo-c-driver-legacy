#include "connection_pool.h"

static int connectToReplicaSet( mongo *conn, const char *replicaName, char *hosts ) {
  char *hostPortPair = strtok( hosts, "," ), host[MAXHOSTNAMELEN];
  int port = MONGO_DEFAULT_PORT;

  mongo_replica_set_init( conn, replicaName );
  while( hostPortPair != NULL ) {
    sscanf( hostPortPair, "%[^:]:%d", host, &port );
    mongo_replica_set_add_seed( conn, host, port );
    hostPortPair = strtok( NULL, "," );
    port = MONGO_DEFAULT_PORT; /* reset port to default */
  }
  return mongo_replica_set_client( conn );
}

static int authenticate( mongo_connection *conn, const char *connectionString ) {
  char user[MAX_USER_LEN] = {'\0'}, pass[MAX_PASS_LEN] = {'\0'}, db[MAX_DB_LEN] = {'\0'};
  int credentialsScanned = sscanf( connectionString, "mongodb://%[^:]:%[^@]@%*[^/]/%[^?]?", user, pass, db );

  if( credentialsScanned != 3 ) {
    /* not all of required credentials exists */
    conn->err = MONGO_INVALID_CONNECTION_STRING;
    return MONGO_ERROR;
  }
  return mongo_cmd_authenticate( conn->conn, db, user, pass );
}

MONGO_EXPORT int mongo_connection_connect( mongo_connection *conn ) {
  int multipleHostsProvided, needToAuth, res;
  char *hosts, replicaName[MAX_REPLICA_NAME_LEN] = {'\0'};

  if( conn->conn->connected ) return MONGO_OK;
  
  hosts = ( char* )bson_malloc( sizeof(char) * strlen( conn->pool->cs ) );
  sscanf( conn->pool->cs, "mongodb://%[^/]/%*[^?]?replicaSet=%s", hosts, replicaName );
  needToAuth = (strchr( hosts, '@' ) != NULL); /* Moved out of conditional to avoid MSVC warnings... bummer */
  if( needToAuth )
  {
    /* remove user and pass */
    strcpy( hosts, strchr( hosts, '@' ) + 1 );
  }
  multipleHostsProvided = strchr( hosts, ',' ) != NULL;

  do {
    if( hosts[0] == '\0' || /* required */
      ( multipleHostsProvided && replicaName[0] == '\0' )) /* replica set name required if multiple hosts specified */
    {
      conn->err = MONGO_INVALID_CONNECTION_STRING;
      res = MONGO_ERROR;
      break;
    }

    if( !multipleHostsProvided )
    {
      /* single server */
      char host[MAXHOSTNAMELEN];
      int port = MONGO_DEFAULT_PORT;

      sscanf( hosts, "%[^:]:%d", host, &port );
      res = mongo_client( conn->conn, host, port );
    }
    else
    {
      res = connectToReplicaSet( conn->conn, replicaName, hosts );
    }
    if( needToAuth && res == MONGO_OK )
      res = authenticate( conn, conn->pool->cs );
  } while( 0 );

  bson_free( hosts );
  return res;
}

MONGO_EXPORT int mongo_connection_reconnect( mongo_connection *conn ) {
  return mongo_reconnect( conn->conn ) == MONGO_OK && authenticate( conn, conn->pool->cs ) == MONGO_OK ? MONGO_OK : MONGO_ERROR;
}

MONGO_EXPORT void mongo_connection_disconnect( mongo_connection *conn ) {
  mongo_disconnect( conn->conn );
}

static mongo_connection* removeFirst( mongo_connection_pool *pool ) {
  mongo_connection *res = pool->head;

  spinLock_lock( &pool->lock );

  pool->head = pool->head->next;

  spinlock_unlock( &pool->lock );  

  return res;
}

static mongo_connection* mongo_connection_new() {
  return ( mongo_connection* )bson_malloc( sizeof( mongo_connection ) );
}

static void mongo_connection_delete( mongo_connection* _this ) {
  mongo_destroy( _this->conn );
  bson_free( _this );
}

static mongo_connection_pool* mongo_connection_pool_new() {
  return ( mongo_connection_pool* )bson_malloc( sizeof( mongo_connection_pool ) );
}

static void mongo_connection_pool_delete( mongo_connection_pool *_this ) {
  mongo_connection *conn = _this->head;
  while( conn != NULL) {
    mongo_connection *next = conn->next;
    mongo_connection_delete( conn );
    conn = next;
  }
  bson_free( _this );
}

MONGO_EXPORT mongo_connection* mongo_connection_pool_acquire( mongo_connection_pool *pool ) {
  mongo_connection *res;
  if( pool->head == NULL ) {
    /* create new connection */
    res = mongo_connection_new();
    res->err = MONGO_CONNECTION_SUCCESS;
    res->pool = pool;    
    mongo_connection_connect( res );
  } else /* return first from pool */
    res = removeFirst( pool );

  res->next = NULL;
  return res;
}

MONGO_EXPORT void mongo_connection_pool_release( mongo_connection_pool *pool, mongo_connection *conn ) {
  spinLock_lock( &pool->lock );

  /* insert at the beginning of the pool */
  conn->next = pool->head;
  pool->head = conn;

  spinlock_unlock( &pool->lock );  
}

MONGO_EXPORT void mongo_connection_dictionary_init( mongo_connection_dictionary *dict ) {
  dict->head = NULL;
  spinLock_init( &dict->lock );  
}

MONGO_EXPORT void mongo_connection_dictionary_destroy( mongo_connection_dictionary *dict ) {
  mongo_connection_pool *pool = dict->head;
  while( pool != NULL ) {
    mongo_connection_pool *next = pool->next;
    mongo_connection_pool_delete( pool );
    pool = next;
  }
}

static void addToDictionary( mongo_connection_dictionary *dict, mongo_connection_pool *pool, mongo_connection_pool *lastPoolInDict ) 
{   
  spinLock_lock( &(dict->lock) );    

  /* insert at the end of dictionary */
  if( dict->head == NULL )
    dict->head = pool;
  else
    lastPoolInDict->next = pool;

  spinlock_unlock( &(dict->lock) );
}

MONGO_EXPORT mongo_connection_pool* mongo_connection_dictionary_get_pool( mongo_connection_dictionary *dict, char *cs ) {
  mongo_connection_pool *pool = dict->head, *lastPoolInDict = pool;

  /* find in dictionary by connection string */
  while( pool != NULL ) {
    lastPoolInDict = pool;
    if( strcmp( cs, pool->cs ) == 0 ) break; /* found */
    pool = pool->next;
  }

  if( pool == NULL ) {
    /* create new pool object */
    pool = mongo_connection_pool_new();
    pool->head = NULL;
    pool->cs = cs;
    pool->next = NULL;    
    spinLock_init( &pool->lock );

    addToDictionary( dict, pool, lastPoolInDict );
  }

  return pool;
}