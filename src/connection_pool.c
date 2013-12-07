#include "connection_pool.h"

#define SPINLOCK_LOCKED 1
#define SPINLOCK_UNLOCKED 0
#define SPINS_BETWEEN_THREADSWITCH 1000

static void spin( int *spinCount ) {
  if( (*spinCount)++ > SPINS_BETWEEN_THREADSWITCH ) {
    SwitchToThread();
    *spinCount = 0;
  }
}

static void spinLock( LONG *lock ) {
  int spins = 0;
  while ( InterlockedCompareExchange( lock, SPINLOCK_LOCKED, SPINLOCK_UNLOCKED ) != SPINLOCK_UNLOCKED ) {
    spin( &spins );  
  };
}

static void spinUnlock( LONG *lock ) {
  int spins = 0;
  while ( InterlockedCompareExchange( lock, SPINLOCK_UNLOCKED, SPINLOCK_LOCKED ) != SPINLOCK_LOCKED ) {
    spin( &spins );
  };
}

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
  char *hosts = ( char* )malloc( sizeof(char) * strlen( conn->pool->cs ) ), replicaName[MAX_REPLICA_NAME_LEN] = {'\0'};

  sscanf( conn->pool->cs, "mongodb://%[^/]/%*[^?]?replicaSet=%s", hosts, replicaName );
  if( needToAuth = strchr( hosts, '@' ) != NULL)
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

  free( hosts );
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

  spinLock( &pool->lock );

  pool->head = pool->head->next;

  spinUnlock( &pool->lock );  

  return res;
}

MONGO_EXPORT mongo_connection* mongo_connection_pool_acquire( mongo_connection_pool *pool ) {
  mongo_connection *res;
  if( pool->head == NULL ) {
    /* create new connection */
    res = ( mongo_connection* )bson_malloc( sizeof( mongo_connection ) );
    res->err = MONGO_CONNECTION_SUCCESS;
    res->pool = pool;    
    mongo_connection_connect( res );
  } else /* return first from pool */
    res = removeFirst( pool );

  res->next = NULL;
  return res;
}

MONGO_EXPORT void mongo_connection_pool_release( mongo_connection_pool *pool, mongo_connection *conn ) {
  spinLock( &pool->lock );

  /* insert at the beginning of the pool */
  conn->next = pool->head;
  pool->head = conn;

  spinUnlock( &pool->lock );  
}

MONGO_EXPORT void mongo_connection_dictionary_init( mongo_connection_dictionary *dict ) {
  dict->head = NULL;
  dict->lock = 0;
}

static void addToDictionary( mongo_connection_dictionary *dict, mongo_connection_pool *pool, mongo_connection_pool *lastPoolInDict ) 
{   
  spinLock( &(dict->lock) );    

  /* insert at the end of dictionary */
  if( dict->head == NULL )
    dict->head = pool;
  else
    lastPoolInDict->next = pool;

  spinUnlock( &(dict->lock) );
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
    pool = ( mongo_connection_pool* )bson_malloc( sizeof( mongo_connection_pool ) );
    pool->head = NULL;
    pool->cs = cs;
    pool->next = NULL;
    pool->lock = 0;

    addToDictionary( dict, pool, lastPoolInDict );
  }

  return pool;
}