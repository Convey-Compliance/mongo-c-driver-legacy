#include "connection_pool.h"
#include "env.h"

void main() {
  mongo_connection_dictionary dic;
  mongo_connection_pool *pool;
  mongo_connection *c;

  mongo_env_sock_init();

  mongo_connection_dictionary_init( &dic );
  pool = mongo_connection_dictionary_get_pool( &dic, "mongodb://127.0.0.1" );
  c = mongo_connection_pool_acquire( pool );
  mongo_connection_pool_release( pool, c );

  pool = mongo_connection_dictionary_get_pool( &dic, "mongodb://user:pass@127.0.0.1/dbtest" );
  c = mongo_connection_pool_acquire( pool );
}