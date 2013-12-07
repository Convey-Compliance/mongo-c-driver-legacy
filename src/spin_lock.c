#include "spin_lock.h"

#define SPINLOCK_LOCKED 1
#define SPINLOCK_UNLOCKED 0
#define SPINS_BETWEEN_THREADSWITCH 1000

static void spin( int *spinCount ) {
  if( (*spinCount)++ > SPINS_BETWEEN_THREADSWITCH ) {
    SwitchToThread();
    *spinCount = 0;
  }
}

void spinLock_init( spin_lock *_this ){
  (*_this) = 0; /* Start unlocked */
}

void spinLock_done( spin_lock *_this ){
  /* Empty function, in the future can be used if spin_lock becomes a more complex type
     that requires some kind of finalization */
}

void spinLock_lock( spin_lock *_this ) {
  int spins = 0;
  while ( InterlockedCompareExchange( _this, SPINLOCK_LOCKED, SPINLOCK_UNLOCKED ) != SPINLOCK_UNLOCKED ) {
    spin( &spins );  
  };
}

void spinlock_unlock( spin_lock *_this ) {
  int spins = 0;
  while ( InterlockedCompareExchange( _this, SPINLOCK_UNLOCKED, SPINLOCK_LOCKED ) != SPINLOCK_LOCKED ) {
    spin( &spins );
  };
}