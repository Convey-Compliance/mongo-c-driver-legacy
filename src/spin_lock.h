#ifndef SPIN_LOCK_H_
#define SPIN_LOCK_H_

typedef volatile long spin_lock;

void crossYield( void );
long crossSwap( spin_lock *_this, long originalValue, long exchgValue );

void spinLock_init( spin_lock *_this );
void spinLock_destroy( spin_lock *_this );
void spinLock_lock( spin_lock *_this );
int spinLock_tryLock( spin_lock *_this );
void spinlock_unlock( spin_lock *_this );

#endif