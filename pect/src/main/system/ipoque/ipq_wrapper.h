/* written by Magnus Bartsch, ipoque GmbH
 * magnus.bartsch@ipoque.com
 */

#ifndef __IPOQUE_API_INCLUDE_FILE__
#error CANNOT INCLUDE THIS .H FILE, INCLUDE IPQ_API.H
#endif

typedef void *(*pace_malloc_t)( unsigned long size );
typedef void (*pace_free_t)( void *ptr );

typedef void *(*pace_ext_malloc_t)( unsigned long size,
                                    void *user_ptr );
typedef void (*pace_ext_free_t)( void *ptr,
                                 void *user_ptr );

typedef void *(*pace_realloc_t)( void *ptr, unsigned long size,
                                 void *memory_userptr );

