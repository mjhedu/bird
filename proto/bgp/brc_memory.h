/*
 * memory.h
 *
 *  Created on: Dec 4, 2013
 *      Author: reboot
 */

#ifndef MEMORY_H_
#define MEMORY_H_

//#include <fp_types.h>
//#include <t_glob.h>

#include <stdio.h>
#include <stdint.h>

#define F_MDA_REFPTR                    ((uint16_t)1 << 1)
#define F_MDA_FREE                      ((uint16_t)1 << 2)
#define F_MDA_REUSE                     ((uint16_t)1 << 3)
#define F_MDA_WAS_REUSED                ((uint16_t)1 << 4)
#define F_MDA_EOF                       ((uint16_t)1 << 5)
#define F_MDA_FIRST_REUSED              ((uint16_t)1 << 6)
#define F_MDA_ARR_DIST                  ((uint16_t)1 << 7)
#define F_MDA_NO_REALLOC                ((uint16_t)1 << 8)
#define F_MDA_ORPHANED                  ((uint16_t)1 << 10)
#define F_MDA_ST_MISC00                 ((uint16_t)1 << 11)
#define F_MDA_ST_MISC01                 ((uint16_t)1 << 12)

#define MDA_MDALLOC_RE                  ((uint32_t)1 << 1)

typedef struct mda_object
{
  void *ptr;
  struct mda_object *next;
  struct mda_object *prev;
}*p_md_obj, md_obj;

#ifdef _G_SSYS_THREAD
#include        <pthread.h>
#endif

typedef struct mda_header
{
  p_md_obj objects;
  p_md_obj pos, first;
  size_t offset, count;
  uint16_t flags;
#ifdef _G_SSYS_THREAD
pthread_mutex_t mutex;
#endif
} mda, *pmda;


#pragma pack(push, 4)

typedef struct ___nn_2x64
{
uint64_t u00, u01;
uint16_t u16_00;
} _nn_2x64, *__nn_2x64;

#pragma pack(pop)

int
md_g_free (pmda md);

void *
md_swap_s (pmda md, p_md_obj md_o1, p_md_obj md_o2);
void *
md_swap (pmda md, p_md_obj md_o1, p_md_obj md_o2);

int
md_copy (pmda source, pmda dest, size_t block_sz, int
(*cb) (void *source, void *dest, void *ptr));
int
is_memregion_null (void *addr, size_t size);

#define F_MDALLOC_NOLINK                ((uint32_t)1 << 1)

void *
md_alloc (pmda md, size_t b, uint32_t flags, void *refptr);
void *
md_unlink (pmda md, p_md_obj md_o);
int
md_init (pmda md, int nm);

#ifdef _G_SSYS_THREAD
off_t
md_get_off_ts (pmda md);
#endif

#endif /* MEMORY_H_ */
