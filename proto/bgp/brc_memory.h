/*
 * memory.h
 *
 *  Created on: Dec 4, 2013
 *      Author: reboot
 */

#ifndef MEMORY_H_
#define MEMORY_H_

#include <stdio.h>
#include <stdint.h>

#define F_MDA_REFPTR                    ((uint8_t)1 << 1)

typedef struct mda_object
{
  void *ptr;
  struct mda_object *next;
  struct mda_object *prev;
}*p_md_obj, md_obj;


typedef struct mda_header
{
  p_md_obj pos, first;
  size_t offset;
  uint8_t flags;

} mda, *pmda;


#pragma pack(push, 4)

typedef struct ___nn_2x64
{
uint64_t u00, u01;
uint16_t u16_00;
} _nn_2x64, *__nn_2x64;

#pragma pack(pop)

int
md_free (pmda md);

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
void
md_init (pmda md);

#define MD_START(md,t,n) do {p_md_obj ptr=(md)->first;t *n;for(;ptr&&(n=(t *)ptr->ptr);ptr=ptr->next)
#define MD_START_N(md,t,n) do {p_md_obj ptr=(md)->first;t *n;for(;ptr&&(n=(t *)ptr->ptr);)
#define MD_END } while(0);

#endif /* MEMORY_H_ */
