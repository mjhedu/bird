/*
 * memory.c
 *
 *  Created on: Dec 4, 2013
 *      Author: reboot
 */

#include "brc_memory.h"

#include <stdlib.h>
#include <string.h>

int
md_free (pmda md)
{

  if (!md || !md->first)
    {

      return 1;
    }

  p_md_obj ptr = md->first;
  while (ptr)
    {
      if (!(md->flags & F_MDA_REFPTR) && ptr->ptr)
	{
	  free (ptr->ptr);
	  ptr->ptr = NULL;
	}
      p_md_obj s_ptr = ptr->next;
      free (ptr);
      ptr = s_ptr;

    }

  bzero (md, sizeof(mda));

  return 0;
}

int
md_copy (pmda source, pmda dest, size_t block_sz, int
(*cb) (void *source, void *dest, void *ptr))
{
  if (!source || 0 == source->offset || !dest)
    {
      return 1;
    }

  if (dest->offset)
    {
      return 2;
    }
#ifdef _G_SSYS_THREAD
  mutex_lock (&source->mutex);
#endif

  int ret = 0;
  p_md_obj ptr = source->first;
  void *d_ptr;

  md_init (dest);

  while (ptr)
    {
      d_ptr = md_alloc (dest, block_sz, 0, NULL);
      if (!d_ptr)

	{
	  ret = 10;
	  break;
	}
      memcpy (d_ptr, ptr->ptr, block_sz);
      if (NULL != cb)
	{
	  cb ((void*) ptr->ptr, (void*) dest, (void*) d_ptr);
	}
      ptr = ptr->next;
    }

  if (ret)
    {
      md_free (dest);
    }

  if (source->offset != dest->offset)
    {
#ifdef _G_SSYS_THREAD
      pthread_mutex_unlock (&source->mutex);
#endif
      return 3;
    }
#ifdef _G_SSYS_THREAD
  pthread_mutex_unlock (&source->mutex);
#endif
  return 0;
}

int
is_memregion_null (void *addr, size_t size)
{
  size_t i = size - 1;
  unsigned char *ptr = (unsigned char*) addr;
  while (!ptr[i] && i)
    {
      i--;
    }
  return i;
}

void
md_init (pmda md)
{
  if (!md || md->first)
    {
      return;
    }

}

void *
md_alloc (pmda md, size_t b, uint32_t flags, void *refptr)
{
#ifdef _G_SSYS_THREAD
  mutex_lock (&md->mutex);
#endif

  /*if (md->offset >= md->count)
   {
   size_t newc = md->count * 2;
   p_md_obj oldptr = md->objects;
   md->objects = realloc (md->objects, newc * sizeof(md_obj));
   memset (&md->objects[md->count], 0x0, md->count * sizeof(md_obj));

   if (oldptr != md->objects)
   {
   md_relink (md);
   }

   md->count = newc;

   }*/

  p_md_obj pos = calloc (1, sizeof(md_obj));

  if (NULL == pos)
    {
      fprintf (stderr, "Out of memory");
      abort ();
    }

  if (md->flags & F_MDA_REFPTR)
    {
      pos->ptr = refptr;
    }
  else
    {
      if ( NULL == (pos->ptr = calloc (1, b)))
	{
	  fprintf (stderr, "Out of memory");
	  abort ();
	}

    }

  if (NULL == md->first)
    {
      md->first = pos;
    }
  else
    {
      md->pos->next = pos;
      pos->prev = md->pos;
    }

  md->pos = pos;
  md->offset++;

  return pos->ptr;
}

void *
md_unlink (pmda md, p_md_obj md_o)
{

  p_md_obj c_ptr = NULL;

  if (md_o->prev)
    {
      ((p_md_obj) md_o->prev)->next = (p_md_obj) md_o->next;
      c_ptr = md_o->prev;

    }

  if (md_o->next)
    {
      ((p_md_obj) md_o->next)->prev = (p_md_obj) md_o->prev;
      c_ptr = md_o->next;

    }

  if (md->first == md_o)
    {
      md->first = c_ptr;
    }

  md->offset--;

  if (NULL == md->first && md->offset > 0)
    {
      abort ();
    }

  if (md->pos == md_o)
    {
      if (c_ptr)
	{
	  md->pos = c_ptr;
	}
      else
	{
	  md->pos = md->first;
	}
    }

  if (!(md->flags & F_MDA_REFPTR) && md_o->ptr)
    {
      free (md_o->ptr);
    }

  free (md_o);

  return (void*) c_ptr;
}

