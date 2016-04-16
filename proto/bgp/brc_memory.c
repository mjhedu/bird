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
md_g_free (pmda md)
{
#ifdef _G_SSYS_THREAD
  mutex_lock (&md->mutex);
#endif
  if (!md || !md->objects)
    {
#ifdef _G_SSYS_THREAD
      pthread_mutex_unlock (&md->mutex);
#endif
      return 1;
    }

  if (!(md->flags & F_MDA_REFPTR))
    {
      p_md_obj ptr = md->first, ptr_s;
      while (ptr)
	{
	  ptr_s = ptr->next;
	  if (ptr->ptr)
	    {
	      free (ptr->ptr);
	      ptr->ptr = NULL;
	    }
	  ptr = ptr_s;
	}
    }

  free (md->objects);

#ifdef _G_SSYS_THREAD
  pthread_mutex_unlock (&md->mutex);
#endif

  bzero (md, sizeof(mda));

  return 0;
}

void *
md_swap (pmda md, p_md_obj md_o1, p_md_obj md_o2)
{
  if (!md_o1 || !md_o2)
    {
      return NULL;
    }

  void *ptr2_s;

  ptr2_s = md_o1->prev;
  md_o1->next = md_o2->next;
  md_o1->prev = md_o2;
  md_o2->next = md_o1;
  md_o2->prev = ptr2_s;

  if (md_o2->prev)
    {
      ((p_md_obj) md_o2->prev)->next = md_o2;
    }

  if (md_o1->next)
    {
      ((p_md_obj) md_o1->next)->prev = md_o1;
    }

  if (md->first == md_o1)
    {
      md->first = md_o2;
    }

  return md_o2->next;
}

void *
md_swap_s (pmda md, p_md_obj md_o1, p_md_obj md_o2)
{
  void *ptr = md_o1->ptr;
  md_o1->ptr = md_o2->ptr;
  md_o2->ptr = ptr;

  return md_o1->next;
}

int
md_copy (pmda source, pmda dest, size_t block_sz, int
(*cb) (void *source, void *dest, void *ptr))
{
  if (!source || 0 == source->count || !dest)
    {
      return 1;
    }

  if (dest->count)
    {
      return 2;
    }
#ifdef _G_SSYS_THREAD
  mutex_lock (&source->mutex);
#endif

  int ret = 0;
  p_md_obj ptr = source->first;
  void *d_ptr;

  md_init (dest, (int) source->count);

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
      md_g_free (dest);
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

int
md_init (pmda md, int nm)
{
  if (!md || md->objects)
    {
      return 1;
    }

  bzero (md, sizeof(mda));
  if (!(md->objects = calloc (nm + 1, sizeof(md_obj))))
    {
      fprintf (stderr, "ERROR: md_init: could not allocate memory\n");
      abort ();
    }

  md->count = (size_t) nm;
  md->pos = md->objects;
  md->first = NULL;
#ifdef _G_SSYS_THREAD
  mutex_init (&md->mutex, PTHREAD_MUTEX_RECURSIVE, PTHREAD_MUTEX_ROBUST);
#endif

  return 0;
}

void *
md_alloc (pmda md, size_t b, uint32_t flags, void *refptr)
{
#ifdef _G_SSYS_THREAD
  mutex_lock (&md->mutex);
#endif

  if (md->offset >= md->count)
    {
#ifdef _G_SSYS_THREAD
      pthread_mutex_unlock (&md->mutex);
#endif
      return NULL;
    }

  p_md_obj pos = md->objects;
  ssize_t pcntr = 0;

  while (pos->ptr && pcntr < md->count)
    {
      pcntr++;
      pos++;
    }

  if (pcntr >= md->count)
    {
#ifdef _G_SSYS_THREAD
      pthread_mutex_unlock (&md->mutex);
#endif
      return NULL;
    }

  if (md->flags & F_MDA_REFPTR)
    {
      pos->ptr = refptr;
    }
  else
    {
      pos->ptr = calloc (1, b);
    }

  if (NULL == md->first)
    {
      md->first = pos;
    }
  else
    {
      if (!(flags & F_MDALLOC_NOLINK))
	{
	  md->pos->next = pos;
	  pos->prev = md->pos;
	}
    }

  md->pos = pos;
  md->offset++;

#ifdef _G_SSYS_THREAD
  pthread_mutex_unlock (&md->mutex);
#endif
  return md->pos->ptr;
}

void *
md_unlink (pmda md, p_md_obj md_o)
{
#ifdef _G_SSYS_THREAD
  mutex_lock (&md->mutex);
#endif

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
      if (NULL != c_ptr)
	{
	  md->pos = c_ptr;
	}
      else
	{
	  md->pos = md->objects;
	}
    }

  if (!(md->flags & F_MDA_REFPTR) && NULL != md_o->ptr)
    {
      free (md_o->ptr);
    }

  md_o->ptr = NULL;
  md_o->next = NULL;
  md_o->prev = NULL;

#ifdef _G_SSYS_THREAD
  pthread_mutex_unlock (&md->mutex);
#endif

  return (void*) c_ptr;
}

