/*
 * br_string.c
 *
 *  Created on: Apr 10, 2016
 *      Author: reboot
 */

#include <stdio.h>
#include <string.h>

#include "brc_memory.h"

#include "br_string.h"

int
string_split (char *line, char dl, pmda output_t)
{
  int i, p, c, llen = strlen (line);

  for (i = 0, p = 0, c = 0; i <= llen; i++)
    {
      while (line[i] == dl && line[i])
	i++;
      p = i;

      while (line[i] != dl && line[i] != 0xA && line[i])
	i++;

      if (i > p)
	{
	  char *buffer = md_alloc (output_t, (i - p) + 10, 0, NULL);
	  if (!buffer)
	    return -1;
	  memcpy (buffer, &line[p], i - p);
	  c++;
	}
    }
  return c;
}

char *
md_string_join (pmda input_t, char dl, char *out, size_t max)
{
  p_md_obj ptr = input_t->first;

  max--;

  char *base = out;

  size_t w = 0;

  while (ptr)
    {
      char *s = ptr->ptr;

      size_t l = strlen (s) + 1;

      if (w + l > max)
	{
	  break;
	}

      snprintf (out, l, "%s", s);

      out += l;

      ptr = ptr->next;

      if (ptr)
	{
	  out[-1] = dl;
	}

      w += l;

    }

  out[0] = 0x0;

  return base;
}

#include <ctype.h>

void
str_to_lower (char* str)
{
  for (; str[0]; str++)
    {
      str[0] = tolower (str[0]);
    }
}
