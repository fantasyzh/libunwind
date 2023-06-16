/* libunwind - a platform-independent unwind library
   Copyright (C) 2003-2005 Hewlett-Packard Co
        Contributed by David Mosberger-Tang <davidm@hpl.hp.com>

This file is part of libunwind.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  */

#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "libunwind_i.h"
#include "os-linux.h"

static pid_t global_pid = 0;
static int global_pid_proc_maps_fd = -1;

void init_global_proc_map(pid_t pid)
{
    if (pid > 0)
    {
        char path[sizeof ("/proc/0123456789/maps")], *cp;
        memcpy (path, "/proc/", 6);
        cp = unw_ltoa (path + 6, pid);
        assert (cp + 6 < path + sizeof (path));
        memcpy (cp, "/maps", 6);

        int fd = open (path, O_RDONLY);
        if (fd >= 0)
        {
            /* copy to mem buffer */
            int memfd = syscall(__NR_memfd_create, "global_pid_proc_maps_fd", (unsigned int)0);
            if (memfd < 0)
            {
                perror("memfd_create");
                exit(1);
            }
            char buffer[4096];
            int n = -1;
            while ((n = read(fd, buffer, sizeof(buffer))) > 0)
            {
                write(memfd, buffer, n);
            }
            if (n < 0)
            {
                perror("read proc maps");
                exit(1);
            }
            close(fd);
            global_pid_proc_maps_fd = memfd;
            global_pid = pid;
        }
    }
}

int get_global_proc_map_fd(pid_t pid)
{
    if (global_pid <= 0)
    {
        return -1;
    }

    char path[sizeof ("/proc/0123456789/task/0123456789")], *cp;
    memcpy (path, "/proc/", 6);
    cp = unw_ltoa (path + 6, global_pid);
    assert (cp + 6 < path + sizeof (path));
    memcpy (cp, "/task/", 6);
    cp = unw_ltoa (cp + 6, pid);
    (*cp) = '\0';

    if (access(path, F_OK) == 0)
    {
        return global_pid_proc_maps_fd;
    }
    else
    {
        return -1;
    }
}

int is_global_proc_map_fd(int fd)
{
    return fd == global_pid_proc_maps_fd;
}

int
tdep_get_elf_image (struct elf_image *ei, pid_t pid, unw_word_t ip,
                    unsigned long *segbase, unsigned long *mapoff,
                    char *path, size_t pathlen)
{
  struct map_iterator mi;
  int found = 0, rc;
  unsigned long hi;
  char root[sizeof ("/proc/0123456789/root")], *cp;
  char *full_path;
  struct stat st;

  if (maps_init (&mi, pid) < 0)
    return -1;

  while (maps_next (&mi, segbase, &hi, mapoff, NULL))
    if (ip >= *segbase && ip < hi)
      {
        found = 1;
        break;
      }

  if (!found)
    {
      maps_close (&mi);
      return -1;
    }

  full_path = mi.path;

  /* Get process root */
  memcpy (root, "/proc/", 6);
  cp = unw_ltoa (root + 6, pid);
  assert (cp + 6 < root + sizeof (root));
  memcpy (cp, "/root", 6);

  size_t _len = strlen (mi.path) + 1;
  if (!stat(root, &st) && S_ISDIR(st.st_mode))
    _len += strlen (root);
  else
    root[0] = '\0';

  full_path = path;
  if(!path)
    full_path = (char*) malloc (_len);
  else if(_len >= pathlen) // passed buffer is too small, fail
    return -1;

  strcpy (full_path, root);
  strcat (full_path, mi.path);

  rc = elf_map_image (ei, full_path);

  if (!path)
    free (full_path);

  maps_close (&mi);
  return rc;
}

#ifndef UNW_REMOTE_ONLY

void
tdep_get_exe_image_path (char *path)
{
  strcpy(path, "/proc/self/exe");
}

#endif /* !UNW_REMOTE_ONLY */
