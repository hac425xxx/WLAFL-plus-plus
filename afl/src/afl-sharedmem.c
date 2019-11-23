/*
   american fuzzy lop++ - shared memory related code
   -------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#define AFL_MAIN

#ifdef __ANDROID__
#include "android-ashmem.h"
#endif
#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "sharedmem.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>

#ifndef USEMMAP
#include <sys/ipc.h>
#include <sys/shm.h>
#endif

extern unsigned char *trace_bits;

extern char SHM_ID[255];

#ifdef USEMMAP
/* ================ Proteas ================ */
int g_shm_fd = -1;
unsigned char *g_shm_base = NULL;
char g_shm_file_path[L_tmpnam];
/* ========================================= */
#else
static s32 shm_id; /* ID of the SHM region              */
#endif

/* Get rid of shared memory (atexit handler). */

void remove_shm(void)
{

#ifdef USEMMAP
  if (g_shm_base != NULL)
  {

    munmap(g_shm_base, MAP_SIZE);
    g_shm_base = NULL;
  }

  if (g_shm_fd != -1)
  {

    close(g_shm_fd);
    g_shm_fd = -1;
  }

#else
  shmctl(shm_id, IPC_RMID, NULL);
#endif
}

/* Configure shared memory. */

void setup_shm(unsigned char dumb_mode)
{

  u8 *shm_str;

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0)
    PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  printf("set env %s=%s\n", SHM_ENV_VAR, shm_str);
  setenv(SHM_ENV_VAR, shm_str, 1);

  snprintf(SHM_ID, sizeof(SHM_ID), "%d", shm_id);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);

  if (!trace_bits)
    PFATAL("shmat() failed");
}
