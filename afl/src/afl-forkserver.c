/*
   american fuzzy lop++ - forkserver code
   --------------------------------------

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

   Shared code that implements a forkserver. This is used by the fuzzer
   as well the other components like afl-tmin.

 */

#include "config.h"
#include "types.h"
#include "debug.h"
#include "forkserver.h"
#include "afl-fuzz.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h>

/* a program that includes afl-forkserver needs to define these */
extern u8 uses_asan;
extern u8 *trace_bits;
extern s32 forksrv_pid, child_pid, fsrv_ctl_fd, fsrv_st_fd;
extern s32 out_fd, out_dir_fd, dev_null_fd; /* initialize these with -1 */
#ifndef HAVE_ARC4RANDOM
extern s32 dev_urandom_fd;
#endif
extern u32 exec_tmout;
extern u64 mem_limit;
extern u8 *out_file, *target_path, *doc_path;
extern FILE *plot_file;

extern char SHM_ID[255];
extern char instrument_arguments[0x200];

/* we need this internally but can be defined and read extern in the main source
 */
void kill_process(int pid)
{
  char cmd[512] = {0};
  snprintf(cmd, 512, "kill -9 %d", pid);
  system(cmd);
}

/* the timeout handler */

void handle_timeout(int sig)
{

  if (child_pid > 0)
  {

    child_timed_out = 1;
    kill(child_pid, SIGKILL);
  }
  else if (child_pid == -1 && forksrv_pid > 0)
  {

    child_timed_out = 1;
    kill(forksrv_pid, SIGKILL);
  }
}

#ifdef __ANDROID__
char *read_pipe_path = "/data/local/tmp/wlafl_pipe_read";
char *write_pipe_path = "/data/local/tmp/wlafl_pipe_write";
#else
char *read_pipe_path = "/tmp/wlafl_pipe_read";
char *write_pipe_path = "/tmp/wlafl_pipe_write";
#endif

int read_pipe = -1;
int write_pipe = -1;

int setup_pipe()
{

  char tmp[1000] = {0};
  snprintf(tmp, 1000, "%s_%d", read_pipe_path, getpid());
  if (access(tmp, F_OK) == -1)
  {
    int res = mkfifo(tmp, 0666);
    if (res != 0)
    {
      fprintf(stderr, "Could not create fifo %s\n", tmp);
      exit(1);
    }
  }
  snprintf(tmp, 1000, "%s_%d", write_pipe_path, getpid());
  if (access(tmp, F_OK) == -1)
  {
    int res = mkfifo(tmp, 0666);
    if (res != 0)
    {
      fprintf(stderr, "Could not create fifo %s\n", tmp);
      exit(1);
    }
  }
}

// 创建一个进程
void create_process(char **argv)
{

  setup_pipe();

  char **TMP[255] = {0};

  int i = 0;

  char *drrun_path = getenv("DYRUN_PATH");

  TMP[i++] = drrun_path;
  TMP[i++] = "-c";
  TMP[i++] = "libcoverage.so";

  char TMP_INSTRUMENT_ARGS[0x200];

  strcpy(TMP_INSTRUMENT_ARGS, instrument_arguments);

  char* p = TMP_INSTRUMENT_ARGS;
  TMP[i++] = p;
  while (*p)
  {
    if (*p == ' ')
    {
      *p = '\x00';
      TMP[i++] = p + 1;
    }
    p++;
  }

  // TMP[i++] = "-nargs";
  // TMP[i++] = "3";
  // TMP[i++] = "-target_module";
  // TMP[i++] = "demo";
  // TMP[i++] = "-target_offset";
  // TMP[i++] = "0xb28";
  // TMP[i++] = "-coverage_module";
  // TMP[i++] = "demo";

  TMP[i++] = "-shm_id";
  TMP[i++] = SHM_ID;

  TMP[i++] = "-fuzzer_id";
  char fuzzer_id[20] = {0};
  snprintf(fuzzer_id, 20, "%d", getpid());
  TMP[i++] = fuzzer_id;

  TMP[i++] = "--";

  for (int j = 0; argv[j] != NULL; j++)
  {
    TMP[i++] = argv[j];
  }

  printf("verify executed cmd:\n");
  for (int j = 0; TMP[j] != NULL; j++)
  {
    printf("%s ", TMP[j]);
  }
  printf("\n");

  // getchar();


  forksrv_pid = fork();
  if (forksrv_pid < 0)
    PFATAL("fork() failed");

  if (!forksrv_pid)
  {

    if (!getenv("LD_BIND_LAZY"))
      setenv("LD_BIND_NOW", "1", 0);

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    execv(TMP[0], TMP);

    *(u32 *)trace_bits = EXEC_FAIL_SIG;
    exit(0);
  }

  char tmp[1000] = {0};
  snprintf(tmp, 1000, "%s_%d", read_pipe_path, getpid());
  read_pipe = open(tmp, O_RDONLY);

  snprintf(tmp, 1000, "%s_%d", write_pipe_path, getpid());
  write_pipe = open(tmp, O_WRONLY);
}
