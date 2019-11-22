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

/* we need this internally but can be defined and read extern in the main source
 */
void destroy_target_process()
{
  char cmd[512] = {0};
  snprintf(cmd, 512, "kill -9 %d", child_pid);
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

char *read_pipe_path = "/tmp/wlafl_pipe_read";
char *write_pipe_path = "/tmp/wlafl_pipe_write";

int read_pipe = -1;
int write_pipe = -1;

int setup_pipe()
{

  if (write_pipe != -1)
  {
    close(write_pipe);
  }
  if (read_pipe != -1)
  {
    close(read_pipe);
  }

  if (access(read_pipe_path, F_OK) == -1)
  {
    int res = mkfifo(read_pipe_path, 0666);
    if (res != 0)
    {
      fprintf(stderr, "Could not create fifo %s\n", read_pipe_path);
      exit(1);
    }
  }
  if (access(write_pipe_path, F_OK) == -1)
  {
    int res = mkfifo(write_pipe_path, 0666);
    if (res != 0)
    {
      fprintf(stderr, "Could not create fifo %s\n", write_pipe_path);
      exit(1);
    }
  }
}

// 创建一个进程
void create_process(char **argv)
{

  setup_pipe();

  forksrv_pid = fork();
  if (forksrv_pid < 0)
    PFATAL("fork() failed");

  if (!forksrv_pid)
  {

    if (!getenv("LD_BIND_LAZY"))
      setenv("LD_BIND_NOW", "1", 0);

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    execv(argv[0], argv);

    *(u32 *)trace_bits = EXEC_FAIL_SIG;
    exit(0);
  }
  read_pipe = open(read_pipe_path, O_RDONLY);
  write_pipe = open(write_pipe_path, O_WRONLY);
}
