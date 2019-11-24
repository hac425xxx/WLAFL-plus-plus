#define _CRT_SECURE_NO_WARNINGS

#define MAP_SIZE 65536

#include "dr_api.h"
#include "drmgr.h"
#include "drx.h"
#include "drreg.h"
#include "drwrap.h"

#include "drsyms.h"

#ifdef __ANDROID__
#include "../../afl/include/android-ashmem.h"
#endif

#include "../../afl/include/config.h"

#include "drtable.h"
#include <string.h>
#include <stdlib.h>

#ifdef _WINDOWS
#include <windows.h>
#else
#include <unistd.h>
#include <sys/syscall.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include <sys/stat.h>
typedef unsigned int DWORD;
#endif

enum
{
    CMD_QUERY,
    CMD_WAIT_REQUEST,
    CMD_START_FUZZ,
    CMD_PROCESS_CRASH,
    CMD_PROCESS_NOMAL_RETURN,
    CMD_PROCESS_TIMEOUT,
    CMD_STOP_FUZZ,
};

//fuzz modes
enum persistence_mode_t
{
    native_mode = 0,
    in_app = 1,
};

typedef struct
{
    char name[256];
    unsigned long base;
    unsigned long end;
} MODULE_INFO;

MODULE_INFO target_module = {0};

typedef struct _winafl_option_t
{
    /* Use nudge to notify the process for termination so that
     * event_exit will be called.
     */
    bool nudge_kills;
    bool debug_mode;
    int persistence_mode;
    int coverage_kind;
    char logdir[MAXIMUM_PATH];
    char fuzz_module[MAXIMUM_PATH];
    char fuzz_method[MAXIMUM_PATH];
    char fuzzer_id[MAXIMUM_PATH];
    char shm_id[MAXIMUM_PATH];
    unsigned long fuzz_offset;
    int fuzz_iterations;
    void **func_args;
    int num_fuz_args;
    drwrap_callconv_t callconv;
    bool thread_coverage;
    bool no_loop;
    bool dr_persist_cache;
} winafl_option_t;

static winafl_option_t options;

typedef struct _winafl_data_t
{
    file_t log;
    unsigned char *fake_afl_area; //used for thread_coverage
    unsigned char *afl_area;
} winafl_data_t;
static winafl_data_t winafl_data;

static int winafl_tls_field;

typedef struct _fuzz_target_t
{
    reg_t xsp; /* stack level at entry to the fuzz target */
    reg_t xbp;
    reg_t lr;
    app_pc func_pc;
    int iteration;
} fuzz_target_t;
static fuzz_target_t fuzz_target;

static client_id_t client_id;

static void
event_exit(void);

static void
event_thread_exit(void *drcontext);

#ifdef _WINDOWS
static HANDLE pipe_fd;
#else
static int pipe_fd;
int write_pipe;
int read_pipe;

#ifdef __ANDROID__
char *read_pipe_path = "/data/local/tmp/wlafl_pipe_read";
char *write_pipe_path = "/data/local/tmp/wlafl_pipe_write";
#else
char *read_pipe_path = "/tmp/wlafl_pipe_read";
char *write_pipe_path = "/tmp/wlafl_pipe_write";
#endif

#endif

/****************************************************************************
 * Nudges
 */

enum
{
    NUDGE_TERMINATE_PROCESS = 1,
};

static void
event_nudge(void *drcontext, uint64 argument)
{
    int nudge_arg = (int)argument;
    int exit_arg = (int)(argument >> 32);
    if (nudge_arg == NUDGE_TERMINATE_PROCESS)
    {
        static int nudge_term_count;
        /* handle multiple from both NtTerminateProcess and NtTerminateJobObject */
        uint count = dr_atomic_add32_return_sum(&nudge_term_count, 1);
        if (count == 1)
        {
            dr_abort();
        }
    }
}

static bool
event_soft_kill(process_id_t pid, int exit_code)
{
    /* we pass [exit_code, NUDGE_TERMINATE_PROCESS] to target process */
    dr_config_status_t res;
    res = dr_nudge_client_ex(pid, client_id,
                             NUDGE_TERMINATE_PROCESS | (uint64)exit_code << 32,
                             0);
    if (res == DR_SUCCESS)
    {
        /* skip syscall since target will terminate itself */
        return true;
    }
    /* else failed b/c target not under DR control or maybe some other
     * error: let syscall go through
     */
    return false;
}

/****************************************************************************
 * Event Callbacks
 */

int ReadCommandFromPipe()
{
    int cmd = 0;
#ifdef _WINDOWS
    DWORD num_read;
    ReadFile(pipe, &cmd, sizeof(cmd), &num_read, NULL);
#else
    if (read(read_pipe, &cmd, sizeof(cmd)) != sizeof(cmd))
    {
        return -1;
    }
#endif
    return cmd;
}

void WriteCommandToPipe(int cmd)
{

#ifdef _WINDOWS
    DWORD num_written;
    WriteFile(pipe, &cmd, sizeof(cmd), &num_written, NULL);
#else
    if (write(write_pipe, &cmd, sizeof(cmd)) != sizeof(cmd))
    {
        dr_printf("write cmd(%p) failed\n");
        dr_abort();
    }

#endif
}

#ifdef _WINDOWS
static bool
onexception(void *drcontext, dr_exception_t *excpt)
{
    DWORD exception_code = excpt->record->ExceptionCode;

    if (options.debug_mode)
        dr_fprintf(winafl_data.log, "Exception caught: %x\n", exception_code);

    if ((exception_code == EXCEPTION_ACCESS_VIOLATION) ||
        (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
        (exception_code == EXCEPTION_PRIV_INSTRUCTION) ||
        (exception_code == EXCEPTION_INT_DIVIDE_BY_ZERO) ||
        (exception_code == STATUS_HEAP_CORRUPTION) ||
        (exception_code == EXCEPTION_STACK_OVERFLOW) ||
        (exception_code == STATUS_STACK_BUFFER_OVERRUN) ||
        (exception_code == STATUS_FATAL_APP_EXIT))
    {
        if (options.debug_mode)
        {
            dr_fprintf(winafl_data.log, "crashed\n");
        }
        else
        {
            WriteCommandToPipe('C');
        }
        dr_abort();
    }
    return true;
}

#else
dr_signal_action_t
onexception(void *drcontext, dr_siginfo_t *siginfo)
{

    if (siginfo->sig == SIGILL ||
        siginfo->sig == SIGBUS ||
        siginfo->sig == SIGFPE ||
        siginfo->sig == SIGSEGV ||
        siginfo->sig == SIGABRT)
    {
        void *access_addr = NULL;
        bool bAccessMemory = (siginfo->sig == SIGBUS || siginfo->sig == SIGSEGV);
        if (bAccessMemory)
        {
            access_addr = siginfo->access_address;
        }
        dr_printf("exception pc: %p, access_addr:%p\n", siginfo->mcontext->pc, access_addr);

        if (!options.debug_mode)
        {
            WriteCommandToPipe(CMD_PROCESS_CRASH);
        }
        // close(read_pipe);
        // close(write_pipe);
        dr_abort();
    }

    return DR_SIGNAL_DELIVER; //return normal
}

#endif

unsigned long pre_offset = 0;

static void
log_edge(unsigned long offset)
{

    unsigned long id = offset ^ pre_offset;
    id &= MAP_SIZE - 1;
    winafl_data.afl_area[id]++;

    if (options.debug_mode)
    {
        dr_printf("offset:%p\n", offset);
        dr_printf("pre_offset:%p\n", pre_offset);
        dr_printf("id:%p\n", id);
    }

    pre_offset = offset >> 1;
}

static dr_emit_flags_t
instrument_edge_coverage(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                         bool for_trace, bool translating, void *user_data)
{
    static bool debug_information_output = false;
    app_pc start_pc;
    unsigned long offset;
    bool should_instrument = false;

    if (!drmgr_is_first_instr(drcontext, inst))
        return DR_EMIT_DEFAULT;

    start_pc = dr_fragment_app_pc(tag);

    if (start_pc >= target_module.base && start_pc <= target_module.end)
    {
        should_instrument = true;
    }

    if (!should_instrument)
        return DR_EMIT_DEFAULT | DR_EMIT_PERSISTABLE;

    offset = (unsigned long)(start_pc - target_module.base);

    dr_insert_clean_call(drcontext, bb, NULL, (void *)log_edge, true, 1, OPND_CREATE_INTPTR(offset));

    return DR_EMIT_DEFAULT;
}

static void
pre_loop_start_handler(void *wrapcxt, INOUT void **user_data)
{
    void *drcontext = drwrap_get_drcontext(wrapcxt);

    //let server know we finished a cycle, redundunt on first cycle.
    WriteCommandToPipe(0xf1);

    if (options.debug_mode && fuzz_target.iteration == options.fuzz_iterations)
    {
        dr_abort();
    }
    fuzz_target.iteration++;

    //let server know we are starting a new cycle
    WriteCommandToPipe('P');

    //wait for server acknowledgement for cycle start
    char command = ReadCommandFromPipe();

    if (command != 'F')
    {
        if (command == 'Q')
        {
            dr_abort();
        }
        else
        {
            char errorMessage[] = "unrecognized command received over pipe: ";
            errorMessage[sizeof(errorMessage) - 2] = command;
            DR_ASSERT_MSG(false, errorMessage);
        }
    }

    memset(winafl_data.afl_area, 0, MAP_SIZE);
}

static void
pre_fuzz_handler(void *wrapcxt, INOUT void **user_data)
{
    int command = 0;
    int i;
    void *drcontext;

    app_pc target_to_fuzz = drwrap_get_func(wrapcxt);
    dr_mcontext_t *mc = drwrap_get_mcontext_ex(wrapcxt, DR_MC_ALL);
    drcontext = drwrap_get_drcontext(wrapcxt);

#if defined(AARCH64)
    fuzz_target.xsp = mc->xsp;
    fuzz_target.xbp = mc->r29;
    fuzz_target.lr = mc->lr;
    fuzz_target.func_pc = target_to_fuzz;
#else
    fuzz_target.xsp = mc->xsp;
    fuzz_target.xbp = mc->xbp;
    fuzz_target.func_pc = target_to_fuzz;
#endif

    if (options.debug_mode)
    {
        dr_printf("In pre_fuzz_handler\n");
    }

    //save or restore arguments
    if (!options.no_loop)
    {
        if (fuzz_target.iteration == 0)
        {
            for (i = 0; i < options.num_fuz_args; i++)
                options.func_args[i] = drwrap_get_arg(wrapcxt, i);
        }
        else
        {
            for (i = 0; i < options.num_fuz_args; i++)
                drwrap_set_arg(wrapcxt, i, options.func_args[i]);
        }
    }

    if (!options.debug_mode)
    {
        command = ReadCommandFromPipe();

        if (command == CMD_QUERY)
        {

            // dr_printf("Instrument: Recv CMD_QUERY, now write CMD_WAIT_REQUEST to afl-fuzz\n");
            WriteCommandToPipe(CMD_WAIT_REQUEST); // 通知 afl-fuzz 程序可以开始 fuzzing

            //等待接收开始 fuzzing 的命令
            command = ReadCommandFromPipe();
            if (command != CMD_START_FUZZ)
            {
                if (command == CMD_STOP_FUZZ) // 0xff 表示退出
                {
                    dr_abort();
                }
                else
                {
                    dr_printf("Instrument: unrecognized command received over pipe");
                    dr_abort();
                }
            }
        }
        else
        {
            dr_printf("Instrument: Wait CMD_QUERY failded\n");
            dr_abort();
        }
    }
    memset(winafl_data.afl_area, 0, MAP_SIZE);
}

static void
post_fuzz_handler(void *wrapcxt, void *user_data)
{
    dr_mcontext_t *mc;
    mc = drwrap_get_mcontext(wrapcxt);
    if (!options.debug_mode)
    {
        WriteCommandToPipe(CMD_PROCESS_NOMAL_RETURN); // 表示执行完了
    }
    else
    {
        dr_printf("In post_fuzz_handler\n");
    }

    // dr_printf("In post_fuzz_handler\n");

    /* We don't need to reload context in case of network-based fuzzing. */
    if (options.no_loop)
        return;

    fuzz_target.iteration++;
    if (options.debug_mode && fuzz_target.iteration == options.fuzz_iterations)
    {
        dr_abort();
    }
#if defined(AARCH64)
    mc->xsp = fuzz_target.xsp;
    mc->r29 = fuzz_target.xbp;
    mc->lr = fuzz_target.lr;
    mc->pc = fuzz_target.func_pc;
#else
    mc->xsp = fuzz_target.xsp;
    mc->xbp = fuzz_target.xbp;
    mc->pc = fuzz_target.func_pc;
#endif

    drwrap_redirect_execution(wrapcxt);
}

static void
event_module_unload(void *drcontext, const module_data_t *info)
{
    ;
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    app_pc to_wrap = 0;
    char *module_name = (char *)dr_module_preferred_name(info);

    if (options.debug_mode)
        dr_fprintf(winafl_data.log, "Module loaded: %s\t%p----%p\n", module_name, info->start, info->end);

    if (strstr(module_name, target_module.name) != NULL)
    {
        target_module.base = info->start;
        target_module.end = info->end;
    }

    if (strcmp(module_name, options.fuzz_module) == 0)
    {
        if (options.fuzz_offset)
        {
            to_wrap = info->start + options.fuzz_offset;
        }
        else
        {
            to_wrap = (app_pc)dr_get_proc_address(info->handle, options.fuzz_method);
            if (!to_wrap)
            {
                drsym_lookup_symbol(info->full_path, options.fuzz_method, (size_t *)(&to_wrap), 0);
                to_wrap += (size_t)info->start;
            }
        }
        if (options.persistence_mode == native_mode)
        {
            drwrap_wrap_ex(to_wrap, pre_fuzz_handler, post_fuzz_handler, NULL, options.callconv);
        }
        if (options.persistence_mode == in_app)
        {
            drwrap_wrap_ex(to_wrap, pre_loop_start_handler, NULL, NULL, options.callconv);
        }
    }
}

static void
event_exit(void)
{
    drx_exit();
    drmgr_exit();
    drsym_exit();
}

static void
event_init(void)
{
    char buf[MAXIMUM_PATH];
    memset(winafl_data.afl_area, 0, MAP_SIZE);
}

static void
setup_pipe()
{
#ifdef _WINDOWS
    pipe = CreateFile(
        options.pipe_name, // pipe name
        GENERIC_READ |     // read and write access
            GENERIC_WRITE,
        0,             // no sharing
        NULL,          // default security attributes
        OPEN_EXISTING, // opens existing pipe
        0,             // default attributes
        NULL);         // no template file

    if (pipe == INVALID_HANDLE_VALUE)
        DR_ASSERT_MSG(false, "error connecting to pipe");
#else
    dr_printf("open pipe\n");
    char tmp[1000] = {0};

    snprintf(tmp, 1000, "%s_%s", read_pipe_path, options.fuzzer_id);
    puts(tmp);
    write_pipe = open(tmp, O_WRONLY);

    snprintf(tmp, 1000, "%s_%s", write_pipe_path, options.fuzzer_id);
    puts(tmp);
    read_pipe = open(tmp, O_RDONLY);
#endif
}

static void
setup_shmem()
{

#ifdef _WINDOWS
    HANDLE map_file;

    map_file = OpenFileMapping(
        FILE_MAP_ALL_ACCESS, // read/write access
        FALSE,               // do not inherit the name
        options.shm_name);   // name of mapping object

    if (map_file == NULL)
        DR_ASSERT_MSG(false, "error accesing shared memory");

    winafl_data.afl_area = (unsigned char *)MapViewOfFile(map_file,            // handle to map object
                                                          FILE_MAP_ALL_ACCESS, // read/write permission
                                                          0,
                                                          0,
                                                          MAP_SIZE);

    if (winafl_data.afl_area == NULL)
        DR_ASSERT_MSG(false, "error accesing shared memory");
#else
    int32_t shm_id = -1;
    if ((shm_id = atoi(options.shm_id)) < 0)
    {
        dr_printf("invalid " SHM_ENV_VAR " contents");
        dr_abort();
    }
    if ((winafl_data.afl_area = (u8 *)shmat(shm_id, NULL, 0)) == (void *)-1 || winafl_data.afl_area == NULL)
    {
        dr_printf("get share memory failed.\n");
        dr_abort();
    }

#endif
}

static void
options_init(client_id_t id, int argc, const char *argv[])
{
    int i;
    const char *token;
    /* default values */
    options.persistence_mode = native_mode;
    options.nudge_kills = true;
    options.debug_mode = false;
    options.fuzz_module[0] = 0;
    options.fuzz_method[0] = 0;
    options.fuzz_offset = 0;
    options.fuzz_iterations = 1000;
    options.no_loop = false;
    options.func_args = NULL;
    options.num_fuz_args = 0;
    options.callconv = DRWRAP_CALLCONV_DEFAULT;
    options.dr_persist_cache = false;

    for (i = 1 /*skip client*/; i < argc; i++)
    {

        token = argv[i];

        dr_printf("token:%s\n", token);

        if (strcmp(token, "-no_nudge_kills") == 0)
            options.nudge_kills = false;
        else if (strcmp(token, "-nudge_kills") == 0)
            options.nudge_kills = true;
        else if (strcmp(token, "-debug") == 0)
            options.debug_mode = true;
        else if (strcmp(token, "-shm_id") == 0)
        {
            strcpy(options.shm_id, argv[i + 1]);
            i++;
        }
        else if (strcmp(token, "-fuzzer_id") == 0)
        {
            strcpy(options.fuzzer_id, argv[i + 1]);
            i++;
        }
        else if (strcmp(token, "-coverage_module") == 0)
        {
            strncpy(target_module.name, argv[++i], sizeof(target_module.name));
        }
        else if (strcmp(token, "-target_module") == 0)
        {
            strncpy(options.fuzz_module, argv[++i], sizeof(options.fuzz_module));
        }
        else if (strcmp(token, "-target_method") == 0)
        {
            strncpy(options.fuzz_method, argv[++i], sizeof(options.fuzz_method));
        }
        else if (strcmp(token, "-fuzz_iterations") == 0)
        {
            options.fuzz_iterations = atoi(argv[++i]);
        }
        else if (strcmp(token, "-nargs") == 0)
        {
            options.num_fuz_args = atoi(argv[++i]);
        }
        else if (strcmp(token, "-target_offset") == 0)
        {
            options.fuzz_offset = strtoul(argv[++i], NULL, 0);
        }
        else if (strcmp(token, "-call_convention") == 0)
        {
            ++i;
            if (strcmp(argv[i], "stdcall") == 0)
                options.callconv = DRWRAP_CALLCONV_CDECL;
            else if (strcmp(argv[i], "fastcall") == 0)
                options.callconv = DRWRAP_CALLCONV_FASTCALL;
            else if (strcmp(argv[i], "thiscall") == 0)
                options.callconv = DRWRAP_CALLCONV_THISCALL;
            else if (strcmp(argv[i], "ms64") == 0)
                options.callconv = DRWRAP_CALLCONV_MICROSOFT_X64;
            else
            {
                dr_printf("Unknown calling convention, using default value instead.\n");
                dr_abort();
            }
                
        }
        else if (strcmp(token, "-no_loop") == 0)
        {
            options.no_loop = true;
        }
        else if (strcmp(token, "-drpersist") == 0)
        {
            options.dr_persist_cache = true;
        }
        else if (strcmp(token, "-persistence_mode") == 0)
        {
            const char *mode = argv[++i];
            if (strcmp(mode, "in_app") == 0)
            {
                options.persistence_mode = in_app;
            }
            else
            {
                options.persistence_mode = native_mode;
            }
        }
        else
        {
            dr_printf("UNRECOGNIZED OPTION: \"%s\"\n", token);
            dr_abort();
        }
    }

    if (options.fuzz_module[0] && (options.fuzz_offset == 0) && (options.fuzz_method[0] == 0))
    {
        dr_printf("If fuzz_module is specified, then either fuzz_method or fuzz_offset must be as well\n");
        dr_abort();
    }

    if (options.num_fuz_args)
    {
        options.func_args = (void **)dr_global_alloc(options.num_fuz_args * sizeof(void *));
    }
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drreg_options_t ops = {sizeof(ops), 2 /*max slots needed: aflags*/, false};

    dr_set_client_name("WinAFL", "");

    drmgr_init();
    drx_init();
    drreg_init(&ops);
    drwrap_init();
    drsym_init(0);

    dr_printf("options_init\n");
    options_init(id, argc, argv);

    dr_register_exit_event(event_exit);

#ifdef _WINDOWS
    drmgr_register_exception_event(onexception);
#else
    drmgr_register_signal_event(onexception);
#endif

    dr_printf("drmgr_register_bb_instrumentation_event\n");
    drmgr_register_bb_instrumentation_event(NULL, instrument_edge_coverage, NULL);

    drmgr_register_module_load_event(event_module_load);
    drmgr_register_module_unload_event(event_module_unload);
    dr_register_nudge_event(event_nudge, id);

    client_id = id;

    if (options.nudge_kills)
        drx_register_soft_kills(event_soft_kill);

    if (!options.debug_mode)
    {
        setup_pipe();
        setup_shmem();
    }
    else
    {
        winafl_data.afl_area = (unsigned char *)dr_global_alloc(MAP_SIZE);
    }

    event_init();
}
