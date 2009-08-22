#include <errno.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <bits/siginfo.h>
#include <linux/ptrace.h>

/*
    Imposes the following restrictions:

    Restricts:              Argument:       Method:
    ----------------------- --------------- ---------------------
    Coredumps               (always)        setrlimit(RLIMIT_CORE, 0)
    Process/thread creation -s              syscall wrapper
    Socket access           -s              syscall wrapper
    Clock time limit        -T              alarm()
    CPU time limit          -t              setrlimit(RLIMIT_CPU)
    Memory limit            -m              setrlimit(RLIMIT_AS)
    Output size             -o              setrlimit(RLIMIT_FSIZE)
    File access             -r              chroot()
    User                    -u              setuid()

    CPU time limit is geven on the command line in seconds.
    The wall clock time limit is derived as ceil(t*1.2) in seconds.

    TODO: create test cases for failing AND succeeding programs
*/

#define E_SUCCESS           (0)     /* No errors; status == 0 */
#define E_FAILURE           (1)     /* No errors; status != 0*/
#define E_INTERNAL          (2)     /* Guarded execution failed */
#define E_EXEC              (3)     /* exec() failed */
#define E_SYSCALL           (4)     /* Forbidden syscall */
#define E_KILLED            (5)     /* Process was killed */
#define E_CPU_TIME          (6)     /* CPU time limit exceeded */
#define E_GLOBAL_TIME       (7)     /* Global time limit exceeded */

static bool verbose;
static bool limit_syscalls;	/* If set, restricts system calls */
static int limit_time_cpu;      /* In seconds -- 0 if no limit */
static int limit_time_total;    /* Wall clock time -- 0 if no limit */
static int limit_memory;        /* In bytes -- 0 if no limit */
static int limit_output;        /* In bytes -- 0 if no limit */
static const char *limit_root;  /* Root path -- NULL if no chroot */
static uid_t limit_uid;         /* User id + 1 -- 0 if no setuid */

static pid_t child_pid;         /* Stores the PID of the child process */
static bool alarmed;            /* Set if the alarm signal was received */

void checked_setrlimit(int resource, rlim_t value)
{
    struct rlimit rlim = { value, value };

    if (setrlimit(resource, &rlim) != 0)
    {
        perror("setrlimit() failed");
        exit(E_INTERNAL);
    }
}

void run_child(char *cmdline[])
{
    /* Disable core dumps */
    checked_setrlimit(RLIMIT_CORE, 0);

    /* Impose CPU time limit */
    if (limit_time_cpu > 0)
        checked_setrlimit(RLIMIT_CPU, limit_time_cpu);

    /* Impose memory limit */
    if (limit_memory > 0)
        checked_setrlimit(RLIMIT_AS, limit_memory);

    /* Impose output limit */
    if (limit_output > 0)
    {
        sigset_t ss;
        checked_setrlimit(RLIMIT_FSIZE, limit_output);
        sigemptyset(&ss);
        sigaddset(&ss, SIGXFSZ);
        if (sigprocmask(SIG_BLOCK, &ss, 0) != 0)
        {
            perror("chroot() failed");
            exit(1);
        }
    }

    /* Restrict file system access */
    if (limit_root != NULL)
    {
        if (chroot(limit_root) != 0)
        {
            perror("chroot() failed");
            exit(1);
        }
    }

    /* Change (effective/real/saved) user id */
    if (limit_uid > 0)
    {
        if (setuid(limit_uid - 1) != 0)
        {
            perror("setuid() failed");
            exit(1);
        }
    }

    /* if (limit_syscalls) */
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            perror("ptrace() in child failed");
            exit(1);
        }
    }

    /* HACK: prevent forking (instead of just detecting it) */
    if (limit_syscalls)
    {
        checked_setrlimit(RLIMIT_NPROC, 1);
    }

    execvp(*cmdline, cmdline);
    perror("exec() failed");
    exit(1);
}

bool disallowed(int id)
{
    return limit_syscalls && (
        id ==   2 ||    /* fork */
        id ==  11 ||    /* execve */
        id == 102 ||    /* socketcall */
        id == 120 ||    /* clone */
        id == 190 );    /* vfork */
}

long checked_ptrace(int request, void *addr, void *data)
{
    long res;

    res = ptrace(request, child_pid, addr, data);
    if (res < 0)
    {
        perror("ptrace() failed");
        exit(E_INTERNAL);
    }

    return res;
}

void alarm_handler(int sig)
{
    /* sig == SIGALRM */
    alarmed = true;
    checked_ptrace(PTRACE_KILL, NULL, NULL);
}

void run_parent()
{
    int num_traps = 0;

    /* Impose global time limit */
    if (limit_time_total > 0)
    {
        struct sigaction sa = { };
        sa.sa_handler = alarm_handler;
        if (sigaction(SIGALRM, &sa, NULL) != 0)
        {
            perror("sigaction() failed");
            exit(E_INTERNAL);
        }
        alarm(limit_time_total);
    }

    for(;;)
    {
        int status;

        if (waitpid(child_pid, &status, 0) != child_pid && !alarmed)
        {
            perror("waitpid() failed");
            exit(E_INTERNAL);
        }

        /* checked_ptrace(PTRACE_SETOPTIONS, 0, (void*)PTRACE_O_TRACESYSGOOD); */

        if (alarmed)
        {
            if (verbose)
                fprintf(stderr, "Global time limit exceeded!\n");
            exit(E_GLOBAL_TIME);
        }

        if (WIFEXITED(status))
        {
            if (num_traps < 3)
                exit(E_EXEC);

            if (verbose)
                fprintf(stderr, "Process exited with status %d.\n",
                    WEXITSTATUS(status));
            exit(WEXITSTATUS(status) == 0 ? E_SUCCESS : E_FAILURE);
        }

        if (WIFSIGNALED(status))
        {
            struct rusage ru;
            int secs;

            getrusage(RUSAGE_CHILDREN, &ru);
            /* Round time up */
            secs = ru.ru_utime.tv_sec + ru.ru_stime.tv_sec +
                (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec + 100*1000)/1000000;
            if (limit_time_cpu > 0 && secs >= limit_time_cpu)
            {
                if (verbose)
                    fprintf(stderr, "CPU time limit exceeded!\n");
                exit(E_CPU_TIME);
            }
            else
            {
                if (verbose)
                    fprintf(stderr, "Process was killed by signal %d.\n",
                        WTERMSIG(status));
                exit(E_KILLED);
            }
        }

        if (WIFSTOPPED(status))
        {
            siginfo_t si;
            struct user_regs_struct {
                long ebx, ecx, edx, esi, edi, ebp, eax;
                unsigned short ds, __ds, es, __es;
                unsigned short fs, __fs, gs, __gs;
                long orig_eax, eip;
                unsigned short cs, __cs;
                long eflags, esp;
                unsigned short ss, __ss;
            } regs;

            checked_ptrace(PTRACE_GETSIGINFO, NULL, &si);
            if (si.si_signo == SIGTRAP)     /* (SIGTRAP|0x80) */
            {
                checked_ptrace(PTRACE_GETREGS, NULL, &regs);
                if (num_traps > 0 && num_traps%2 == 0 && disallowed(regs.orig_eax))
                {
                    if (verbose)
                        fprintf(stderr, "Process attempted to perform "
                            "disallowed syscall %ld!\n", regs.orig_eax);
                    checked_ptrace(PTRACE_KILL, NULL, NULL);
                    exit(E_SYSCALL);
                }
                ++num_traps;

                /* checked_ptrace(PTRACE_SETOPTIONS, 0, (void*)PTRACE_O_TRACESYSGOOD); */
                checked_ptrace(PTRACE_SYSCALL, NULL, NULL);
            }
            else
            {
                /* checked_ptrace(PTRACE_SETOPTIONS, 0, (void*)PTRACE_O_TRACESYSGOOD); */
                checked_ptrace(PTRACE_SYSCALL, NULL, (void*)si.si_signo);
            }
        }
    }

    /* does not return */
}

const char *parse_dir(const char *path)
{
    struct stat st;

    if (stat(optarg, &st) != 0)
    {
        fprintf(stderr, "Could not stat \"%s\": %s\n", path, strerror(errno));
        exit(1);
    }

    if (!S_ISDIR(st.st_mode))
    {
        fprintf(stderr, "\"%s\" is not a directory.\n", path);
        exit(1);
    }

    return path;
}

uid_t parse_user(const char *user)
{
    struct passwd *pw;
    int uid;
    char dummy;

    if (sscanf(optarg, "%d%c", &uid, &dummy) == 1)
    {
        if ((pw = getpwuid((uid_t)uid)) == NULL)
        {
            fprintf(stderr, "Invalid user id: %s\n", optarg);
            exit(1);
        }
    }
    else
    {
        if ((pw = getpwnam(user)) == NULL)
        {
            fprintf(stderr, "Invalid user name: %s\n", optarg);
            exit(1);
        }
    }

    return pw->pw_uid;
}

int parse_size(const char *str)
{
    int i;
    char *end;

    i = strtol(str, &end, 10);
    if (str == end)
        goto invalid;

    if (end[0] != '\0')
    {
        if (!(end[1] == '\0' || (end[2] == '\0' && (end[1] != 'B' || end[1] != 'b'))))
            goto invalid;

        if (end[0] == 'K' || end[0] == 'k')
            i *= 1024;
        else
        if (end[0] == 'M' || end[0] == 'm')
            i *= 1024*1024;
        else
        if (end[0] == 'G' || end[0] == 'g')
            i *= 1024*1024*1024;
        else
            goto invalid;
    }
    return i;

invalid:
    fprintf(stderr, "Invalid size: %s\n", str);
    exit(1);
}

void usage(int status)
{
    printf(
"Usage: runguard [options] [executable] [arguments...]\n"
"\n"
"Runs a program in a restricted environment.\n"
"\n"
"The executable must be a real executable (ie. not a shell command) and its path\n"
"must be given relative to the filesystem root (specified with -r).\n"
"\n"
"Options are:\n"
"   -T <time>   Maximum execution time (in wall-clock seconds)\n"
"   -t <time>   Maximum execution time (in CPU seconds)\n"
"   -m <size>   Maximum virtual memory allowed (in bytes)\n"
"   -o <size>   Maximum output size (in bytes)\n"
"   -r <dir>    Filesystem root (root only!)\n"
"   -u <uid>    Execute as user (userid or username) (root only!)\n"
"   -s          Restricted system calls\n"
"   -v          Verbose\n"
"\n"
"Upon exit the status code is set to one of:\n"
"   0       No errors occured; child exited with zero status\n"
"   1       No errors occured; child exited with non-zero status\n"
"   2       Internal error; guarded execution failed!\n"
"   3       exec() failed; argument was not executable\n"
"   4       Child process attempted to make a forbidden system call\n"
"   5       Child process was killed; either because of a runtime error (eg\n"
"           segmentation fault) or because the memory limit was exceeded\n"
"   6       CPU time limit exceeded\n"
"   7       Global time limit exceeded. This occurs when the process spends too\n"
"           much time sleeping or waiting on I/O, or when the system load is too\n"
"           high.\n"
"\n"
"Normally, runguard does not print any output, except when an internal error\n"
"occurs. If -v is given, a text description is printed when the process exits,\n"
"in addition to reporting the cause as a status code.\n"
    );
    exit(status);
}

int main(int argc, char *argv[])
{
    int n;

    if (argc < 2)
        usage(0);

    while ((n = getopt(argc, argv, "T:t:m:o:r:u:sv")) != -1)
    {
        char dummy;
        switch(n)
        {
        case 'T':
            if (sscanf(optarg, "%d%c", &limit_time_total, &dummy) != 1)
            {
                fprintf(stderr, "Invalid time limit: %s\n", optarg);
                exit(1);
            }
            break;
        case 't':
            if (sscanf(optarg, "%d%c", &limit_time_cpu, &dummy) != 1)
            {
                fprintf(stderr, "Invalid time limit: %s\n", optarg);
                exit(1);
            }
            break;
        case 'm':
            limit_memory = parse_size(optarg);
            break;
        case 'o':
            limit_output = parse_size(optarg);
            break;
        case 'r':
            limit_root = parse_dir(optarg);
            break;
        case 'u':
            limit_uid = 1 + parse_user(optarg);
            break;
        case 's':
            limit_syscalls = true;
            break;
        case 'v':
            verbose = true;
            break;
        }
    }

    if (optind >= argc)
        usage(1);

    child_pid = fork();
    if (child_pid == -1)
    {
        perror("fork() failed");
        exit(1);
    }
    else
    if (child_pid == 0)
    {
        run_child(argv + optind);
    }
    else
    {
        run_parent();
    }

    fprintf(stderr, "Should not get here!\n");
    exit(E_INTERNAL);
}
