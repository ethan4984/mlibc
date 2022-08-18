#ifndef _ABIBITS_SIGNAL_H
#define _ABIBITS_SIGNAL_H

#include <stdint.h>
#include <time.h>
#include <abi-bits/pid_t.h>
#include <abi-bits/uid_t.h>
#include <bits/size_t.h>

union sigval {
	int sival_int;
	void *sival_ptr;
};

typedef struct {
	int si_signo;
	int si_code;
	int si_errno;
	pid_t si_pid;
	uid_t si_uid;
	void *si_addr;
	int si_status;
	union sigval si_value;
} siginfo_t;

// Required for sys_sigaction sysdep.
#define SA_NOCLDSTOP 1
#define SA_NOCLDWAIT 2
#define SA_SIGINFO 4
#define SA_ONSTACK 0x08000000
#define SA_RESTART 0x10000000
#define SA_NODEFER 0x40000000
#define SA_RESETHAND 0x80000000
#define SA_RESTORER 0x04000000

#ifdef __cplusplus
extern "C" {
#endif

#define SIG_ERR ((__sighandler)(void *)(-1))
#define SIG_DFL ((__sighandler)(void *)(0))
#define SIG_IGN ((__sighandler)(void *)(1))

#define SIGABRT 6
#define SIGFPE 8
#define SIGILL 4
#define SIGINT 2
#define SIGSEGV 11
#define SIGTERM 15
#define SIGPROF 27
#define SIGIO 29
#define SIGPWR 30
#define SIGRTMIN 35
#define SIGRTMAX 64

// TODO: replace this by uint64_t
typedef long sigset_t;

// constants for sigprocmask()
#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2

#define SIGHUP    1
#define SIGQUIT   3
#define SIGTRAP   5
#define SIGIOT    SIGABRT
#define SIGBUS    7
#define SIGKILL   9
#define SIGUSR1   10
#define SIGUSR2   12
#define SIGPIPE   13
#define SIGALRM   14
#define SIGSTKFLT 16
#define SIGCHLD   17
#define SIGCONT   18
#define SIGSTOP   19
#define SIGTSTP   20
#define SIGTTIN   21
#define SIGTTOU   22
#define SIGURG    23
#define SIGXCPU   24
#define SIGXFSZ   25
#define SIGVTALRM 26
#define SIGWINCH  28
#define SIGPOLL   29
#define SIGSYS    31
#define SIGUNUSED SIGSYS
#define SIGCANCEL 32

#define MINSIGSTKSZ 2048
#define SIGSTKSZ 8192
#define SS_ONSTACK 1
#define SS_DISABLE 2

typedef struct __stack {
	void *ss_sp;
	int ss_flags;
	size_t ss_size;
} stack_t;

// constants for sigev_notify of struct sigevent
#define SIGEV_SIGNAL 0
#define SIGEV_NONE 1
#define SIGEV_THREAD 2

#define SEGV_MAPERR 1
#define SEGV_ACCERR 2

#define BUS_ADRALN 1

#define ILL_ILLOPC 1
#define ILL_ILLTRP 4
#define ILL_PRVOPC 5

#define NSIG 65

#define SI_ASYNCNL (-60)
#define SI_TKILL (-6)
#define SI_SIGIO (-5)
#define SI_ASYNCIO (-4)
#define SI_MESGQ (-3)
#define SI_TIMER (-2)
#define SI_QUEUE (-1)
#define SI_USER 0
#define SI_KERNEL 128

#define REG_R8 0
#define REG_R9 1
#define REG_R10 2
#define REG_R11 3
#define REG_R12 4
#define REG_R13 5
#define REG_R14 6
#define REG_R15 7
#define REG_RDI 8
#define REG_RSI 9
#define REG_RBP 10
#define REG_RBX 11
#define REG_RDX 12
#define REG_RAX 13
#define REG_RCX 14
#define REG_RSP 15
#define REG_RIP 16
#define REG_EFL 17
#define REG_CSGSFS 18
#define REG_ERR 19
#define REG_TRAPNO 20
#define REG_OLDMASK 21
#define REG_CR2 22
#define NGREG 23

struct sigevent {
	union sigval sigev_value;
	int sigev_notify;
	int sigev_signo;
	void (*sigev_notify_function)(union sigval);
	// MISSING: sigev_notify_attributes
};

struct sigaction {
	union {
		void (*sa_handler)(int);
		void (*sa_sigaction)(int, siginfo_t *, void *);
	} __sa_handler;
	sigset_t sa_mask;
	int sa_flags;
	void (*sa_restorer)(void);
};
#define sa_handler __sa_handler.sa_handler
#define sa_sigaction __sa_handler.sa_sigaction

// Taken from the linux kernel headers

#if defined(__x86_64__)

struct _fpreg {
	unsigned short significand[4];
	unsigned short exponent;
};

struct _fpxreg {
	unsigned short significand[4];
	unsigned short exponent;
	unsigned short padding[3];
};

struct _xmmreg {
	uint32_t element[4];
};

struct _fpstate {
	uint16_t cwd;
	uint16_t swd;
	uint16_t ftw;
	uint16_t fop;
	uint64_t rip;
	uint64_t rdp;
	uint32_t mxcsr;
	uint32_t mxcr_mask;
	struct _fpxreg _st[8];
	struct _xmmreg _xmm[16];
	uint32_t padding[24];
};

typedef struct {
	unsigned long gregs[NGREG];
	struct _fpstate *fpstate;
	unsigned long __reserved1[8];
} mcontext_t;

typedef struct __ucontext {
	unsigned long uc_flags;
	struct __ucontext *uc_link;
	stack_t uc_stack;
	mcontext_t uc_mcontext;
	sigset_t uc_sigmask;
} ucontext_t;

#else
#error "Missing architecture specific code."
#endif

#ifdef __cplusplus
}
#endif

#endif // _ABIBITS_SIGNAL_H
