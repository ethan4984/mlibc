#include <errno.h>
#include <type_traits>

#include <bits/feature.h>
#include <bits/ensure.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include "cxx-syscall.hpp"

#define STUB_ONLY { __ensure(!"STUB_ONLY function was called"); __builtin_unreachable(); }

#define NR_read 0
#define NR_write 1
#define NR_open 2
#define NR_close 3
#define NR_stat 4
#define NR_fstat 5
#define NR_lseek 8
#define NR_mmap 9
#define NR_sigaction 13
#define NR_rt_sigprocmask 14
#define NR_ioctl 16
#define NR_pipe 22
#define NR_select 23
#define NR_socket 41
#define NR_connect 42
#define NR_sendmsg 46
#define NR_recvmsg 47
#define NR_fork 57
#define NR_execve 59
#define NR_exit 60
#define NR_wait4 61
#define NR_fcntl 72
#define NR_unlink 87
#define NR_arch_prctl 158
#define NR_sys_futex 202
#define NR_clock_gettime 228
#define NR_pselect6 270
#define NR_pipe2 293

#define ARCH_SET_FS	0x1002

namespace mlibc {

void sys_libc_log(const char *message) {
	size_t n = 0;
	while(message[n])
		n++;
	do_syscall(NR_write, 2, message, n);
	char lf = '\n';
	do_syscall(NR_write, 2, &lf, 1);
}

void sys_libc_panic() {
	__builtin_trap();
}

int sys_tcb_set(void *pointer) {
	auto ret = do_syscall(NR_arch_prctl, ARCH_SET_FS, pointer);
	if(int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_anon_allocate(size_t size, void **pointer) {
	return sys_vm_map(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			-1, 0, pointer);
}
int sys_anon_free(void *pointer, size_t size) {
	return sys_vm_unmap(pointer, size);
}

int sys_open(const char *path, int flags, int *fd) {
        // TODO: pass mode in sys_open() sysdep
	auto ret = do_syscall(NR_open, path, flags, 0666);
	if(int e = sc_error(ret); e)
		return e;
	*fd = sc_int_result<int>(ret);
	return 0;
}

int sys_close(int fd) {
	auto ret = do_syscall(NR_close, fd);
	if(int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_read(int fd, void *buffer, size_t size, ssize_t *bytes_read) {
	auto ret = do_syscall(NR_read, fd, buffer, size);
	if(int e = sc_error(ret); e)
		return e;
	*bytes_read = sc_int_result<ssize_t>(ret);
	return 0;
}

int sys_write(int fd, const void *buffer, size_t size, ssize_t *bytes_written) {
	auto ret = do_syscall(NR_write, fd, buffer, size);
	if(int e = sc_error(ret); e)
		return e;
	*bytes_written = sc_int_result<ssize_t>(ret);
	return 0;
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
	auto ret = do_syscall(NR_lseek, fd, offset, whence);
	if(int e = sc_error(ret); e)
		return e;
	*new_offset = sc_int_result<off_t>(ret);
	return 0;
}

int sys_vm_map(void *hint, size_t size, int prot, int flags,
		int fd, off_t offset, void **window) {
	auto ret = do_syscall(NR_mmap, hint, size, prot, flags, fd, offset);
	// TODO: musl fixes up EPERM errors from the kernel.
	if(int e = sc_error(ret); e)
		return e;
	*window = sc_ptr_result<void>(ret);
	return 0;
}
int sys_vm_unmap(void *pointer, size_t size) STUB_ONLY

// All remaining functions are disabled in ldso.
#ifndef MLIBC_BUILDING_RTDL

int sys_clock_get(int clock, time_t *secs, long *nanos) {
        struct timespec tp = {};
        auto ret = do_syscall(NR_clock_gettime, clock, &tp);
        if (int e = sc_error(ret); e)
                return e;
        *secs = tp.tv_sec;
        *nanos = tp.tv_nsec;
        return 0;
}

int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
        (void) flags;
        sc_result_t ret;
        if(!path)
                ret = do_syscall(NR_fstat, fd, statbuf);
        else
                ret = do_syscall(NR_stat, path, statbuf);
        if (int e = sc_error(ret); e)
                return e;
        return 0;
}

int sys_sigaction(int signum, const struct sigaction *act,
                struct sigaction *oldact) {
        auto ret = do_syscall(NR_sigaction, signum, act, oldact, sizeof(sigset_t));
        if (int e = sc_error(ret); e)
                return e;
        return 0;
}

int sys_socket(int domain, int type, int protocol, int *fd) {
        auto ret = do_syscall(NR_socket, domain, type, protocol);
        if (int e = sc_error(ret); e)
                return e;
        *fd = sc_int_result<int>(ret);
        return 0;
}

int sys_msg_send(int sockfd, const struct msghdr *msg, int flags, ssize_t *length) {
        auto ret = do_syscall(NR_sendmsg, sockfd, msg, flags);
        if (int e = sc_error(ret); e)
                return e;
        *length = sc_int_result<ssize_t>(ret);
        return 0;
}

int sys_msg_recv(int sockfd, struct msghdr *msg, int flags, ssize_t *length) {
        auto ret = do_syscall(NR_recvmsg, sockfd, msg, flags);
        if (int e = sc_error(ret); e)
                return e;
        *length = sc_int_result<ssize_t>(ret);
        return 0;
}

int sys_fcntl(int fd, int cmd, va_list args, int *result) {
        auto arg = va_arg(args, unsigned long);
        // TODO: the api for linux differs for each command so fcntl()s might fail with -EINVAL
        // we should implement all the different fcntl()s
        auto ret = do_syscall(NR_fcntl, fd, cmd, arg);
        if (int e = sc_error(ret); e)
                return e;
        *result = sc_int_result<int>(ret);
        return 0;
}

int sys_unlink(const char *path) {
	auto ret = do_syscall(NR_unlink, path);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

#if __MLIBC_POSIX_OPTION

#include <sys/ioctl.h>

int sys_isatty(int fd) {
        struct winsize ws;
        auto ret = do_syscall(NR_ioctl, fd, TIOCGWINSZ, &ws);
        if (int e = sc_error(ret); e)
                return e;
        auto res = sc_int_result<unsigned long>(ret);
        if(!res) return 0;
        return 1;
}

int sys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
        auto ret = do_syscall(NR_connect, sockfd, addr, addrlen);
        if (int e = sc_error(ret); e)
                return e;
        return 0;
}

int sys_pselect(int nfds, fd_set *readfds, fd_set *writefds,
                fd_set *exceptfds, struct timeval *timeout, const sigset_t sigmask, int *num_events) {
        // The Linux kernel really wants 7 arguments, even tho this is not supported
        // To fix that issue, they use a struct as the last argument.
        // See the man page of pselect and the glibc source code
        struct {
                sigset_t ss;
                size_t ss_len;
        } data;
        data.ss = (uintptr_t)sigmask;
        data.ss_len = NSIG / 8;

        auto ret = do_syscall(NR_pselect6, nfds, readfds, writefds,
                        exceptfds, timeout, &data);
        if (int e = sc_error(ret); e)
                return e;
        *num_events = sc_int_result<int>(ret);
        return 0;
}

int sys_pipe(int *fds, int flags) {
        if(flags) {
                auto ret = do_syscall(NR_pipe2, fds, flags);
                if (int e = sc_error(ret); e)
                        return e;
                return 0;
        } else {
                auto ret = do_syscall(NR_pipe, fds);
                if (int e = sc_error(ret); e)
                        return e;
                return 0;
        }
}

int sys_fork(pid_t *child) {
        auto ret = do_syscall(NR_fork);
        if (int e = sc_error(ret); e)
                return e;
        *child = sc_int_result<int>(ret);
        return 0;
}

int sys_waitpid(pid_t pid, int *status, int flags, pid_t *ret_pid) {
        auto ret = do_syscall(NR_wait4, pid, status, flags, 0);
        if (int e = sc_error(ret); e)
                return e;
        *ret_pid = sc_int_result<int>(ret);
        return 0;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]) {
        auto ret = do_syscall(NR_execve, path, argv, envp);
        if (int e = sc_error(ret); e)
                return e;
        return 0;
}

int sys_sigprocmask(int how, const sigset_t *set, sigset_t *old) {
        auto ret = do_syscall(NR_rt_sigprocmask, how, set, old, NSIG / 8);
        if (int e = sc_error(ret); e)
                return e;
        return 0;
}

#endif // __MLIBC_POSIX_OPTION

void sys_exit(int status) {
	do_syscall(NR_exit, status);
	__builtin_trap();
}

#endif // MLIBC_BUILDING_RTDL

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

int sys_futex_wait(int *pointer, int expected) {
	auto ret = do_syscall(NR_sys_futex, pointer, FUTEX_WAIT, expected, nullptr);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_futex_wake(int *pointer) {
	auto ret = do_syscall(NR_sys_futex, pointer, FUTEX_WAKE, 1);
	if (int e = sc_error(ret); e)
		return e;
	auto num_woken = sc_int_result<int>(ret);
	__ensure(num_woken >= 0 && num_woken <= 1);
	return num_woken;
}

} // namespace mlibc
