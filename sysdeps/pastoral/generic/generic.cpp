#include <bits/ensure.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>

#define STUB_ONLY { __ensure(!"STUB_ONLY function was called"); __builtin_unreachable(); }

#define SYSCALL0(NUM) ({					 \
	asm volatile ("syscall"					 \
				  : "=a"(ret), "=d"(errno)	 \
				  : "a"(NUM)				 \
				  : "rcx", "r11", "memory"); \
})

#define SYSCALL1(NUM, ARG0) ({				 \
	asm volatile ("syscall"					 \
				  : "=a"(ret), "=d"(errno)	 \
				  : "a"(NUM), "D"(ARG0)		 \
				  : "rcx", "r11", "memory"); \
})

#define SYSCALL2(NUM, ARG0, ARG1) ({			   \
	asm volatile ("syscall"						   \
				  : "=a"(ret), "=d"(errno)		   \
				  : "a"(NUM), "D"(ARG0), "S"(ARG1) \
				  : "rcx", "r11", "memory");	   \
})

#define SYSCALL3(NUM, ARG0, ARG1, ARG2) ({					  \
	asm volatile ("syscall"									  \
				  : "=a"(ret), "=d"(errno)					  \
				  : "a"(NUM), "D"(ARG0), "S"(ARG1), "d"(ARG2) \
				  : "rcx", "r11", "memory");				  \
})

#define SYSCALL4(NUM, ARG0, ARG1, ARG2, ARG3) ({			   \
	register uint64_t arg3 asm("r10") = (uint64_t)ARG3;			   \
	asm volatile ("syscall"									   \
				  : "=a"(ret), "=d"(errno)					   \
				  : "a"(NUM), "D"(ARG0), "S"(ARG1), "d"(ARG2), \
					"r"(arg3)								   \
				  : "rcx", "r11", "memory");				   \
})

#define SYSCALL5(NUM, ARG0, ARG1, ARG2, ARG3, ARG4)				\
	register uint64_t arg3 asm("r10") = (uint64_t)ARG3;			\
	register uint64_t arg4 asm("r8") = (uint64_t)ARG4;			\
	asm volatile ("syscall"										\
				  : "=a"(ret), "=d"(errno)						\
				  : "a"(NUM), "D"(ARG0), "S"(ARG1), "d"(ARG2),	\
				  	"r"(arg3), "r"(arg4)						\
				  : "rcx", "r11", "memory");

#define SYSCALL6(NUM, ARG0, ARG1, ARG2, ARG3, ARG4, ARG5) ({   \
	register uint64_t arg3 asm("r10") = (uint64_t)ARG3;			   \
	register uint64_t arg4 asm("r8")  = (uint64_t)ARG4;			   \
	register uint64_t arg5 asm("r9")  = (uint64_t)ARG5;			   \
	asm volatile ("syscall"									   \
				  : "=a"(ret), "=d"(errno)					   \
				  : "a"(NUM), "D"(ARG0), "S"(ARG1), "d"(ARG2), \
					"r"(arg3), "r"(arg4), "r"(arg5)			   \
				  : "rcx", "r11", "memory");				   \
})

#define SYSCALL_OPENAT 0
#define SYSCALL_CLOSE 1
#define SYSCALL_READ 2
#define SYSCALL_WRITE 3
#define SYSCALL_LSEEK 4
#define SYSCALL_DUP 5
#define SYSCALL_DUP2 6
#define SYSCALL_MMAP 7
#define SYSCALL_MUNMAP 8
#define SYSCALL_SET_FS_BASE 9
#define SYSCALL_SET_GS_BASE 10
#define SYSCALL_GET_FS_BASE 11
#define SYSCALL_GET_GS_BASE 12
#define SYSCALL_LOG 13
#define SYSCALL_EXIT 14
#define SYSCALL_GETPID 15
#define SYSCALL_GETTID 16
#define SYSCALL_GETPPID 17
#define SYSCALL_ISATTY 18
#define SYSCALL_FCNTL 19
#define SYSCALL_FSTAT 20
#define SYSCALL_FSTATAT 21
#define SYSCALL_IOCTL 22
#define SYSCALL_FORK 23
#define SYSCALL_WAITPID 24
#define SYSCALL_READDIR 25
#define SYSCALL_EXECVE 26
#define SYSCALL_GETCWD 27
#define SYSCALL_CHDIR 28
#define SYSCALL_FACCESSAT 29
#define SYSCALL_PIPE 30
#define SYSCALL_UMASK 31
#define SYSCALL_GETUID 32
#define SYSCALL_GETEUID 33
#define SYSCALL_SETUID 34
#define SYSCALL_SETEUID 35
#define SYSCALL_GETGID 36
#define SYSCALL_GETEGID 37
#define SYSCALL_SETGID 38
#define SYSCALL_SETEGID 39
#define SYSCALL_FCHMOD 40
#define SYSCALL_FCHMODAT 41
#define SYSCALL_FCHOWNAT 42

namespace mlibc {

void sys_libc_log(const char *message) {
	int ret, errno;
	SYSCALL1(SYSCALL_LOG, message);
}

void sys_libc_panic() {
	sys_libc_log("\nMLIBC PANIC\n");
	sys_exit(255);
}

int sys_futex_wait(int *pointer, int expected, const struct timespec *time) STUB_ONLY
int sys_futex_wake(int *pointer) STUB_ONLY

void sys_exit(int status) {
	int ret, errno;
	SYSCALL1(SYSCALL_EXIT, status);
}

pid_t sys_getpgid(pid_t pid, pid_t *pgid) {
	mlibc::infoLogger() << "sys_getpgid() is unimplemented" << frg::endlog;
	*pgid = 0;

	return 0;
}

int sys_tcb_set(void *pointer) {
	int ret, errno;
	SYSCALL1(SYSCALL_SET_FS_BASE, pointer);
	return 0;
}

int sys_vm_map(void *hint, size_t size, int prot, int flags,
			   int fd, off_t offset, void **window) {
	void *ret;
	int errno;
	SYSCALL6(SYSCALL_MMAP, hint, size, prot, flags, fd, offset);
	if (ret == NULL)
		return errno;
	*window = ret;
	return 0;
}

int sys_vm_unmap(void *pointer, size_t size) {
	int ret, errno;
	SYSCALL2(SYSCALL_MUNMAP, pointer, size);
	if (ret == -1)
		return errno;
	return 0;
}

int sys_anon_allocate(size_t size, void **pointer) {
	int errno = sys_vm_map(NULL, size, PROT_EXEC | PROT_READ | PROT_WRITE,
						   MAP_ANONYMOUS, -1, 0, pointer);
	return errno;
}

int sys_anon_free(void *pointer, size_t size) {
	return 0;
}

int sys_open(const char *path, int flags, mode_t mode, int *fd) {
	int ret;
	int errno;

	SYSCALL4(SYSCALL_OPENAT, AT_FDCWD, path, flags, mode);

	if(ret == -1) {
		return errno;
	}

	*fd = ret;

	return 0;
}

int sys_openat(int dirfd, const char *path, int flags, mode_t mode, int *fd) {
	int ret;
	int errno;

	SYSCALL4(SYSCALL_OPENAT, dirfd, path, flags, mode);

	if(ret == -1) {
		return errno;
	}

	*fd = ret;

	return 0;
}

int sys_open_dir(const char *path, int *fd) {
	return sys_open(path, O_DIRECTORY, 0, fd);
}

int sys_close(int fd) {
	int ret, errno;
	SYSCALL1(SYSCALL_CLOSE, fd);
	if (ret == -1)
		return errno;
	return 0;
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
	off_t ret;
	int errno;
	SYSCALL3(SYSCALL_LSEEK, fd, offset, whence);
	if (ret == -1)
		return errno;
	*new_offset = ret;
	return 0;
}

int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
	ssize_t ret;
	int errno;
	SYSCALL3(SYSCALL_READ, fd, buf, count);
	if (ret == -1)
		return errno;
	*bytes_read = ret;
	return 0;
}

int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
	ssize_t ret;
	int errno;
	SYSCALL3(SYSCALL_WRITE, fd, buf, count);
	if (ret == -1)
		return errno;
	*bytes_written = ret;
	return 0;
}


pid_t sys_getpid() {
	pid_t ret;
	int errno;
	SYSCALL0(SYSCALL_GETPID);
	return ret;
}

pid_t sys_getppid() {
	pid_t ret;
	int errno;
	SYSCALL0(SYSCALL_GETPPID);
	return ret;
}

int sys_ttyname(int fd, char *buf, size_t size) {
	mlibc::infoLogger() << "mlibc: " << __func__ << " is a stub!\n" << frg::endlog;
	return ENOSYS;
}

int sys_clock_get(int clock, time_t *secs, long *nanos) {
	mlibc::infoLogger() << "mlibc: " << __func__ << " is a stub!\n" << frg::endlog;
	*secs  = 0;
	*nanos = 0;
	return 0;
}

int sys_gethostname(char *buffer, size_t bufsize) {
	const char *hostname = "pastoral";
	for (size_t i = 0; i < bufsize; i++) {
		buffer[i] = hostname[i];
		if (hostname[i] == 0)
			break;
	}
	mlibc::infoLogger() << "mlibc: " << __func__ << " is a stub!\n" << frg::endlog;
	return 0;
}

int sys_dup(int fd, int flags, int *newfd) {
	int errno, ret;
	SYSCALL1(SYSCALL_DUP, fd);
	if (ret == -1)
		return errno;
	*newfd = ret;
	return 0;
}

int sys_dup2(int fd, int flags, int newfd) {
	int errno, ret;
	SYSCALL2(SYSCALL_DUP2, fd, newfd);
	if (ret == -1)
		return errno;
	return 0;
}

int sys_fcntl(int fd, int request, va_list args, int *result) {
	int errno, ret;
	SYSCALL3(SYSCALL_FCNTL, fd, request, va_arg(args, uint64_t));
	if(ret == -1)
		return errno;
	*result = ret;
	return 0;
}

int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
	switch (fsfdt) {
		case fsfd_target::fd: {
			int errno, ret;
			SYSCALL2(SYSCALL_FSTAT, fd, statbuf);
			if (ret == -1)
				return errno;
			break;
		}
		case fsfd_target::path: {
			int errno, ret;
			SYSCALL4(SYSCALL_FSTATAT, AT_FDCWD, path, statbuf, flags);
			if (ret == -1)
				return errno;
			break;
		}
		case fsfd_target::fd_path: {
			int errno, ret;
			SYSCALL4(SYSCALL_FSTATAT, fd, path, statbuf, flags);
			if (ret == -1)
				return errno;
			break;
		}
		default: {
			__ensure(!"stat: Invalid fsfdt");
			__builtin_unreachable();
			return -1;
		}
	}
	return 0;
}

int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {
	mlibc::infoLogger() << "mlibc: " << __func__ << " is a stub!\n" << frg::endlog;
	return 0;
}

int sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
	mlibc::infoLogger() << "mlibc: " << __func__ << " is a stub!\n" << frg::endlog;
	return 0;
}

int sys_pselect(int num_fds, fd_set *read_set, fd_set *write_set, fd_set *except_set,
		const struct timespec *timeout, const sigset_t *sigmask, int *num_events) {
	mlibc::infoLogger() << "mlibc: " << __func__ << " is a stub!\n" << frg::endlog;
	return 0;
}

int sys_isatty(int fd) {
	return 0;
}

int sys_ioctl(int fd, unsigned long request, void *arg, int *result) {
	int ret;
	int errno;
	SYSCALL3(SYSCALL_IOCTL, fd, request, arg);
	if (ret == -1)
		return errno;
	*result = ret;
	return 0;
}

int sys_fork(pid_t *child) {
	pid_t ret;
	int errno;
	SYSCALL0(SYSCALL_FORK);
	if (ret == -1)
		return errno;
	*child = ret;
	return 0;
}

int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
	if(ru) {
		mlibc::infoLogger() << "mlibc: struct rusage in sys_waitpid is unsupported" << frg::endlog;
		return ENOSYS;
	}

	int errno, ret;
	SYSCALL3(SYSCALL_WAITPID, pid, status, flags);
	if (ret == -1)
		return errno;
	*ret_pid = ret;
	return 0;
}

int sys_read_entries(int fd, void *buffer, size_t max_size, size_t *bytes_read) {
	int ret;
	int errno;

	SYSCALL2(SYSCALL_READDIR, fd, buffer);

	if (ret == -1 && errno == 0) {
		/* end of dir */
		*bytes_read = 0;
		return 0;
	} else if (ret == -1) {
		return errno;
	}

	*bytes_read = sizeof(struct dirent);
	return 0;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]) {
	int errno, ret;
	SYSCALL3(SYSCALL_EXECVE, path, argv, envp);
	return errno;
}

int sys_faccessat(int dirfd, const char *pathname, int mode, int flags) {
	int ret, errno;
	SYSCALL4(SYSCALL_FACCESSAT, dirfd, pathname, mode, flags);

	if(ret == -1) {
		return errno;
	}

	return 0;
}

int sys_access(const char *path, int mode) {
	return sys_faccessat(AT_FDCWD, path, mode, 0);
}

int sys_getcwd(char *buffer, size_t size) {
	int errno, ret;
	SYSCALL2(SYSCALL_GETCWD, buffer, size);

	if(ret == 0)
		return errno;

	return 0;
}

int sys_chdir(const char *path) {
	int errno, ret;
	SYSCALL1(SYSCALL_CHDIR, path);

	if(ret == -1)
		return errno;

	return 0;
}

int sys_pipe(int *fds, int flags) {
	int errno, ret;
	SYSCALL2(SYSCALL_PIPE, fds, flags);

	if(ret == -1) {
		return errno;
	}

	return 0;
}

int sys_umask(mode_t mode, mode_t *old) {
	int errno, ret;
	SYSCALL1(SYSCALL_UMASK, mode);

	*old = ret;
	return mode;
}

uid_t sys_getuid() {
	int errno, ret;
	SYSCALL0(SYSCALL_GETUID);

	return ret;
}

uid_t sys_geteuid() {
	int errno, ret;
	SYSCALL0(SYSCALL_GETEUID);

	return ret;
}

int sys_setuid(uid_t uid) {
	int errno, ret;
	SYSCALL1(SYSCALL_SETUID, uid);

	if(ret == -1) {
		return errno;
	}

	return 0;
}

int sys_seteuid(uid_t euid) {
	int errno, ret;
	SYSCALL1(SYSCALL_SETEUID, euid);

	if(ret == -1) {
		return errno;
	}

	return 0;
}

uid_t sys_getgid() {
	int errno, ret;
	SYSCALL0(SYSCALL_GETGID);

	return ret;
}

uid_t sys_getegid() {
	int errno, ret;
	SYSCALL0(SYSCALL_GETEGID);

	return ret;
}


int sys_setgid(uid_t gid) {
	int errno, ret;
	SYSCALL1(SYSCALL_SETGID, gid);

	if(ret == -1) {
		return errno;
	}

	return 0;
}

int sys_setegid(uid_t egid) {
	int errno, ret;
	SYSCALL1(SYSCALL_SETEGID, egid);

	if(ret == -1) {
		return errno;
	}

	return 0;
}


int sys_fchmod(int fd, mode_t mode) {
	int errno, ret;
	SYSCALL2(SYSCALL_FCHMOD, fd, mode);

	if(ret == -1) {
		return errno;
	}

	return 0;
}

int sys_fchmodat(int fd, const char *pathname, mode_t mode, int flags) {
	int errno, ret;
	SYSCALL4(SYSCALL_FCHMODAT, fd, pathname, mode, flags);

	if(ret == -1) {
		return errno;
	}

	return 0;
}

int sys_chmod(const char *pathname, mode_t mode) {
	return sys_fchmodat(AT_FDCWD, pathname, mode, 0);
}

int sys_fchownat(int fd, const char *path, uid_t uid, gid_t gid, int flags) {
	int errno, ret;
	SYSCALL5(SYSCALL_FCHOWNAT, fd, path, uid, gid, flags);

	if(ret == -1) {
		return errno;
	}

	return 0;
}

} // namespace mlibc