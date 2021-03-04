/*
 * Copyright (c) 2015-2021 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>

#include <lttng/lttng.h>
#include <lttng/handle.h>
#include <lttng/session.h>
#include <lttng/tracker.h>

#define MESSAGE_PREFIX "[lttng-trace] "
#define NR_HANDLES	2

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP	128
#endif

#define PERROR(msg)		perror(msg "\n")
#define ERR(fmt, args...)	fprintf(stderr, fmt "\n", ## args)

#ifdef DEBUG
#define DBG(fmt, args...)	printf(fmt "\n", ## args)
#else
#define DBG(fmt, args...)
#endif

#define __unused __attribute__((unused))

static pid_t sigfwd_pid;

static bool opt_help = false,
	    opt_no_context = false,
	    opt_no_pause = false,
	    opt_no_syscall = false,
	    opt_session = false,
	    opt_view = false,
	    opt_output = false;

static const char *output_path;
static const char *session_name;

struct lttng_trace_ctx {
	char session_name[LTTNG_NAME_MAX];
	char path[PATH_MAX];
	time_t creation_time;
};

static
long ptrace_setup(pid_t pid)
{
	long ptrace_ret;
	unsigned long flags;

	flags = PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT
		| PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK
		| PTRACE_O_TRACEEXEC;
	//ptrace_ret = ptrace(PTRACE_SETOPTIONS, pid,
	ptrace_ret = ptrace(PTRACE_SEIZE, pid,
		NULL, (void *) flags);
	if (ptrace_ret) {
		//PERROR("ptrace setoptions");
		PERROR("ptrace seize");
		return -1;
	}
	return 0;
}

static
int wait_on_children(pid_t top_pid, struct lttng_handle **handle,
		size_t nr_handles)
{
	pid_t pid;
	long ptrace_ret;
	int ret;
	size_t i;

	pid = top_pid;
	DBG("Setup ptrace options on top child pid %d", pid);
	ret = ptrace_setup(pid);
	if (ret) {
		return ret;
	}
	for (i = 0; i < nr_handles; i++) {
		ret = lttng_track_pid(handle[i], pid);
		if (ret && ret != -LTTNG_ERR_INVALID) {
			ERR("Error %d tracking pid %d", ret, pid);
		}
	}
	top_pid = -1;
	/* Restart initial raise(SIGSTOP) */
	//ptrace_ret = ptrace(PTRACE_CONT, pid, 0, restartsig);
	//TODO wait for child to have stopped....
	ret = kill(pid, SIGCONT);
	if (ret) {
	//if (ptrace_ret) {
		PERROR("kill");
		return -1;
	}

	for (;;) {
		int status;

		pid = waitpid(-1, &status, __WALL);
		DBG("Activity on child pid %d", pid);
		if (pid < 0) {
			if (errno == ECHILD) {
				/* No more children to possibly wait for. */
				return 0;
			} else {
				PERROR("waitpid");
				return -1;
			}
		} else if (pid == 0) {
			ERR("Unexpected PID 0");
			return -1;
		} else {
			if (WIFSTOPPED(status)) {
				int shiftstatus, restartsig;

				DBG("Child pid %d is stopped", pid);
				shiftstatus = status >> 8;
				if (shiftstatus == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
					DBG("Child pid %d is exiting", pid);
#if 0
					for (i = 0; i < nr_handles; i++) {
						ret = lttng_untrack_pid(handle[i], pid);
						if (ret && ret != -LTTNG_ERR_INVALID) {
							ERR("Error %d untracking pid %d", ret, pid);
						}
					}
#endif
				} else if (shiftstatus == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
					long newpid;

					ptrace_ret = ptrace(PTRACE_GETEVENTMSG, pid, 0, &newpid);
					if (ptrace_ret) {
						PERROR("ptrace");
						return -1;
					}
					DBG("Child pid %d is forking, child pid %ld", pid, newpid);
					for (i = 0; i < nr_handles; i++) {
						ret = lttng_track_pid(handle[i], newpid);
						if (ret && ret != -LTTNG_ERR_INVALID) {
							ERR("Error %d tracking pid %ld", ret, newpid);
						}
					}
				} else if (shiftstatus == (SIGTRAP | (PTRACE_EVENT_VFORK << 8))) {
					long newpid;

					ptrace_ret = ptrace(PTRACE_GETEVENTMSG, pid, 0, &newpid);
					if (ptrace_ret) {
						PERROR("ptrace");
						return -1;
					}
					DBG("Child pid %d issuing vfork, child pid %ld", pid, newpid);
					for (i = 0; i < nr_handles; i++) {
						ret = lttng_track_pid(handle[i], newpid);
						if (ret && ret != -LTTNG_ERR_INVALID) {
							ERR("Error %d tracking pid %ld", ret, newpid);
						}
					}
				} else if (shiftstatus == (SIGTRAP | PTRACE_EVENT_CLONE << 8)) {
					long newpid;

					ptrace_ret = ptrace(PTRACE_GETEVENTMSG, pid, 0, &newpid);
					if (ptrace_ret) {
						PERROR("ptrace");
						return -1;
					}
					DBG("Child pid %d issuing clone, child pid %ld", pid, newpid);
					for (i = 0; i < nr_handles; i++) {
						ret = lttng_track_pid(handle[i], newpid);
						if (ret && ret != -LTTNG_ERR_INVALID) {
							ERR("Error %d tracking pid %ld", ret, newpid);
						}
					}
				} else if (shiftstatus == (SIGTRAP | PTRACE_EVENT_EXEC << 8)) {
					long oldpid;

					ptrace_ret = ptrace(PTRACE_GETEVENTMSG, pid, 0, &oldpid);
					if (ptrace_ret) {
						PERROR("ptrace");
						return -1;
					}
					DBG("Child pid (old: %ld, new: %d) is issuing exec",
							oldpid, pid);
					/*
					 * Needed for exec issued from
					 * multithreaded process.
					 */
					for (i = 0; i < nr_handles; i++) {
						ret = lttng_untrack_pid(handle[i], oldpid);
						if (ret && ret != -LTTNG_ERR_INVALID) {
							ERR("Error %d untracking pid %ld", ret, oldpid);
						}
						ret = lttng_track_pid(handle[i], pid);
						if (ret && ret != -LTTNG_ERR_INVALID) {
							ERR("Error %d tracking pid %d", ret, pid);
						}
					}
				} else if (shiftstatus == SIGTRAP) {
					DBG("Received SIGTRAP from pid %d without event of interest", pid);
				} else if (shiftstatus == SIGSTOP) {
					DBG("Received SIGSTOP from pid %d without event of interest", pid);
				} else if (shiftstatus == SIGSEGV) {
					DBG("Received SIGSEGV from pid %d without event of interest", pid);
				} else if (shiftstatus == SIGTTIN) {
					DBG("Received SIGTTIN from pid %d without event of interest", pid);
				} else if (shiftstatus == SIGTTOU) {
					DBG("Received SIGTTOU from pid %d without event of interest", pid);
				} else if (shiftstatus == SIGTSTP) {
					DBG("Received SIGTSTP from pid %d without event of interest", pid);
				} else {
					DBG("Ignoring signal %d (status %d) from pid %d (eventcode = %u)",
						WSTOPSIG(status), status, pid,
						(shiftstatus & ~WSTOPSIG(status)) >> 8);
				}

				restartsig = WSTOPSIG(status);
				switch (restartsig) {
				case SIGTSTP:
				case SIGTTIN:
				case SIGTTOU:
				case SIGSTOP:
				{
					//siginfo_t siginfo;

					errno = 0;
					//ptrace_ret = ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo);
					//if (ptrace_ret < 0 && errno == EINVAL) {
					if (restartsig == SIGTTIN) {
						ret = kill(pid, SIGTTIN);
						if (ret) {
							PERROR("kill");
							return -1;
						}
					} else if (status >> 16 == PTRACE_EVENT_STOP) {
						DBG("ptrace stop");
						//ptrace_ret = ptrace(PTRACE_LISTEN, pid, 0, 0);
						ptrace_ret = ptrace(PTRACE_CONT, pid, 0, 0);
						if (ptrace_ret) {
							PERROR("ptrace cont");
							return -1;
						}
					} else {
						DBG("job control stop ret %ld errno %d", ptrace_ret, errno);
						/*
						 * It's not a group-stop, so restart process,
						 * skipping the signal.
						 */
						ptrace_ret = ptrace(PTRACE_CONT, pid, 0, 0);
						if (ptrace_ret) {
							PERROR("ptrace cont");
							return -1;
						}
					}
					break;
				}
				case SIGTRAP:
				{
					//unsigned long data;

					//if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &data) == 0) {
						/*
						 * Restart process skipping the signal when
						 * receiving a message.
						 */
						ptrace_ret = ptrace(PTRACE_CONT, pid, 0, 0);
						if (ptrace_ret) {
							PERROR("ptrace");
							return -1;
						}
						break;
					//}
				}
					/* Fall-through */
				default:
					/* Restart with original signal. */
					ptrace_ret = ptrace(PTRACE_CONT, pid, 0, restartsig);
					if (ptrace_ret) {
						PERROR("ptrace");
						return -1;
					}
				}
			} else if (WIFEXITED(status)) {
				DBG("Child pid %d exited normally with status %d",
					pid, WEXITSTATUS(status));
				for (i = 0; i < nr_handles; i++) {
					ret = lttng_untrack_pid(handle[i], pid);
					if (ret && ret != -LTTNG_ERR_INVALID) {
						ERR("Error %d tracking pid %d", ret, pid);
					}
				}
			} else if (WIFSIGNALED(status)) {
				DBG("Child pid %d terminated by signal %d", pid,
					WTERMSIG(status));
				for (i = 0; i < nr_handles; i++) {
					ret = lttng_untrack_pid(handle[i], pid);
					if (ret && ret != -LTTNG_ERR_INVALID) {
						ERR("Error %d tracking pid %d", ret, pid);
					}
				}
			} else {
				DBG("Unhandled status %d from child %d", status, pid);
			}
		}
	}
}

static
int run_child(int argc, char **argv)
{
	pid_t pid;
	int ret;

	if (argc < 1) {
		ERR("Please provide executable name as first argument.");
		return -1;
	}

	pid = fork();
	if (pid > 0) {
		/* In parent */
		DBG("Child process created (pid: %d)", pid);
	} else if (pid == 0) {
		/* In child */
#if 0
		long ptraceret;

		ptraceret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		if (ptraceret) {
			PERROR("ptrace");
			exit(EXIT_FAILURE);
		}
#endif
		ret = raise(SIGSTOP);
		if (ret) {
			PERROR("raise");
			exit(EXIT_FAILURE);
		}
		ret = execvp(argv[0], &argv[0]);
		if (ret) {
			PERROR("execvp");
			exit(EXIT_FAILURE);
		}
	} else {
		PERROR("fork");
		return -1;
	}
	return pid;
}

static
int create_session(struct lttng_trace_ctx *ctx)
{
	return lttng_create_session(ctx->session_name, ctx->path);
}

static
int destroy_session(struct lttng_trace_ctx *ctx)
{
	return lttng_destroy_session(ctx->session_name);
}

static
int start_session(struct lttng_trace_ctx *ctx)
{
	return lttng_start_tracing(ctx->session_name);
}

static
int enable_syscalls(struct lttng_trace_ctx *ctx)
{
	struct lttng_domain domain;
	struct lttng_event *ev;
	struct lttng_handle *handle;
	int ret = 0;

	if (opt_no_syscall)
		return 0;
	memset(&domain, 0, sizeof(domain));
	ev = lttng_event_create();
	if (!ev) {
		ERR("Error creating event");
		goto end;
	}
	domain.type = LTTNG_DOMAIN_KERNEL;
	domain.buf_type = LTTNG_BUFFER_GLOBAL;

	handle = lttng_create_handle(ctx->session_name, &domain);
	if (!handle) {
		ERR("Error creating handle");
		ret = -1;
		goto error_handle;
	}
	ev->type = LTTNG_EVENT_SYSCALL;
	strcpy(ev->name, "*");
	ev->loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;
	ret = lttng_enable_event_with_exclusions(handle,
			ev, NULL, NULL, 0, NULL);
	if (ret) {
		ERR("Error enabling syscall events");
		ret = -1;
	}
	lttng_destroy_handle(handle);
error_handle:
	lttng_event_destroy(ev);
end:
	return ret;
}

static
int add_contexts(struct lttng_trace_ctx *ctx, enum lttng_domain_type domain_type)
{
	struct lttng_domain domain;
	struct lttng_event_context event_ctx;
	struct lttng_handle *handle;
	const char *domain_str;
	int ret = 0;

	if (opt_no_context)
		return 0;
	memset(&domain, 0, sizeof(domain));
	switch (domain_type) {
	case LTTNG_DOMAIN_KERNEL:
		domain.buf_type = LTTNG_BUFFER_GLOBAL;
		domain_str = "kernel";
		break;
	case LTTNG_DOMAIN_UST:
		domain.buf_type = LTTNG_BUFFER_PER_UID;
		domain_str = "ust";
		break;
	default:
		return -1;
	}
	domain.type = domain_type;

	handle = lttng_create_handle(ctx->session_name, &domain);
	if (!handle) {
		ERR("Error creating handle");
		ret = -1;
		goto end;
	}
	memset(&event_ctx, 0, sizeof(event_ctx));
	event_ctx.ctx = LTTNG_EVENT_CONTEXT_PROCNAME;
	if (lttng_add_context(handle, &event_ctx, NULL, NULL) < 0) {
		ERR("Error adding `procname` context to domain `%s`", domain_str);
		ret = -1;
		goto error_context;
	}
	memset(&event_ctx, 0, sizeof(event_ctx));
	event_ctx.ctx = LTTNG_EVENT_CONTEXT_VPID;
	if (lttng_add_context(handle, &event_ctx, NULL, NULL) < 0) {
		ERR("Error adding `vpid` context to domain `%s`", domain_str);
		ret = -1;
		goto error_context;
	}
	memset(&event_ctx, 0, sizeof(event_ctx));
	event_ctx.ctx = LTTNG_EVENT_CONTEXT_VTID;
	if (lttng_add_context(handle, &event_ctx, NULL, NULL) < 0) {
		ERR("Error adding `vtid` context to domain `%s`", domain_str);
		ret = -1;
		goto error_context;
	}

error_context:
	lttng_destroy_handle(handle);
end:
	return ret;
}

static
int create_channels(struct lttng_trace_ctx *ctx, enum lttng_domain_type domain_type)
{
	struct lttng_domain domain;
	struct lttng_channel *channel;
	struct lttng_handle *handle;
	const char *domain_str;
	int ret = 0;

	memset(&domain, 0, sizeof(domain));
	switch (domain_type) {
	case LTTNG_DOMAIN_KERNEL:
		domain.buf_type = LTTNG_BUFFER_GLOBAL;
		domain_str = "kernel";
		break;
	case LTTNG_DOMAIN_UST:
		domain.buf_type = LTTNG_BUFFER_PER_UID;
		domain_str = "ust";
		break;
	default:
		return -1;
	}
	domain.type = domain_type;
	channel = lttng_channel_create(&domain);
	if (!channel) {
		ERR("Error creating channel for domain `%s`", domain_str);
		ret = -1;
		goto end;
	}
	channel->enabled = 1;

	handle = lttng_create_handle(ctx->session_name, &domain);
	if (!handle) {
		ERR("Error creating handle");
		ret = -1;
		goto error_handle;
	}
	if (lttng_enable_channel(handle, channel) < 0) {
		ERR("Error enabling channel for domain `%s`", domain_str);
		ret = -1;
	}
	lttng_destroy_handle(handle);
error_handle:
	lttng_channel_destroy(channel);
end:
	return ret;
}

static
struct lttng_handle *create_kernel_handle(struct lttng_trace_ctx *ctx)
{
	struct lttng_domain domain;

	memset(&domain, 0, sizeof(domain));
	domain.type = LTTNG_DOMAIN_KERNEL;
	domain.buf_type = LTTNG_BUFFER_GLOBAL;
	return lttng_create_handle(ctx->session_name, &domain);
}

static
struct lttng_handle *create_ust_handle(struct lttng_trace_ctx *ctx)
{
	struct lttng_domain domain;

	memset(&domain, 0, sizeof(domain));
	domain.type = LTTNG_DOMAIN_UST;
	domain.buf_type = LTTNG_BUFFER_PER_UID;
	return lttng_create_handle(ctx->session_name, &domain);
}

static
void sighandler(int signo, siginfo_t *siginfo __unused, void *context __unused)
{
	int ret;

	DBG("sighandler receives signal %d, forwarding to child %d",
		signo, sigfwd_pid);
	ret = kill(sigfwd_pid, signo);
	if (ret) {
		PERROR("kill");
		abort();
	}
}

/*
 * Replace forbidden session name characters by '_'.
 */
static
void replace_session_chars(char *session_name)
{
	size_t len, i;

	len = strlen(session_name);
	for (i = 0; i < len; i++) {
		char *p = &session_name[i];
		switch (*p) {
		case '/':
			*p = '_';
			break;
		default:
			break;
		}
	}
}

static
int lttng_trace_ctx_init(struct lttng_trace_ctx *ctx, const char *cmd_name)
{
	char datetime[16];
	struct tm *timeinfo;

	ctx->creation_time = time(NULL);
	if (ctx->creation_time == (time_t) -1) {
		PERROR("time");
		return -1;
	}
	timeinfo = localtime(&ctx->creation_time);
	if (!timeinfo) {
		PERROR("localtime");
		return -1;
	}
	strftime(datetime, sizeof(datetime), "%Y%m%d-%H%M%S", timeinfo);

	if (opt_session) {
		if (strlen(session_name) > LTTNG_NAME_MAX - 1) {
			ERR("Session name is too long");
			return -1;
		}
		strcpy(ctx->session_name, session_name);
	} else {
		memset(ctx, 0, sizeof(*ctx));
		strncpy(ctx->session_name, cmd_name, LTTNG_NAME_MAX - 1);
		ctx->session_name[LTTNG_NAME_MAX - 1] = '\0';
		strcat(ctx->session_name, "-");
		strcat(ctx->session_name, datetime);
	}
	replace_session_chars(ctx->session_name);

	if (opt_output) {
		if (strlen(output_path) > PATH_MAX - 1) {
			ERR("output path is too long");
			return -1;
		}
		strcpy(ctx->path, output_path);
	} else {
		strcpy(ctx->path, "/tmp/lttng-trace/");
		strcat(ctx->path, ctx->session_name);
	}
	return 0;
}

static
int lttng_trace_untrack_all(struct lttng_handle **handle,
                size_t nr_handles)
{
	size_t i;
	int ret;

	for (i = 0; i < nr_handles; i++) {
		ret = lttng_untrack_pid(handle[i], -1);
		if (ret && ret != -LTTNG_ERR_INVALID) {
			ERR("Error %d untracking pid %d", ret, -1);
		}
	}
	return 0;
}

/* Return value:
 * >= 0: number of arguments to skip before command.
 * < 0: error.
 */
static
int parse_args(int argc, char **argv)
{
	int i;

	for (i = 1; i < argc; i++) {
		const char *str = argv[i];

		if (!strcmp(str, "--")) {
			i++;		/* Next is command position. */
			goto end;
		}
		if (str[0] != '-') {
			goto end;	/* Cursor at command position. */
		}
		if (!strcmp(str, "--help")) {
			opt_help = true;
		}
		if (!strcmp(str, "--no-context")) {
			opt_no_context = true;
		}
		if (!strcmp(str, "--no-pause")) {
			opt_no_pause = true;
		}
		if (!strcmp(str, "--no-syscall")) {
			opt_no_syscall = true;
		}
		if (!strcmp(str, "--output")) {
			opt_output = true;
			if (i == argc - 1) {
				ERR("Expected path argument after --output");
				return -1;
			}
			output_path = argv[++i];
		}
		if (!strcmp(str, "--session")) {
			opt_session = true;
			if (i == argc - 1) {
				ERR("Expected path argument after --session");
				return -1;
			}
			session_name = argv[++i];
		}
		if (!strcmp(str, "--view")) {
			opt_view = true;
		}
	}
end:
	if (i == argc && !opt_help) {
		ERR("Expected COMMAND argument after options. See `%s --help` for details.", argv[0]);
		return -1;
	}
	return i;
}

static
int show_help(int argc __unused, char **argv)
{
	printf("Usage of %s:\n", argv[0]);
	printf("\n");
	printf("  %s [OPTION] [--] COMMAND [COMMAND OPTIONS]\n", argv[0]);
	printf("\n");
	printf("Runs COMMAND while tracing the system calls of the children\n");
	printf("process hierarchy. See standard error output while executing\n");
	printf("this command for more information.\n");
	printf("\n");
	printf("Supported options:\n");
	printf("  --help:         This help screen.\n");
	printf("  --no-context:   Do not trace default contexts (vpid, vtid, procname).\n");
	printf("  --no-pause:     Do not wait for user input before running COMMAND.\n");
	printf("  --no-syscall:   Do not trace system calls.\n");
	printf("  --output PATH:  Write trace into output PATH. (default: /tmp/lttng-ptrace/$SESSION_NAME)\n");
	printf("  --session NAME: Tracing session name. (default: lttng-ptrace-$PID-$DATETIME)\n");
	printf("  --view:         View trace after end of COMMAND execution.\n");
	printf("\n");
	return 0;
}

int main(int argc, char **argv)
{
	int retval = 0, ret;
	pid_t pid;
	struct lttng_handle *handle[NR_HANDLES];
	struct sigaction act;
	struct lttng_trace_ctx ptrace_ctx;
	int skip_args = 0;

	skip_args = parse_args(argc, argv);
	if (skip_args < 0) {
		return EXIT_FAILURE;
	}
	if (opt_help) {
		show_help(argc, argv);
		return EXIT_SUCCESS;
	}

	if (lttng_trace_ctx_init(&ptrace_ctx, argv[skip_args])) {
		ERR("Error initializing trace context");
		retval = -1;
		goto end;
	}

	act.sa_sigaction = sighandler;
	act.sa_flags = SA_SIGINFO | SA_RESTART;
	sigemptyset(&act.sa_mask);
	ret = sigaction(SIGTERM, &act, NULL);
	if (ret) {
		PERROR("sigaction");
		retval = -1;
		goto end;
	}
	ret = sigaction(SIGINT, &act, NULL);
	if (ret) {
		PERROR("sigaction");
		retval = -1;
		goto end;
	}
	if (create_session(&ptrace_ctx) < 0) {
		fprintf(stderr, "%sError: Unable to create tracing session. Please ensure that lttng-sessiond is running as root and that your user belongs to the `tracing` group.\n", MESSAGE_PREFIX);
		retval = -1;
		goto end;
	}
	handle[0] = create_kernel_handle(&ptrace_ctx);
	if (!handle[0]) {
		retval = -1;
		goto end_kernel_handle;
	}
	handle[1] = create_ust_handle(&ptrace_ctx);
	if (!handle[1]) {
		retval = -1;
		goto end_ust_handle;
	}
	if (create_channels(&ptrace_ctx, LTTNG_DOMAIN_KERNEL) < 0) {
		retval = -1;
		goto end_wait_on_children;
	}
	if (create_channels(&ptrace_ctx, LTTNG_DOMAIN_UST) < 0) {
		retval = -1;
		goto end_wait_on_children;
	}
	if (enable_syscalls(&ptrace_ctx) < 0) {
		retval = -1;
		goto end_wait_on_children;
	}
	if (add_contexts(&ptrace_ctx, LTTNG_DOMAIN_KERNEL) < 0) {
		retval = -1;
		goto end_wait_on_children;
	}
	if (add_contexts(&ptrace_ctx, LTTNG_DOMAIN_UST) < 0) {
		retval = -1;
		goto end_wait_on_children;
	}
	if (lttng_trace_untrack_all(handle, NR_HANDLES) < 0) {
		retval = -1;
		goto end_wait_on_children;
	}
	fprintf(stderr, "%sTracing session `%s` created. It can be customized using the `lttng` command.\n", MESSAGE_PREFIX, ptrace_ctx.session_name);
	if (!opt_no_pause) {
		fprintf(stderr, "%sPress <ENTER> key when ready to run the child process.\n", MESSAGE_PREFIX);
		getchar();
	}

	if (start_session(&ptrace_ctx) < 0) {
		retval = -1;
		goto end_wait_on_children;
	}

	//TODO: signal off before we can forward it.
	pid = run_child(argc - skip_args, argv + skip_args);
	if (pid <= 0) {
		retval = -1;
		goto end;
	}

	sigfwd_pid = pid;
	//TODO signals on

	ret = wait_on_children(pid, handle, NR_HANDLES);
	if (ret) {
		retval = -1;
		goto end_wait_on_children;
	}


end_wait_on_children:
	lttng_destroy_handle(handle[1]);
end_ust_handle:
	lttng_destroy_handle(handle[0]);
end_kernel_handle:
	if (destroy_session(&ptrace_ctx)) {
		ERR("Error destroying session");
		retval = -1;
	}
end:
	if (retval) {
		return EXIT_FAILURE;
	} else {
		fprintf(stderr, "%sSub-process hierarchy traced successfully. View trace with `babeltrace2 %s`.\n", MESSAGE_PREFIX,
				ptrace_ctx.path);
		if (opt_view) {
			return execlp("babeltrace2", "babeltrace2", ptrace_ctx.path, NULL);
		}
		return EXIT_SUCCESS;
	}
	return 0;
}
