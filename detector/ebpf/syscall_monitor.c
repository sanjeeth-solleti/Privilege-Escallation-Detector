/*
 * syscall_monitor.c
 * eBPF program — monitors privilege escalation syscalls
 * Compiled and loaded at runtime via BCC
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define TASK_COMM_LEN 16
#define FNAME_LEN     256

/* Event types */
#define EVENT_SETUID    1
#define EVENT_EXECVE    2
#define EVENT_OPENAT    3
#define EVENT_CHMOD     4
#define EVENT_CAPSET    5
#define EVENT_SETGID    6
#define EVENT_SETREUID  7
#define EVENT_SETRESUID 8

struct event_t {
    u32  pid;
    u32  ppid;
    u32  uid;
    u32  euid;
    u32  gid;
    u32  new_uid;
    u32  new_gid;
    u64  timestamp;
    u32  event_type;
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
    char filename[FNAME_LEN];
    char syscall_name[32];
};

BPF_RINGBUF_OUTPUT(events, 256);

/* ── Helper: fill common fields ───────────────────────────── */
static inline void fill_common(struct event_t *e) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;

    e->pid       = bpf_get_current_pid_tgid() >> 32;
    e->uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid       = bpf_get_current_uid_gid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read real EUID from task credentials
    struct cred *cred = NULL;
    bpf_probe_read_kernel(&cred, sizeof(cred), &task->cred);
    if (cred) {
        u32 euid = 0;
        bpf_probe_read_kernel(&euid, sizeof(euid), &cred->euid);
        e->euid = euid;
    }

    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
        bpf_probe_read_kernel_str(&e->parent_comm, sizeof(e->parent_comm),
                                  parent->comm);
        u32 ppid = 0;
        bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid);
        e->ppid = ppid;
    }
}

/* ── setuid ───────────────────────────────────────────────── */
TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e);
    e->event_type = EVENT_SETUID;
    e->new_uid    = (u32)args->uid;
    __builtin_memcpy(e->syscall_name, "setuid", 7);
    events.ringbuf_submit(e, 0);
    return 0;
}

/* ── setreuid ─────────────────────────────────────────────── */
TRACEPOINT_PROBE(syscalls, sys_enter_setreuid) {
    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e);
    e->event_type = EVENT_SETREUID;
    e->new_uid    = (u32)args->euid;
    __builtin_memcpy(e->syscall_name, "setreuid", 9);
    events.ringbuf_submit(e, 0);
    return 0;
}

/* ── setresuid ────────────────────────────────────────────── */
TRACEPOINT_PROBE(syscalls, sys_enter_setresuid) {
    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e);
    e->event_type = EVENT_SETRESUID;
    e->new_uid    = (u32)args->euid;
    __builtin_memcpy(e->syscall_name, "setresuid", 10);
    events.ringbuf_submit(e, 0);
    return 0;
}

/* ── setgid ───────────────────────────────────────────────── */
TRACEPOINT_PROBE(syscalls, sys_enter_setgid) {
    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e);
    e->event_type = EVENT_SETGID;
    e->new_gid    = (u32)args->gid;
    __builtin_memcpy(e->syscall_name, "setgid", 7);
    events.ringbuf_submit(e, 0);
    return 0;
}

/* ── execve ───────────────────────────────────────────────── */
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e);
    e->event_type = EVENT_EXECVE;
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), args->filename);
    __builtin_memcpy(e->syscall_name, "execve", 7);
    events.ringbuf_submit(e, 0);
    return 0;
}

/* ── openat ───────────────────────────────────────────────── */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e);
    e->event_type = EVENT_OPENAT;
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), args->filename);
    __builtin_memcpy(e->syscall_name, "openat", 7);
    events.ringbuf_submit(e, 0);
    return 0;
}

/* ── chmod ────────────────────────────────────────────────── */
TRACEPOINT_PROBE(syscalls, sys_enter_chmod) {
    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e);
    e->event_type = EVENT_CHMOD;
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), args->filename);
    __builtin_memcpy(e->syscall_name, "chmod", 6);
    events.ringbuf_submit(e, 0);
    return 0;
}

/* ── capset ───────────────────────────────────────────────── */
TRACEPOINT_PROBE(syscalls, sys_enter_capset) {
    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e);
    e->event_type = EVENT_CAPSET;
    __builtin_memcpy(e->syscall_name, "capset", 7);
    events.ringbuf_submit(e, 0);
    return 0;
}
