/*
 * hooks.h — shared data structures for eBPF programs
 */
#ifndef HOOKS_H
#define HOOKS_H

#define TASK_COMM_LEN 16
#define FNAME_LEN     256

/* Event types */
#define EVENT_SETUID   1
#define EVENT_EXECVE   2
#define EVENT_OPENAT   3
#define EVENT_CHMOD    4
#define EVENT_CAPSET   5
#define EVENT_SETGID   6
#define EVENT_SETREUID 7
#define EVENT_SETRESUID 8

/* Shared event structure written to ring buffer */
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

#endif /* HOOKS_H */
