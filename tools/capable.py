#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# capable   Trace security capabilitiy checks (cap_capable()).
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: capable [-h] [-v] [-p PID] [-K] [-U]
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Sep-2016   Brendan Gregg   Created this.

from __future__ import print_function

import argparse
import signal
from collections import Counter
from functools import partial
from Queue import Queue
from os import getpid
from threading import Thread, Event
from time import strftime

import psutil
from bcc import BPF

from CapableUtilities import *


class Enum(set):
    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError


# Thread to upload the snapshot of the current state of process_capabilities dict every min
class TimerThread(Thread):
    def __init__(self, event, snapshot_filename):
        Thread.__init__(self)
        self.stopped = event
        self.snapshot_filename = snapshot_filename

    def run(self):
        while not self.stopped.wait(60):
            # print("my thread")
            write_to_file(process_capabilities_dict, self.snapshot_filename)


# Class to handle the killing of capabilities gracefully
class GracefulKiller:
    kill_now = False

    def __init__(self, stop_event):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)
        # signal.signal(signal.SIGKILL, self.exit_gracefully)
        self.stop_event = stop_event

    def exit_gracefully(self, signum, frame):
        print("Stopping the capable service")
        self.kill_now = True
        self.stop_event.set()
        task_queue.join()
        write_to_file(process_capabilities_dict)


# process event
def parse_event(event):
    kernel_stack = []
    user_stack = []
    # event = bpf["events"].event(data)

    if event.cap in capabilities:
        name = capabilities[event.cap]
    else:
        name = "?"
    print("%-9s %-6d %-6d %-6d %-16s %-4d %-20s %d" % (strftime("%H:%M:%S"),
                                                       event.uid, event.pid, event.tgid,
                                                       event.comm.decode('utf-8', 'replace'),
                                                       event.cap, name, event.audit))
    if args.kernel_stack:
        kernel_stack = print_stack(bpf, event.kernel_stack_id, StackType.Kernel, -1)
    if args.user_stack:
        user_stack = print_stack(bpf, event.user_stack_id, StackType.User, event.tgid)

    uid = int("%-6d" % event.uid)
    pid = int("%-6d" % event.pid)
    process_name = event.comm.decode('utf-8', 'replace')
    cap_name = name

    process_attrs = ['cmdline', 'connections', 'cpu_percent', 'create_time', 'cwd', 'environ', 'exe', 'gids', 'name',
                     'num_threads', 'open_files', 'pid', 'status', 'terminal', 'threads', 'uids', 'username']

    try:
        current_process = psutil.Process(pid)
        process_details = parse_process_data(current_process.as_dict(attrs=process_attrs))
        process_details['parent_details'] = [parse_process_data(psutil.Process(parent.pid).as_dict(attrs=process_attrs))
                                             for parent in current_process.parents()]
        process_details['children_details'] = [
            parse_process_data(psutil.Process(child.pid).as_dict(attrs=process_attrs))
            for child in current_process.children(True)]
    except psutil.NoSuchProcess as e:
        print("Process not found : %s ---> %s" % (e.name, e.msg))
        return

    cap_key = "%s \n%s \n%s" % (cap_name, "\n".join(kernel_stack), "\n".join(user_stack))  # cap_name
    process_dict = {
        'process_details': process_details,
        'capabilities': Counter({cap_key: 1}),
        'command': process_details['command']
    }

    user_dict = {
        pid: process_dict,
        'username': process_details['username']
    }

    if uid in process_capabilities_dict:
        user_dict = process_capabilities_dict[uid]

        if pid in user_dict:
            process_dict = user_dict[pid]
            process_dict['process_details'] = process_details
            process_dict['capabilities'].update([cap_key])
            process_dict['command'] = process_details['command']
        user_dict[pid] = process_dict

    process_capabilities_dict[uid] = user_dict


def add_event_to_queue(bpf, cpu, data, size):
    task_queue.put(bpf["events"].event(data))


def parse_and_get_arguments():
    # arguments
    examples = """examples:
        ./capable             # trace capability checks
        ./capable -v          # verbose: include non-audit checks
        ./capable -p 181      # only trace PID 181
        ./capable -K          # add kernel stacks to trace
        ./capable -U          # add user-space stacks to trace
    """
    parser = argparse.ArgumentParser(
        description="Trace security capability checks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="include non-audit checks")
    parser.add_argument("-p", "--pid",
                        help="trace this PID only")
    parser.add_argument("-K", "--kernel-stack", action="store_true",
                        help="output kernel stack trace")
    parser.add_argument("-U", "--user-stack", action="store_true",
                        help="output user stack trace")
    return parser.parse_args()


def setup_bpf():
    # define BPF program
    bpf_text = """
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>
        struct data_t {
           u32 tgid;
           u32 pid;
           u32 uid;
           int cap;
           int audit;
           char comm[TASK_COMM_LEN];
        #ifdef KERNEL_STACKS
           int kernel_stack_id;
        #endif
        #ifdef USER_STACKS
           int user_stack_id;
        #endif
        };
        BPF_PERF_OUTPUT(events);
        #if defined(USER_STACKS) || defined(KERNEL_STACKS)
        BPF_STACK_TRACE(stacks, 2048);
        #endif
        int kprobe__cap_capable(struct pt_regs *ctx, const struct cred *cred,
            struct user_namespace *targ_ns, int cap, int audit)
        {
            u64 __pid_tgid = bpf_get_current_pid_tgid();
            u32 tgid = __pid_tgid >> 32;
            u32 pid = __pid_tgid;
            FILTER1
            FILTER2
            FILTER3
            u32 uid = bpf_get_current_uid_gid();
            struct data_t data = {.tgid = tgid, .pid = pid, .uid = uid, .cap = cap, .audit = audit};
        #ifdef KERNEL_STACKS
            data.kernel_stack_id = stacks.get_stackid(ctx, 0);
        #endif
        #ifdef USER_STACKS
            data.user_stack_id = stacks.get_stackid(ctx, BPF_F_USER_STACK);
        #endif
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        };
        """
    if args.pid:
        bpf_text = bpf_text.replace('FILTER1',
                                    'if (pid != %s) { return 0; }' % args.pid)
    if not args.verbose:
        bpf_text = bpf_text.replace('FILTER2', 'if (audit == 0) { return 0; }')
    if args.kernel_stack:
        bpf_text = "#define KERNEL_STACKS\n" + bpf_text
    if args.user_stack:
        bpf_text = "#define USER_STACKS\n" + bpf_text
    bpf_text = bpf_text.replace('FILTER1', '')
    bpf_text = bpf_text.replace('FILTER2', '')
    bpf_text = bpf_text.replace('FILTER3',
                                'if (pid == %s) { return 0; }' % getpid())
    if debug:
        print(bpf_text)

    # initialize BPF
    bpf = BPF(text=bpf_text)

    # header
    print("%-9s %-6s %-6s %-6s %-16s %-4s %-20s %s" % (
        "TIME", "UID", "PID", "TID", "COMM", "CAP", "NAME", "AUDIT"))

    # atexit.register(write_to_file())

    # loop with callback to print_event
    callback = partial(add_event_to_queue, bpf)
    bpf["events"].open_perf_buffer(callback)

    return bpf


def orchestrator(thread_killer):
    while not thread_killer.kill_now or task_queue.not_empty:
        if task_queue.not_empty:
            event = task_queue.get()
            parse_event(event)
            task_queue.task_done()


# capabilities to names, generated from (and will need updating):
# awk '/^#define.CAP_.*[0-9]$/ { print "    " $3 ": \"" $2 "\"," }' \
#     include/uapi/linux/capability.h
capabilities = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
}

process_capabilities_dict = {}
task_queue = Queue()

if __name__ == "__main__":
    debug = 0
    num_orchestrator_threads = 1

    args = parse_and_get_arguments()

    # Stack trace types
    StackType = Enum(("Kernel", "User",))

    # Run the setup
    bpf = setup_bpf()

    # Set the threads and start execution
    stop_flag = Event()
    snapshot_thread = TimerThread(stop_flag, '/var/log/ProcessCapabilities/process_capabilities_snapshot.json')
    killer = GracefulKiller(stop_flag)  # type: GracefulKiller
    snapshot_thread.start()

    for i in range(num_orchestrator_threads):
        t = Thread(target=orchestrator, args=(killer,))
        t.daemon = True
        t.start()

    while not killer.kill_now:
        bpf.perf_buffer_poll()
