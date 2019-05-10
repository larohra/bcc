from __future__ import print_function

# Utilities Function
def stack_id_err(stack_id):
    import errno
    # -EFAULT in get_stackid normally means the stack-trace is not availible,
    # Such as getting kernel stack trace in userspace code
    return (stack_id < 0) and (stack_id != -errno.EFAULT)


def print_stack(bpf, stack_id, stack_type, tgid):

    if stack_id_err(stack_id):
        print("    [Missed %s Stack]" % stack_type)
        return []
    stack = list(bpf.get_table("stacks").walk(stack_id))
    for addr in stack:
        print("        ", end="")
        print("%s" % (bpf.sym(addr, tgid, show_module=True, show_offset=True)))
    return ["%s" % (bpf.sym(addr, tgid, show_module=True, show_offset=True)) for addr in stack]


def parse_process_data(process_dict):
    process_dict['command'] = " ".join(process_dict['cmdline'])
    return process_dict


def write_to_file(main_dict, file_name='/var/log/ProcessCapabilities/process_capabilities.json'):
    import os
    import json

    directory = os.path.dirname(file_name)
    if not os.path.exists(directory):
        os.makedirs(directory)
    try:
        with open(file_name, 'w') as outfile:
            output_str = json.dumps(
                main_dict)  # .replace(r"\n", "\n") , sort_keys=True, indent=4, separators=(',', ': ')
            outfile.write(output_str)
    except Exception as e:
        print("Ran into some problem : %s" % e)
