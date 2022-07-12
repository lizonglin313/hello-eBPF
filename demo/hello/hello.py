import imp
# import bpf library
from bcc import BPF

# load bpf program
b = BPF(src_file="hello.c")

# kernel probe
b.attach_kprobe(event="do_sys_openat2", fn_name="hello_world")

# read and print kernel debug
b.trace_print()