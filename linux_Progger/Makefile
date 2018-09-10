# builds the trace events example kernel modules;
# then to use one (as root):  insmod <module_name.ko>

# If you include a trace header outside of include/trace/events
# then the file that does the #define CREATE_TRACE_POINTS must
# have that tracer file in its main search path. This is because
# define_trace.h will include it, and must be able to find it from
# the include/trace directory.
#
# Here trace-events-sample.c does the CREATE_TRACE_POINTS.
#
#CFLAGS_trace-events-sample.o := -I$(src)

#obj-$(CONFIG_SAMPLE_TRACE_EVENTS) += trace-events-sample.o

CONFIG_HAVE_SYSCALL_TRACEPOINTS= $(shell awk -F = '/CONFIG_HAVE_SYSCALL_TRACEPOINTS/ {print $$2}' /boot/config-`uname -r`)

$(info $(CONFIG_HAVE_SYSCALL_TRACEPOINTS))

ifeq ($(CONFIG_HAVE_SYSCALL_TRACEPOINTS), y)
TARGETS = all clean

obj-m:=progger_trace.o
KVERSION = $(shell uname -r)
KDIR:=/lib/modules/$(KVERSION)/build
PWD:= $(shell pwd)
CFLAGS-Y:= -O0

all:
	make -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

else

$(warning Your kernel needs to be set 'CONFIG_HAVE_SYSCALL_TRACEPOINT'S in /boot/config-'your kernel version in order to use progger!)

endif
