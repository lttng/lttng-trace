# SPDX-License-Identifier: MIT
#
# Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
#

AM_CPPFLAGS += -I$(top_srcdir)/include -I$(top_builddir)/include

bin_PROGRAMS = lttng-trace

lttng_trace_SOURCES = \
	lttng-trace.c

lttng_trace_LDADD = $(LTTNG_CTL_LIBS)
