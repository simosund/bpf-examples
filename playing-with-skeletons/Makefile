# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS   := playing_with_skeletons
BPF_TARGETS    := dummy_kern

# Depend on bpftool for auto generating
# skeleton header file tc_txq_policy_kern.skel.h
#
BPF_SKEL_OBJ := dummy_kern.o

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk
