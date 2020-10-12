CFLAGS += -Wno-format-nonliteral
NO_AUTO_SRC := 1
SRC += bpf.c
SRC += call.c
SRC += store.c

BPF_USE_JUMPTABLE ?= 0

ifeq ($(BPF_USE_JUMPTABLE), 1)
  SRC += jumptable.c
else
  SRC += instruction.c
endif

include $(RIOTBASE)/Makefile.base
