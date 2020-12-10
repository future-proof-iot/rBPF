BINS = sample_gcoap.bin sample_gcoap2.bin
OBJS = sample_gcoap.o sample_gcoap2.o

LLC ?= llc
CLANG ?= clang
OBJCOPY ?= llvm-objcopy
INC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
EXTRA_CFLAGS ?= -Os -emit-llvm

RIOTBASE = ../../..

BPFINCLUDE =  -I$(RIOTBASE)/drivers/include -I$(RIOTBASE)/core/include -I$(RIOTBASE)/sys/include


all: $(BINS)

.PHONY: clean

clean:
	rm -f $(OBJS)

INC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`

$(OBJS):  %.o:%.c
	$(CLANG) $(INC_FLAGS) \
	        $(BPFINCLUDE) \
	        -Wno-unused-value -Wno-pointer-sign -g3\
	        -Wno-compare-distinct-pointer-types \
	        -Wno-gnu-variable-sized-type-not-at-end \
	        -Wno-address-of-packed-member -Wno-tautological-compare \
	        -Wno-unknown-warning-option \
	        $(EXTRA_CFLAGS) -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@

$(BINS): %.bin:%.o
	$(OBJCOPY) --output-target=binary -j .text $< $@
