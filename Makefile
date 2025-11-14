CLANG ?= clang
LLC ?= llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPFTOOL ?= bpftool

# Пути к заголовкам ядра
KERN_SRC ?= /lib/modules/$(shell uname -r)/build
KERN_INC ?= $(KERN_SRC)/include
UAPI_INC ?= $(KERN_INC)/uapi

# Флаги компиляции
CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -D__BPF_TRACING__ \
              -D__KERNEL__ \
              -D__BPF__ \
              -Dasm_inline=inline \
              -Dasm_volatile_goto= \
              -D__SIZEOF_INT128__=16 \
              -Wno-unused-value \
              -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types \
              -Wno-gnu-variable-sized-type-not-at-end \
              -Wno-address-of-packed-member \
              -Wno-tautological-compare \
              -Wno-unknown-warning-option \
              -fno-stack-protector \
              -fno-jump-tables \
              -fno-unwind-tables \
              -fno-asynchronous-unwind-tables \
              -fno-dwarf2-cfi-asm \
              -I$(KERN_INC) \
              -I$(UAPI_INC) \
              -I/usr/include/bpf \
              -I/usr/include/$(shell uname -m)-linux-gnu \
              -isystem $(KERN_INC)

# Исходные файлы
BPF_C := firewall.bpf.c
BPF_OBJ := firewall.bpf.o
BPF_SKEL := firewall.skel.h
C_SRC := firewall.c
TARGET := firewall

# Зависимости
LIBS := -lbpf -lelf -lz
INCLUDES := -I/usr/include/bpf

.PHONY: all clean install

all: $(TARGET)

# Компиляция BPF программы
$(BPF_OBJ): $(BPF_C)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Генерация skeleton
$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Компиляция основной программы
$(TARGET): $(C_SRC) $(BPF_SKEL) $(BPF_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -I. $(C_SRC) -o $@ $(LIBS)

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(BPF_SKEL) *.o

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

