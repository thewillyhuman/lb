# Build the XDP redirect BPF program shipped with `lb-node`.
#
# Output: deploy/xdp/redirect.bpf.o — load with deploy/xdp/load.sh.
#
# Requirements:
#   * clang >= 10 (BPF target support)
#   * libbpf headers (`apt install libbpf-dev` on Debian/Ubuntu)
#
# We compile with -O2 -g so the verifier sees BTF info and gives clearer
# rejections; the BPF JIT will optimise further at load time.

CLANG ?= clang
INCLUDES ?=
TARGET = redirect.bpf.o

.PHONY: all clean verify

all: $(TARGET)

$(TARGET): redirect.bpf.c
	$(CLANG) -O2 -g -Wall -Werror \
	    -target bpf \
	    -D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/') \
	    $(INCLUDES) \
	    -c $< -o $@

verify: $(TARGET)
	@bpftool prog load $(TARGET) /sys/fs/bpf/lb_redirect_check && \
	    bpftool prog del id $$(bpftool prog show pinned /sys/fs/bpf/lb_redirect_check -j | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])") || \
	    (echo "verification failed"; exit 1)

clean:
	rm -f $(TARGET)
