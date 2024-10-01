#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <qemu-plugin.h>
#include "backend.h"

struct insn_vaddr_list {
    uint64_t vaddr;
    struct insn_vaddr_list *next;
};

enum InsKind {
	MEM_ACCESS_STACK = 0,
	MEM_ACCESS_LINEAR_MEM,
	MEM_ACCESS_PLT,
	MEM_ACCESS_VMCTX,
	MEM_ACCESS_EXECENV,
	MEM_ACCESS_OTHER,

	UNCOND_BRANCH_INS,
	COND_BRANCH_INS,
	CALL_INS,
	RET_INS,
};

struct br_insn_list {
	uint64_t insn_vaddr;
	uint64_t target_addr;
	bool is_cond;
	uint32_t insn_size;
	uint8_t *insn_data;
	struct br_insn_list *next;
};

const uint8_t LAST_CONTENT = 0x23;
const uint8_t INS_IN_CODE = 0x01;
const uint8_t INS_IN_PLT = 0x02;
const uint8_t TARGET_IN_CODE = 0x04;
const uint8_t TARGET_IN_PLT = 0x08;

const char *code_addr_file_path = NULL;
uint64_t insn_low_addr = 0, insn_high_addr = 0, base_obj_addr = 0;
int64_t code_offset = 0;
uint64_t stack_low_addr = 0, stack_high_addr = 0;
uint64_t total_load = 0, total_store = 0;
uint64_t linear_mem_low_addr = 0, linear_mem_high_addr = 0;
uint64_t plt_low_addr = 0, plt_high_addr = 0;
uint64_t vmctx_low_addr = 0, vmctx_high_addr = 0, execenv_low_addr = 0, execenv_high_addr = 0;
struct insn_vaddr_list *head = NULL;
struct br_insn_list *br_head = NULL, *last_br = NULL;
FILE *output = NULL;
// 0: wa2x 1: wamr 2: wasmtime
uint32_t runtime_mode = 0;
GArray *reg_list;

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

bool read_code_addr_space(FILE *f) {
	size_t plt_size = 0, code_size = 0;
	switch (runtime_mode) {
		case 0:
		case 1:
			if (fscanf(f, "%ld %ld %ld %ld", 
				&insn_low_addr, &code_size, &plt_low_addr, &plt_size) != 4) {
				return false;
			}
			insn_high_addr = insn_low_addr + code_size;
			plt_high_addr = plt_low_addr + plt_size;
			break;
		case 2:
			if (fscanf(f, "%ld %ld", 
				&insn_low_addr, &code_size) != 2) {
				return false;
			}
			insn_high_addr = insn_low_addr + code_size;
			break;
	}
	return true;
}

bool update_insn_addr_space(void) {
    FILE *f = fopen(code_addr_file_path, "r");
    bool res = true;
    if (f == NULL) {
        res = false;
        goto fail1;
    }
    if (!read_code_addr_space(f)) {
        res = false;
        goto fail2;
    }
fail2:
    fclose(f);
fail1:
    return res;
}

void update_stack_addr_space(void) {
    stack_low_addr = qemu_plugin_stack_low_addr();
    stack_high_addr = qemu_plugin_stack_high_addr();
}

void serialize_mem_access_record(uint8_t kind, uint8_t is_load, uint64_t addr, uint64_t size, uint64_t offset) {
	fwrite((void *)&kind, sizeof(uint8_t), 1, output);
	fwrite((void *)&offset, sizeof(uint64_t), 1, output);
	fwrite((void *)&is_load, sizeof(uint8_t), 1, output);
	fwrite((void *)&addr, sizeof(uint64_t), 1, output);
	fwrite((void *)&size, sizeof(uint64_t), 1, output);
}

void serialize_branch_record(uint8_t kind, uint64_t target_addr, uint64_t offset, uint8_t mode, uint8_t taken) {
	// fprintf(stderr, "kind:%d offset:%lx target_addr:%lx\n", kind, offset, target_addr);
	fwrite((void *)&kind, sizeof(uint8_t), 1, output);
	fwrite((void *)&offset, sizeof(uint64_t), 1, output);
	fwrite((void *)&target_addr, sizeof(uint64_t), 1, output);
	fwrite((void *)&mode, sizeof(uint8_t), 1, output);
	if (kind == COND_BRANCH_INS) {
		fwrite((void *)&taken, sizeof(uint8_t), 1, output);
	}
}

void serialize_ret_record(uint8_t kind, uint64_t offset, uint8_t in_plt) {
	// fprintf(stderr, "kind:%d offset:%lx in_plt:%d\n", kind, offset, in_plt);
	fwrite((void *)&kind, sizeof(uint8_t), 1, output);
	fwrite((void *)&offset, sizeof(uint64_t), 1, output);
	fwrite((void *)&in_plt, sizeof(uint8_t), 1, output);
}

void update_linear_mem_addr_space(void) {
    char *addr_file_path = getenv("LINEAR_MEMORY_PATH");
    if (!addr_file_path) {
        addr_file_path = "/tmp/linear_mem.txt";
    }
    FILE *f = fopen(addr_file_path, "r");
    size_t size;
    if (f == NULL) {
        return;
    }
    if (fscanf(f, "%ld %ld", &linear_mem_low_addr, &size) != 2) {
        fclose(f);
        return;
    }
    linear_mem_high_addr = linear_mem_low_addr + size;
    fclose(f);
    remove(addr_file_path);
}

bool read_vmctx_addr(FILE *f) {
	size_t vmctx_size = 0, execenv_size = 0;
	switch (runtime_mode) {
		case 0:
		case 2:
			if (fscanf(f, "%ld %ld", &vmctx_low_addr, &vmctx_size) != 2) {
				vmctx_low_addr = vmctx_high_addr = 0;
				return false;
			}
			vmctx_high_addr = vmctx_low_addr + vmctx_size;
			break;

		case 1:
			if (fscanf(f, "%ld %ld %ld %ld", &vmctx_low_addr, &vmctx_size, &execenv_low_addr, &execenv_size) != 4) {
				vmctx_low_addr = vmctx_high_addr = 0;
				execenv_low_addr = execenv_high_addr = 0;
				return false;
			}
			execenv_high_addr = execenv_low_addr + execenv_size;
			vmctx_high_addr = vmctx_low_addr + vmctx_size;
			break;
	}
	return true;
}

bool update_vmctx_addr(void) {
	char *vmctx_path = getenv("VMCTX_PATH");
    if (!vmctx_path) {
        vmctx_path = "/tmp/vmctx.txt";
    }
    FILE *f = fopen(vmctx_path, "r");
    if (f == NULL) {
        return false;
    }
    if (!read_vmctx_addr(f)) {
        fclose(f);
        return false;
    }
    fclose(f);
    remove(vmctx_path);
	return true;
}

bool in_code_sec(uint64_t addr) {
	return addr >= insn_low_addr && addr <= insn_high_addr;
}

bool in_plt_sec(uint64_t addr) {
	return addr >= plt_low_addr && addr <= plt_high_addr;
}

bool is_aot_code(uint64_t addr) {
	return in_code_sec(addr) || in_plt_sec(addr);
}

uint8_t mem_access_kind(uint64_t *addr, uint64_t *insn_addr) {
    if (*addr >= stack_low_addr && *addr <= stack_high_addr) {
		*addr -= stack_low_addr;
		*insn_addr -= insn_low_addr;
		return MEM_ACCESS_STACK;
        // return "stack";
    } else if (*addr >= linear_mem_low_addr && *addr <= linear_mem_high_addr) {
		*addr -= linear_mem_low_addr;
		*insn_addr -= insn_low_addr;
		return MEM_ACCESS_LINEAR_MEM;
        // return "linear memory";
    } else if (in_plt_sec(*insn_addr)) {
		*insn_addr -= plt_low_addr;
		return MEM_ACCESS_PLT;
        // return "plt";
    } else if (*addr >= vmctx_low_addr && *addr <= vmctx_high_addr) {
		*addr -= vmctx_low_addr;
		*insn_addr -= insn_low_addr;
		return MEM_ACCESS_VMCTX;
		// return runtime_mode == 1 ? "module inst" : "vmctx";
	} else if (*addr >= execenv_low_addr && *addr <= execenv_high_addr) {
		*addr -= execenv_low_addr;
		*insn_addr -= insn_low_addr;
		return MEM_ACCESS_EXECENV;
		// return "exec env";
	} else {
		*insn_addr -= insn_low_addr;
		return MEM_ACCESS_OTHER;
        // return "other";
    }
}

void mem_cb(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
            uint64_t vaddr, void *userdata)
{
    if (insn_low_addr == 0 && insn_high_addr == 0 && !update_insn_addr_space()) {
        return;
    }
	if (vmctx_low_addr == 0 && vmctx_high_addr == 0 && !update_vmctx_addr()) {
		return;
	}

    update_linear_mem_addr_space();

    struct insn_vaddr_list *node = (struct insn_vaddr_list *)userdata;
    if (!is_aot_code(node->vaddr)) {
        return;
    }

    bool is_store = qemu_plugin_mem_is_store(info);
    uint32_t shift = qemu_plugin_mem_size_shift(info);
    if (is_store) {
        total_store ++;
    } else {
        total_load ++;
    }
	uint64_t insn_vaddr = node->vaddr;
    uint8_t kind = mem_access_kind(&vaddr, &insn_vaddr);
	serialize_mem_access_record(kind, !is_store, vaddr, 1ll << shift, insn_vaddr);
}

void br_cb(unsigned int vcpu_index, void *userdata) {
	if (insn_low_addr == 0 && insn_high_addr == 0 && !update_insn_addr_space()) {
        return;
    }
	if (last_br == NULL) {
		return;
	}
	struct insn_vaddr_list *node = (struct insn_vaddr_list *)userdata;

	bool insn_in_plt = in_plt_sec(last_br->insn_vaddr);
	bool insn_in_code = in_code_sec(last_br->insn_vaddr);
	bool target_in_plt = in_plt_sec(last_br->target_addr);
	bool target_in_code = in_code_sec(last_br->target_addr);

	uint64_t insn_vaddr = last_br->insn_vaddr;
	uint64_t target_addr = last_br->target_addr;

	if (insn_in_code) {
		insn_vaddr -= insn_low_addr;
	} else if (insn_in_plt) {
		insn_vaddr -= plt_low_addr;
	}

	if (target_in_code) {
		target_addr -= insn_low_addr;
	} else if (target_in_plt) {
		target_addr -= plt_low_addr;
	}

	uint8_t mode = (insn_in_code) | (insn_in_plt << 1) | (target_in_code << 2) | (target_in_plt << 3);

	serialize_branch_record(last_br->is_cond ? COND_BRANCH_INS : UNCOND_BRANCH_INS, target_addr, insn_vaddr, mode, node->vaddr == last_br->target_addr);

	last_br = NULL;
}

void br_record_cb(unsigned int vcpu_index, void *userdata) {
	if (insn_low_addr == 0 && insn_high_addr == 0 && !update_insn_addr_space()) {
        return;
    }

	struct br_insn_list *node = (struct br_insn_list *)userdata;

	if (node->target_addr == 0) {
		node->target_addr = get_branch_target_address(node->insn_data, node->insn_size, node->insn_vaddr, reg_list);
	}

	if (!is_aot_code(node->target_addr) && !is_aot_code(node->insn_vaddr)) {
		return;
	}

	last_br = node;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    if (stack_low_addr == 0 && stack_high_addr == 0) {
        update_stack_addr_space();
    }
    size_t n_insns = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n_insns; ++ i) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
		size_t insn_size = qemu_plugin_insn_size(insn);
		uint8_t *insn_data = malloc(insn_size);
		qemu_plugin_insn_data(insn, insn_data, insn_size);
		struct insn_vaddr_list *node = malloc(sizeof(struct insn_vaddr_list));
        node->vaddr = qemu_plugin_insn_vaddr(insn);
        node->next = head->next;
        head->next = node;
		qemu_plugin_register_vcpu_insn_exec_cb(insn, br_cb, QEMU_PLUGIN_CB_NO_REGS, node);

		qemu_plugin_register_vcpu_mem_cb(insn, mem_cb, 
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, (void *)node);

		if (is_branch(insn_data, insn_size)) {
			struct br_insn_list *br_node = malloc(sizeof(struct br_insn_list));
			br_node->insn_vaddr = qemu_plugin_insn_vaddr(insn);
			br_node->is_cond = !is_uncond_branch(insn_data, insn_size);
			br_node->insn_data = insn_data;
			br_node->insn_size = insn_size;
			br_node->target_addr = 0;
			br_node->next = br_head->next;
			br_head->next = br_node;
			qemu_plugin_register_vcpu_insn_exec_cb(insn, br_record_cb, QEMU_PLUGIN_CB_R_REGS, (void *)br_node);
		} else {
			free(insn_data);
		}

    }
}

void vcpu_atexit(qemu_plugin_id_t id, void *userdata) {
    if (output) {
        // fprintf(output, "total load: %ld, store: %ld\n", total_load, total_store);
		fwrite((void *)&LAST_CONTENT, sizeof(uint8_t), 1, output);
        fclose(output);
    }
    while(head->next) {
        struct insn_vaddr_list *p = head->next;
        head->next = p->next;
        free(p);
    }
    free(head);
	while(br_head->next) {
		struct br_insn_list *p = br_head->next;
		br_head->next = p->next;
		free(p->insn_data);
		free(p);
	}
	free(br_head);
	g_array_free(reg_list, true);
}

const char *search_addr_file(const char *env, const char *def) {
	const char *path = getenv(env);
	if (!path) {
		path = def;
	}
	remove(path);
	return path;
}

void init(void) {
	code_addr_file_path = search_addr_file("CODE_ADDR_PATH", "/tmp/code_addr.txt");
	search_addr_file("VMCTX_PATH", "/tmp/vmctx.txt");
	head = malloc(sizeof(struct insn_vaddr_list));
    head->vaddr = 0;
    head->next = NULL;
	br_head = malloc(sizeof(struct br_insn_list));
	br_head->insn_vaddr = br_head->target_addr = 0;
	br_head->next = NULL;
}

void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {
	reg_list = qemu_plugin_get_registers();
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
	if (argc == 0) {
		fprintf(stderr, "option parsing failed\n");
		return -1;
	}
	for (int i = 0; i < argc; ++ i) {
		char *opt = argv[i];
		g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
		if (g_strcmp0(tokens[0], "runtime") == 0) {
			if (!g_strcmp0(tokens[1], "wa2x")) {
				runtime_mode = 0;
			} else if (!g_strcmp0(tokens[1], "wamr")) {
				runtime_mode = 1;
			} else if (!g_strcmp0(tokens[1], "wasmtime")) {
				runtime_mode = 2;
			} else {
				fprintf(stderr, "option %s parsing failed\n", opt);
				return -1;	
			}
		} else {
			fprintf(stderr, "option %s parsing failed\n", opt);
			return -1;
		}
	}

    init();
	output = fopen("./wasm.out", "w");
    if (output == NULL) {
        return -1;
    }
	fwrite((void *)&runtime_mode, sizeof(uint8_t), 1, output);
	qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, vcpu_atexit, NULL);
    return 0;
}
