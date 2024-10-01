#ifndef __BACKEND_H__
#define __BACKEND_H__

#include <glib.h>
#include <qemu-plugin.h>

bool is_uncond_branch(uint8_t *insn_data, size_t insn_size);

bool is_branch(uint8_t *insn_data, size_t insn_size);

uint64_t get_branch_target_address(uint8_t *insn_data, size_t insn_size, uint64_t insn_vaddr, GArray *reg_list);

#endif
