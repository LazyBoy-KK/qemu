#include "backend.h"
#include <stdio.h>

uint32_t read_u32(uint8_t *data) {
	return *(uint32_t *)data;
}

uint16_t read_u16(uint8_t *data) {
	return *(uint16_t *)data;
}

uint64_t read_register(GArray *reg_list, uint32_t reg) {
	qemu_plugin_reg_descriptor *rd = &g_array_index(
                reg_list, qemu_plugin_reg_descriptor, reg);
	GByteArray *buf = g_byte_array_new();
	int r = qemu_plugin_read_register(rd->handle, buf);
	g_assert(r == buf->len);
	g_assert(buf->len <= sizeof(uint64_t));
	uint64_t res = 0;
	for (int i = buf->len - 1; i >= 0; -- i) {
		res = (res << 8) | buf->data[i];
	}
	g_byte_array_free(buf, true);
	return res;
}

uint64_t u64_sext(uint64_t x, uint64_t b) {
	uint64_t m = 1u << (b - 1);
	return (x ^ m) - m;
}

bool is_ijal(uint8_t *insn_data) {
	// 6-0 bit: 1101111
	uint32_t mask = 0x7f;
	uint32_t data = read_u32(insn_data);
	return (data & mask) == (uint32_t)0x6f;
}

uint64_t ijal_target_addr(uint8_t *insn_data, uint64_t insn_vaddr) {
	uint32_t mask_19_12 = 0xff000, mask_20 = 0x80000000, mask_11 = 0x100000, mask_10_1 = 0x7fe00000;
	uint32_t data = read_u32(insn_data);

	uint32_t offset_20 = (data & mask_20) >> 31;
	uint32_t offset_19_12 = (data & mask_19_12) >> 12;
	uint32_t offset_11 = (data & mask_11) >> 20;
	uint32_t offset_10_1 = (data & mask_10_1) >> 21;

	uint64_t offset = (offset_20 << 20) | (offset_19_12 << 12) | (offset_11 << 11) | (offset_10_1 << 1);
	return insn_vaddr + u64_sext(offset, 21);
}

bool is_ijalr(uint8_t *insn_data) {
	// 14-12 bit: 000, 6-0 bit: 1100111
	uint32_t mask = 0x707f;
	uint32_t data = read_u32(insn_data);
	return (data & mask) == (uint32_t)0x67;
}

uint64_t ijalr_target_addr(uint8_t *insn_data, uint64_t insn_vaddr, GArray *reg_list) {
	uint32_t data = read_u32(insn_data);
	uint32_t offset_mask = 0xfff00000, rs1_mask = 0xf8000;
	uint32_t rs1 = (data & rs1_mask) >> 15;
	uint64_t offset = (data & offset_mask) >> 20;
	uint64_t rs1_val = read_register(reg_list, rs1);
	uint64_t target_addr = rs1_val + u64_sext(offset, 12);
	return target_addr & (~1);
}

bool is_ibeq(uint8_t *insn_data) {
	// 14-12 bit: 000, 6-0 bit: 1100011
	uint32_t mask = 0x707f;
	uint32_t data = read_u32(insn_data);
	return (data & mask) == (uint32_t)0x63;
}

uint64_t ibr_target_addr(uint8_t *insn_data, uint64_t insn_vaddr) {
	uint32_t mask_12 = 0x80000000, mask_10_5 = 0x7e000000, mask_4_1 = 0xf00, mask_11 = 0x80;
	uint32_t data = read_u32(insn_data);

	uint32_t offset_12 = (data & mask_12) >> 31;
	uint32_t offset_10_5 = (data & mask_10_5) >> 25;
	uint32_t offset_4_1 = (data & mask_4_1) >> 8;
	uint32_t offset_11 = (data & mask_11) >> 7;

	uint64_t offset = (offset_12 << 12) | (offset_11 << 11) | (offset_10_5 << 5) | (offset_4_1 << 1);
	return insn_vaddr + u64_sext(offset, 13);
}

bool is_ibne(uint8_t *insn_data) {
	// 14-12 bit: 001, 6-0 bit: 1100011
	uint32_t mask = 0x707f;
	uint32_t data = read_u32(insn_data);
	return (data & mask) == (uint32_t)0x1063;
}

bool is_iblt(uint8_t *insn_data) {
	// 14-12 bit: 100, 6-0 bit: 1100011
	uint32_t mask = 0x707f;
	uint32_t data = read_u32(insn_data);
	return (data & mask) == (uint32_t)0x4063;
}

bool is_ibge(uint8_t *insn_data) {
	// 14-12 bit: 101, 6-0 bit: 1100011
	uint32_t mask = 0x707f;
	uint32_t data = read_u32(insn_data);
	return (data & mask) == (uint32_t)0x5063;
}

bool is_ibltu(uint8_t *insn_data) {
	// 14-12 bit: 110, 6-0 bit: 1100011
	uint32_t mask = 0x707f;
	uint32_t data = read_u32(insn_data);
	return (data & mask) == (uint32_t)0x6063;
}

bool is_ibgeu(uint8_t *insn_data) {
	// 14-12 bit: 111, 6-0 bit: 1100011
	uint32_t mask = 0x707f;
	uint32_t data = read_u32(insn_data);
	return (data & mask) == (uint32_t)0x7063;
}

uint64_t cj_target_addr(uint8_t *insn_data, uint64_t insn_vaddr) {
	uint16_t mask_11 = 0x1000, mask_4 = 0x800, mask_9_8 = 0x600, mask_10 = 0x100, mask_6 = 0x80, mask_7 = 0x40, mask_3_1 = 0x38, mask_5 = 0x4;
	uint16_t data = read_u16(insn_data);

	uint16_t offset_11 = (data & mask_11) >> 12;
	uint16_t offset_4 = (data & mask_4) >> 11;
	uint16_t offset_9_8 = (data & mask_9_8) >> 9;
	uint16_t offset_10 = (data & mask_10) >> 8;
	uint16_t offset_6 = (data & mask_6) >> 7;
	uint16_t offset_7 = (data & mask_7) >> 6;
	uint16_t offset_3_1 = (data & mask_3_1) >> 3;
	uint16_t offset_5 = (data & mask_5) >> 2;

	uint64_t offset = (offset_11 << 11) | (offset_10 << 10) | (offset_9_8 << 8) | (offset_7 << 7) | (offset_6 << 6) | (offset_5 << 5) | (offset_4 << 4) | (offset_3_1 << 1);
	return insn_vaddr + u64_sext(offset, 12);
}

bool is_cj(uint8_t *insn_data) {
	// 15-13 bit: 101, 1-0 bit: 01
	uint16_t mask = 0xe003;
	uint16_t data = read_u16(insn_data);
	return (data & mask) == (uint16_t)0xa001;
}

bool is_cbeqz(uint8_t *insn_data) {
	// 15-13 bit: 110, 1-0 bit: 01
	uint16_t mask = 0xe003;
	uint16_t data = read_u16(insn_data);
	return (data & mask) == (uint16_t)0xc001;
}

uint64_t cbeqz_or_cbnez_target_addr(uint8_t *insn_data, uint64_t insn_vaddr) {
	uint16_t mask_8 = 0x1000, mask_4_3 = 0xc00, mask_7_6 = 0x60, mask_2_1 = 0x18, mask_5 = 0x4;
	uint16_t data = read_u16(insn_data);

	uint16_t offset_8 = (data & mask_8) >> 12;
	uint16_t offset_4_3 = (data & mask_4_3) >> 10;
	uint16_t offset_7_6 = (data & mask_7_6) >> 5;
	uint16_t offset_2_1 = (data & mask_2_1) >> 3;
	uint16_t offset_5 = (data & mask_5) >> 2;

	uint64_t offset = (offset_8 << 8) | (offset_7_6 << 6) | (offset_5 << 5) | (offset_4_3 << 3) | (offset_2_1 << 1);
	return insn_vaddr + u64_sext(offset, 9);
}

bool is_cbnez(uint8_t *insn_data) {
	// 15-13 bit: 111, 1-0 bit: 01
	uint16_t mask = 0xe003;
	uint16_t data = read_u16(insn_data);
	return (data & mask) == (uint16_t)0xe001;
}

bool is_cjr(uint8_t *insn_data) {
	// 15-12 bit: 1000, 6-0 bit: 0000010
	uint16_t mask = 0xf07f;
	uint16_t data = read_u16(insn_data);
	return (data & mask) == (uint16_t)0x8002;
}

uint64_t cjr_or_cjalr_target_addr(uint8_t *insn_data, uint64_t insn_vaddr, GArray *reg_list) {
	uint16_t data = read_u16(insn_data);
	uint16_t rs1_mask = 0xf80;
	uint16_t rs1 = (data & rs1_mask) >> 7;
	uint64_t rs1_val = read_register(reg_list, rs1);
	return rs1_val;
}

bool is_cjalr(uint8_t *insn_data) {
	// 15-12 bit: 1001, 6-0 bit: 0000010
	uint16_t mask = 0xf07f;
	uint16_t data = read_u16(insn_data);
	return (data & mask) == (uint16_t)0x9002;
}

bool is_uncond_branch(uint8_t *insn_data, size_t insn_size) {
	if (insn_size == 2) {
		return is_cj(insn_data) || is_cjalr(insn_data) || is_cjr(insn_data);
	} else if (insn_size == 4) {
		return is_ijal(insn_data) || is_ijalr(insn_data);
	}
	return false;
}

bool is_branch(uint8_t *insn_data, size_t insn_size) {
	if (insn_size == 2) {
		return is_cbeqz(insn_data) || is_cbnez(insn_data) 
			|| is_cj(insn_data) || is_cjalr(insn_data) || is_cjr(insn_data);
	} else if (insn_size == 4) {
		return is_ibeq(insn_data) || is_ibge(insn_data) 
			|| is_ibgeu(insn_data) || is_iblt(insn_data) 
			|| is_ibltu(insn_data) || is_ibne(insn_data) 
			|| is_ijal(insn_data) || is_ijalr(insn_data);
	}
	return false;
}

uint64_t get_branch_target_address(uint8_t *insn_data, size_t insn_size, uint64_t insn_vaddr, GArray *reg_list) {
	if (insn_size == 4) {
		if (is_ijal(insn_data)) {
			return ijal_target_addr(insn_data, insn_vaddr);
		}
		if (is_ijalr(insn_data)) {
			return ijalr_target_addr(insn_data, insn_vaddr, reg_list);
		}
		if (is_ibeq(insn_data) || is_ibge(insn_data) 
			|| is_ibgeu(insn_data) || is_iblt(insn_data) 
			|| is_ibltu(insn_data) || is_ibne(insn_data))
		{
			return ibr_target_addr(insn_data, insn_vaddr);
		}
	} else if (insn_size == 2) {
		if (is_cbeqz(insn_data) || is_cbnez(insn_data)) {
			return cbeqz_or_cbnez_target_addr(insn_data, insn_vaddr);
		}
		if (is_cjr(insn_data) || is_cjalr(insn_data)) {
			return cjr_or_cjalr_target_addr(insn_data, insn_vaddr, reg_list);
		}
		if (is_cj(insn_data)) {
			return cj_target_addr(insn_data, insn_vaddr);
		}
	}
	return 0;
}
