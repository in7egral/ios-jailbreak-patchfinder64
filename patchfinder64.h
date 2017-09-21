//
//  patchfinder64.h
//  UAFExploit
//
//  Created by Vladimir Putin on 14.12.16.
//  Fixes by Alex Hude and Max Bazaliy
//  Some parts of code from Luca Todesco and Pangu
//  Copyright © 2016 FriedApple Team. All rights reserved.
//

#ifndef patchfinder64_h
#define patchfinder64_h

#include <mach/vm_map.h>

struct kern {
    vm_address_t kernel_base;
    uint8_t* kernel_dump;
    vm_size_t kernel_size;
    vm_address_t current_kext_base;
    vm_size_t current_kext_size;
} __attribute((packed));

#define Patchfinder64(x) (Patchfinder64_(#x, x, kern->kernel_base, kern->kernel_dump, kern->kernel_size)  + kern->kernel_base)
#define Patchfinder(x) (x(kern->kernel_base, kern->kernel_dump, kern->kernel_size) + kern->kernel_base)

#ifdef __cplusplus
extern "C" {
#endif

uint64_t Patchfinder64_(char* n, uint64_t (*x)(uint64_t region, uint8_t* kdata, size_t ksize), uint64_t region, uint8_t* kdata, size_t ksize);

int insn_is_funcbegin_64(uint32_t* i);
uint32_t* find_literal_ref_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t* insn, uint64_t address);
// search next instruction, incrementing mode
uint32_t* find_next_insn_matching_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t* current_instruction, int (*match_func)(uint32_t*));
// search next instruction, decrementing mode
uint32_t* find_last_insn_matching_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t* current_instruction, int (*match_func)(uint32_t*));
// by Luca Todesco: calculate value of register in the Aarch64 block of code
uint64_t find_register_value(uint32_t *dataPointer, uint64_t count, uint64_t base, unsigned char reg);
// calculate value (if possible) of register before specific instruction
uint64_t find_pc_rel_value_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t* insn, int reg);
// extract address of the GOT item by BL instruction in the kernel extension
uint64_t find_GOT_address_with_bl_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t *insn);
uint64_t find_printf_in_amfi_execve_hook(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_vnode_isreg_in_amfi_execve_hook(uint64_t region, uint8_t* kdata, size_t ksize);
// sandbox
uint64_t find_sb_eval(uint64_t region, uint8_t* kdata, size_t ksize);
// find sandbox policy list
uint64_t find_sandbox_mac_policy_ops(uint64_t region, uint8_t* kdata, size_t ksize);
// mac_policy_list
uint64_t find_mac_policy_list(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_vm_allocate(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_gPhysAddr(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_gVirtAddr(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_gPhysAddr_pangu(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_pmap_location(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_PE_i_can_has_debugger(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_debug_enabled(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_debug_boot_arg(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_ret0_gadget(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_ret1_gadget(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_IOUserClient_getMetaClass(uint64_t region, uint8_t* kdata, size_t ksize);
// iOS 9.x _mapForIO pwn (replace with ret1_gadget)
uint64_t find_PE_i_can_has_kernel_configuration_got(uint64_t region, uint8_t* kdata, size_t ksize);
// patch with B $PC+8
uint64_t find_lwvm_patch(uint64_t region, uint8_t* kdata, size_t ksize);
// return amfi_allow_any_signature address (allowInvalidSignatures)
// use +1 for amfi_get_out_of_my_way (allowEverything)
// use +2 for cs_enforcement_disable (csEnforcementDisable)
// use +3 for library validation (lvEnforceThirdParty)
uint64_t find_amfi_allow_any_signature(uint64_t region, uint8_t* kdata, size_t ksize);
// __mac_mount patch address
uint64_t find_mac_mount_patch(uint64_t region, uint8_t* kdata, size_t ksize);
// nonceEnabler (patch (offset + 8 + 4) with kOFVariablePermUserRead = 1)
uint64_t find_nonce_variable(uint64_t region, uint8_t* kdata, size_t ksize);

// tfp0 patches
uint64_t find_fill_x22(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_task_reference(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_load_x0_from_x19(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_store_x0_at_x19(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_current_task(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_get_task_ipcspace(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_just_ret(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_mov_x1_x0(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_call_x22(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_thread_exception_return(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_stack_rewrite(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_kernel_task(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_convert_task_to_port(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_realhost_special(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_ipc_port_copyout_send(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_current_proc(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_all_proc(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_data_abort(uint64_t region, uint8_t* kdata, size_t ksize);
// KPP patches
uint64_t find_cpacr_el1(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_arm_init_tramp(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_ttbr0_el1(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_ttbr1_el1(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_vbar(uint64_t region, uint8_t* kdata, size_t ksize);
// experimental
uint64_t find_ttbr0_el1_2(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_ttbr1_el1_2(uint64_t region, uint8_t* kdata, size_t ksize);
    
#ifdef __cplusplus
}
#endif

#endif /* patchfinder64_h */
