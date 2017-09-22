//
//  main.cpp
//  PatchfinderTester
//
//  Created by Vladimir Putin on 26.01.17.
//  Copyright © 2017 FriedApple Team. All rights reserved.
//

#include <iostream>
#include "LoadKernel.hpp"
#include "patchfinder64.h"

#define TestPatch(patchName) \
if (kernel.locatePatchLocation(offset, find_##patchName)) { \
    uint64_t virtual_addr = offset + kernel_base; \
    std::cout << "Found "  #patchName " with offset 0x" << std::hex << offset; \
    std::cout << " virtual address 0x" << virtual_addr << std::dec << "\n"; \
} else { \
    std::cerr << "\e[1;31mFailed to locate " #patchName << "\e[0m \n"; \
}

int main(int argc, const char * argv[]) {
    std::cout << "PatchfinderTester AArch64 v0.3\n";
    
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " kernel_dump" << std::endl;
        return 0;
    }
    
    LoadKernel kernel;
    if (kernel.loadKernel(argv[1])) {
        // test your patchfinder here ...
        // extract xnu version
        std::cout << kernel.getXnuVersion() << "\n";
        uint64_t offset;
        uint64_t kernel_base = kernel.getKernelVirtualBase();
        // general stuff
        TestPatch(vm_allocate)
        TestPatch(pmap_location)
        TestPatch(gPhysAddr)
        TestPatch(gVirtAddr)
        TestPatch(gPhysAddr_pangu)
        TestPatch(PE_i_can_has_debugger)
        TestPatch(debug_enabled)
		TestPatch(debug_boot_arg)
        // sandbox
        TestPatch(sb_eval)
        TestPatch(sandbox_mac_policy_ops)
        //TestPatch(mac_policy_list)
        // AMFI
        TestPatch(printf_in_amfi_execve_hook)
        TestPatch(vnode_isreg_in_amfi_execve_hook)
        // exec935 jail
        TestPatch(ret0_gadget)
		TestPatch(ret1_gadget)
        TestPatch(IOUserClient_getMetaClass)
		// amfi and _mapForIO
        TestPatch(lwvm_patch)
		TestPatch(PE_i_can_has_kernel_configuration_got)
		TestPatch(amfi_allow_any_signature)
		TestPatch(mac_mount_patch)
        // NONC
        TestPatch(nonce_variable)
        // tfp0 stuff
        TestPatch(fill_x22)
        TestPatch(task_reference)
        TestPatch(load_x0_from_x19)
        TestPatch(store_x0_at_x19)
        TestPatch(current_task)
        TestPatch(get_task_ipcspace)
        TestPatch(just_ret)
        TestPatch(mov_x1_x0)
        TestPatch(call_x22)
        TestPatch(thread_exception_return)
        TestPatch(stack_rewrite)
        TestPatch(kernel_task)
        TestPatch(convert_task_to_port)
        TestPatch(realhost_special)
        TestPatch(ipc_port_copyout_send)
        TestPatch(current_proc)
        TestPatch(all_proc)
        TestPatch(data_abort)
        // KPP stuff
        TestPatch(cpacr_el1)
        TestPatch(arm_init_tramp)
        TestPatch(ttbr0_el1)
        TestPatch(ttbr1_el1)
        TestPatch(vbar)
    }
    
    std::cout << "FriedApple Team ©2017\nHave a nice day!" << std::endl;
    
    return 0;
}
