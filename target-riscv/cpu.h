#if !defined (__RISCV_CPU_H__)
#define __RISCV_CPU_H__

//#define DEBUG_OP

#define TARGET_HAS_ICE 1

#define ELF_MACHINE	EM_RISCV

#define CPUArchState struct CPURISCVState

#define ALIGNED_ONLY

#include "config.h"
#include "qemu-common.h"
#include "riscv-defs.h"
#include "exec/cpu-defs.h"
#include "fpu/softfloat.h"

#define TRANSLATE_FAIL -1
#define TRANSLATE_SUCCESS 0

#define NB_MMU_MODES 4

struct CPURISCVState;

#define PGSHIFT 12

// uncomment for lots of debug printing
// #define RISCV_DEBUG_PRINT

#define get_field(reg, mask) (((reg) & (target_ulong)(mask)) / ((mask) & ~((mask) << 1)))
#define set_field(reg, mask, val) (((reg) & ~(target_ulong)(mask)) | (((target_ulong)(val) * ((mask) & ~((mask) << 1))) & (target_ulong)(mask)))


#define FP_RD_NE  0
#define FP_RD_0   1
#define FP_RD_DN  2
#define FP_RD_UP  3
#define FP_RD_NMM 4

#define FSR_RD_SHIFT 5
#define FSR_RD   (0x7 << FSR_RD_SHIFT)

#define FPEXC_NX 0x01
#define FPEXC_UF 0x02
#define FPEXC_OF 0x04
#define FPEXC_DZ 0x08
#define FPEXC_NV 0x10

#define FSR_AEXC_SHIFT 0
#define FSR_NVA  (FPEXC_NV << FSR_AEXC_SHIFT)
#define FSR_OFA  (FPEXC_OF << FSR_AEXC_SHIFT)
#define FSR_UFA  (FPEXC_UF << FSR_AEXC_SHIFT)
#define FSR_DZA  (FPEXC_DZ << FSR_AEXC_SHIFT)
#define FSR_NXA  (FPEXC_NX << FSR_AEXC_SHIFT)
#define FSR_AEXC (FSR_NVA | FSR_OFA | FSR_UFA | FSR_DZA | FSR_NXA)

#define CSR_FFLAGS 0x1
#define CSR_FRM 0x2
#define CSR_FCSR 0x3
#define CSR_CYCLE 0xc00
#define CSR_TIME 0xc01
#define CSR_INSTRET 0xc02
#define CSR_HPMCOUNTER3 0xc03
#define CSR_HPMCOUNTER4 0xc04
#define CSR_HPMCOUNTER5 0xc05
#define CSR_HPMCOUNTER6 0xc06
#define CSR_HPMCOUNTER7 0xc07
#define CSR_HPMCOUNTER8 0xc08
#define CSR_HPMCOUNTER9 0xc09
#define CSR_HPMCOUNTER10 0xc0a
#define CSR_HPMCOUNTER11 0xc0b
#define CSR_HPMCOUNTER12 0xc0c
#define CSR_HPMCOUNTER13 0xc0d
#define CSR_HPMCOUNTER14 0xc0e
#define CSR_HPMCOUNTER15 0xc0f
#define CSR_HPMCOUNTER16 0xc10
#define CSR_HPMCOUNTER17 0xc11
#define CSR_HPMCOUNTER18 0xc12
#define CSR_HPMCOUNTER19 0xc13
#define CSR_HPMCOUNTER20 0xc14
#define CSR_HPMCOUNTER21 0xc15
#define CSR_HPMCOUNTER22 0xc16
#define CSR_HPMCOUNTER23 0xc17
#define CSR_HPMCOUNTER24 0xc18
#define CSR_HPMCOUNTER25 0xc19
#define CSR_HPMCOUNTER26 0xc1a
#define CSR_HPMCOUNTER27 0xc1b
#define CSR_HPMCOUNTER28 0xc1c
#define CSR_HPMCOUNTER29 0xc1d
#define CSR_HPMCOUNTER30 0xc1e
#define CSR_HPMCOUNTER31 0xc1f
#define CSR_SSTATUS 0x100
#define CSR_SIE 0x104
#define CSR_STVEC 0x105
#define CSR_SSCRATCH 0x140
#define CSR_SEPC 0x141
#define CSR_SCAUSE 0x142
#define CSR_SBADADDR 0x143
#define CSR_SIP 0x144
#define CSR_SPTBR 0x180
#define CSR_MSTATUS 0x300
#define CSR_MISA 0x301
#define CSR_MEDELEG 0x302
#define CSR_MIDELEG 0x303
#define CSR_MIE 0x304
#define CSR_MTVEC 0x305
#define CSR_MSCRATCH 0x340
#define CSR_MEPC 0x341
#define CSR_MCAUSE 0x342
#define CSR_MBADADDR 0x343
#define CSR_MIP 0x344
#define CSR_TSELECT 0x7a0
#define CSR_TDATA1 0x7a1
#define CSR_TDATA2 0x7a2
#define CSR_TDATA3 0x7a3
#define CSR_DCSR 0x7b0
#define CSR_DPC 0x7b1
#define CSR_DSCRATCH 0x7b2
#define CSR_MCYCLE 0xb00
#define CSR_MINSTRET 0xb02
#define CSR_MHPMCOUNTER3 0xb03
#define CSR_MHPMCOUNTER4 0xb04
#define CSR_MHPMCOUNTER5 0xb05
#define CSR_MHPMCOUNTER6 0xb06
#define CSR_MHPMCOUNTER7 0xb07
#define CSR_MHPMCOUNTER8 0xb08
#define CSR_MHPMCOUNTER9 0xb09
#define CSR_MHPMCOUNTER10 0xb0a
#define CSR_MHPMCOUNTER11 0xb0b
#define CSR_MHPMCOUNTER12 0xb0c
#define CSR_MHPMCOUNTER13 0xb0d
#define CSR_MHPMCOUNTER14 0xb0e
#define CSR_MHPMCOUNTER15 0xb0f
#define CSR_MHPMCOUNTER16 0xb10
#define CSR_MHPMCOUNTER17 0xb11
#define CSR_MHPMCOUNTER18 0xb12
#define CSR_MHPMCOUNTER19 0xb13
#define CSR_MHPMCOUNTER20 0xb14
#define CSR_MHPMCOUNTER21 0xb15
#define CSR_MHPMCOUNTER22 0xb16
#define CSR_MHPMCOUNTER23 0xb17
#define CSR_MHPMCOUNTER24 0xb18
#define CSR_MHPMCOUNTER25 0xb19
#define CSR_MHPMCOUNTER26 0xb1a
#define CSR_MHPMCOUNTER27 0xb1b
#define CSR_MHPMCOUNTER28 0xb1c
#define CSR_MHPMCOUNTER29 0xb1d
#define CSR_MHPMCOUNTER30 0xb1e
#define CSR_MHPMCOUNTER31 0xb1f
#define CSR_MUCOUNTEREN 0x320
#define CSR_MSCOUNTEREN 0x321
#define CSR_MHPMEVENT3 0x323
#define CSR_MHPMEVENT4 0x324
#define CSR_MHPMEVENT5 0x325
#define CSR_MHPMEVENT6 0x326
#define CSR_MHPMEVENT7 0x327
#define CSR_MHPMEVENT8 0x328
#define CSR_MHPMEVENT9 0x329
#define CSR_MHPMEVENT10 0x32a
#define CSR_MHPMEVENT11 0x32b
#define CSR_MHPMEVENT12 0x32c
#define CSR_MHPMEVENT13 0x32d
#define CSR_MHPMEVENT14 0x32e
#define CSR_MHPMEVENT15 0x32f
#define CSR_MHPMEVENT16 0x330
#define CSR_MHPMEVENT17 0x331
#define CSR_MHPMEVENT18 0x332
#define CSR_MHPMEVENT19 0x333
#define CSR_MHPMEVENT20 0x334
#define CSR_MHPMEVENT21 0x335
#define CSR_MHPMEVENT22 0x336
#define CSR_MHPMEVENT23 0x337
#define CSR_MHPMEVENT24 0x338
#define CSR_MHPMEVENT25 0x339
#define CSR_MHPMEVENT26 0x33a
#define CSR_MHPMEVENT27 0x33b
#define CSR_MHPMEVENT28 0x33c
#define CSR_MHPMEVENT29 0x33d
#define CSR_MHPMEVENT30 0x33e
#define CSR_MHPMEVENT31 0x33f
#define CSR_MVENDORID 0xf11
#define CSR_MARCHID 0xf12
#define CSR_MIMPID 0xf13
#define CSR_MHARTID 0xf14
#define CSR_CYCLEH 0xc80
#define CSR_TIMEH 0xc81
#define CSR_INSTRETH 0xc82
#define CSR_HPMCOUNTER3H 0xc83
#define CSR_HPMCOUNTER4H 0xc84
#define CSR_HPMCOUNTER5H 0xc85
#define CSR_HPMCOUNTER6H 0xc86
#define CSR_HPMCOUNTER7H 0xc87
#define CSR_HPMCOUNTER8H 0xc88
#define CSR_HPMCOUNTER9H 0xc89
#define CSR_HPMCOUNTER10H 0xc8a
#define CSR_HPMCOUNTER11H 0xc8b
#define CSR_HPMCOUNTER12H 0xc8c
#define CSR_HPMCOUNTER13H 0xc8d
#define CSR_HPMCOUNTER14H 0xc8e
#define CSR_HPMCOUNTER15H 0xc8f
#define CSR_HPMCOUNTER16H 0xc90
#define CSR_HPMCOUNTER17H 0xc91
#define CSR_HPMCOUNTER18H 0xc92
#define CSR_HPMCOUNTER19H 0xc93
#define CSR_HPMCOUNTER20H 0xc94
#define CSR_HPMCOUNTER21H 0xc95
#define CSR_HPMCOUNTER22H 0xc96
#define CSR_HPMCOUNTER23H 0xc97
#define CSR_HPMCOUNTER24H 0xc98
#define CSR_HPMCOUNTER25H 0xc99
#define CSR_HPMCOUNTER26H 0xc9a
#define CSR_HPMCOUNTER27H 0xc9b
#define CSR_HPMCOUNTER28H 0xc9c
#define CSR_HPMCOUNTER29H 0xc9d
#define CSR_HPMCOUNTER30H 0xc9e
#define CSR_HPMCOUNTER31H 0xc9f
#define CSR_MCYCLEH 0xb80
#define CSR_MINSTRETH 0xb82
#define CSR_MHPMCOUNTER3H 0xb83
#define CSR_MHPMCOUNTER4H 0xb84
#define CSR_MHPMCOUNTER5H 0xb85
#define CSR_MHPMCOUNTER6H 0xb86
#define CSR_MHPMCOUNTER7H 0xb87
#define CSR_MHPMCOUNTER8H 0xb88
#define CSR_MHPMCOUNTER9H 0xb89
#define CSR_MHPMCOUNTER10H 0xb8a
#define CSR_MHPMCOUNTER11H 0xb8b
#define CSR_MHPMCOUNTER12H 0xb8c
#define CSR_MHPMCOUNTER13H 0xb8d
#define CSR_MHPMCOUNTER14H 0xb8e
#define CSR_MHPMCOUNTER15H 0xb8f
#define CSR_MHPMCOUNTER16H 0xb90
#define CSR_MHPMCOUNTER17H 0xb91
#define CSR_MHPMCOUNTER18H 0xb92
#define CSR_MHPMCOUNTER19H 0xb93
#define CSR_MHPMCOUNTER20H 0xb94
#define CSR_MHPMCOUNTER21H 0xb95
#define CSR_MHPMCOUNTER22H 0xb96
#define CSR_MHPMCOUNTER23H 0xb97
#define CSR_MHPMCOUNTER24H 0xb98
#define CSR_MHPMCOUNTER25H 0xb99
#define CSR_MHPMCOUNTER26H 0xb9a
#define CSR_MHPMCOUNTER27H 0xb9b
#define CSR_MHPMCOUNTER28H 0xb9c
#define CSR_MHPMCOUNTER29H 0xb9d
#define CSR_MHPMCOUNTER30H 0xb9e
#define CSR_MHPMCOUNTER31H 0xb9f

// RISCV Exception Codes
#define EXCP_NONE                       -1   // not a real RISCV exception code
#define RISCV_EXCP_INST_ADDR_MIS           0x0
#define RISCV_EXCP_INST_ACCESS_FAULT       0x1
#define RISCV_EXCP_ILLEGAL_INST            0x2
#define RISCV_EXCP_BREAKPOINT              0x3
#define RISCV_EXCP_LOAD_ADDR_MIS           0x4
#define RISCV_EXCP_LOAD_ACCESS_FAULT       0x5
#define RISCV_EXCP_STORE_AMO_ADDR_MIS      0x6
#define RISCV_EXCP_STORE_AMO_ACCESS_FAULT  0x7
#define RISCV_EXCP_U_ECALL                 0x8 // for convenience, report all
                                                   // ECALLs as this, handler fixes
#define RISCV_EXCP_S_ECALL                 0x9
#define RISCV_EXCP_H_ECALL                 0xa
#define RISCV_EXCP_M_ECALL                 0xb
// interrupts not listed here

#define IS_RV_INTERRUPT(ival) (ival & (0x1 << 31))

#define MSTATUS_UIE         0x00000001
#define MSTATUS_SIE         0x00000002
#define MSTATUS_HIE         0x00000004
#define MSTATUS_MIE         0x00000008
#define MSTATUS_UPIE        0x00000010
#define MSTATUS_SPIE        0x00000020
#define MSTATUS_HPIE        0x00000040
#define MSTATUS_MPIE        0x00000080
#define MSTATUS_SPP         0x00000100
#define MSTATUS_HPP         0x00000600
#define MSTATUS_MPP         0x00001800
#define MSTATUS_FS          0x00006000
#define MSTATUS_XS          0x00018000
#define MSTATUS_MPRV        0x00020000
#define MSTATUS_PUM         0x00040000
#define MSTATUS_MXR         0x00080000
#define MSTATUS_VM          0x1F000000

#define MSTATUS32_SD        0x80000000
#define MSTATUS64_SD        0x8000000000000000

#define SSTATUS_UIE         0x00000001
#define SSTATUS_SIE         0x00000002
#define SSTATUS_UPIE        0x00000010
#define SSTATUS_SPIE        0x00000020
#define SSTATUS_SPP         0x00000100
#define SSTATUS_FS          0x00006000
#define SSTATUS_XS          0x00018000
#define SSTATUS_PUM         0x00040000
#define SSTATUS32_SD        0x80000000
#define SSTATUS64_SD        0x8000000000000000

#define DCSR_XDEBUGVER      (3U<<30)
#define DCSR_NDRESET        (1<<29)
#define DCSR_FULLRESET      (1<<28)
#define DCSR_HWBPCOUNT      (0xfff<<16)
#define DCSR_EBREAKM        (1<<15)
#define DCSR_EBREAKH        (1<<14)
#define DCSR_EBREAKS        (1<<13)
#define DCSR_EBREAKU        (1<<12)
#define DCSR_STOPCYCLE      (1<<10)
#define DCSR_STOPTIME       (1<<9)
#define DCSR_CAUSE          (7<<6)
#define DCSR_DEBUGINT       (1<<5)
#define DCSR_HALT           (1<<3)
#define DCSR_STEP           (1<<2)
#define DCSR_PRV            (3<<0)

#define DCSR_CAUSE_NONE     0
#define DCSR_CAUSE_SWBP     1
#define DCSR_CAUSE_HWBP     2
#define DCSR_CAUSE_DEBUGINT 3
#define DCSR_CAUSE_STEP     4
#define DCSR_CAUSE_HALT     5

#define MIP_SSIP            (1 << IRQ_S_SOFT)
#define MIP_HSIP            (1 << IRQ_H_SOFT)
#define MIP_MSIP            (1 << IRQ_M_SOFT)
#define MIP_STIP            (1 << IRQ_S_TIMER)
#define MIP_HTIP            (1 << IRQ_H_TIMER)
#define MIP_MTIP            (1 << IRQ_M_TIMER)
#define MIP_SEIP            (1 << IRQ_S_EXT)
#define MIP_HEIP            (1 << IRQ_H_EXT)
#define MIP_MEIP            (1 << IRQ_M_EXT)

#define SIP_SSIP MIP_SSIP
#define SIP_STIP MIP_STIP

#define PRV_U 0
#define PRV_S 1
#define PRV_H 2
#define PRV_M 3

#define VM_MBARE 0
#define VM_MBB   1
#define VM_MBBID 2
#define VM_SV32  8
#define VM_SV39  9
#define VM_SV48  10

#define IRQ_S_SOFT   1
#define IRQ_H_SOFT   2
#define IRQ_M_SOFT   3
#define IRQ_S_TIMER  5
#define IRQ_H_TIMER  6
#define IRQ_M_TIMER  7
#define IRQ_S_EXT    9
#define IRQ_H_EXT    10
#define IRQ_M_EXT    11
#define IRQ_COP      12
#define IRQ_HOST     13
 
#define DEFAULT_RSTVEC     0x00001000
#define DEFAULT_NMIVEC     0x00001004
#define DEFAULT_MTVEC      0x00001010
#define CONFIG_STRING_ADDR 0x0000100C
#define EXT_IO_BASE        0x40000000
#define DRAM_BASE          0x80000000

// breakpoint control fields
#define BPCONTROL_X           0x00000001
#define BPCONTROL_W           0x00000002
#define BPCONTROL_R           0x00000004
#define BPCONTROL_U           0x00000008
#define BPCONTROL_S           0x00000010
#define BPCONTROL_H           0x00000020
#define BPCONTROL_M           0x00000040
#define BPCONTROL_BPMATCH     0x00000780
#define BPCONTROL_BPAMASKMAX 0x0F80000000000000
#define BPCONTROL_TDRTYPE    0xF000000000000000

// page table entry (PTE) fields
#define PTE_V     0x001 // Valid
#define PTE_R     0x002 // Read
#define PTE_W     0x004 // Write
#define PTE_X     0x008 // Execute
#define PTE_U     0x010 // User
#define PTE_G     0x020 // Global
#define PTE_A     0x040 // Accessed
#define PTE_D     0x080 // Dirty
#define PTE_SOFT  0x300 // Reserved for Software
 
#define PTE_PPN_SHIFT 10

#define PTE_TABLE(PTE) (((PTE) & (PTE_V | PTE_R | PTE_W | PTE_X)) == PTE_V)

typedef struct riscv_def_t riscv_def_t;

typedef struct TCState TCState;
struct TCState {
    target_ulong gpr[32];
    target_ulong fpr[32];
    target_ulong PC;
    target_ulong load_reservation;
};

typedef struct CPURISCVState CPURISCVState;
struct CPURISCVState {
    TCState active_tc;
    uint32_t current_tc;

    uint64_t csr[4096]; // RISCV CSR registers
    uint64_t priv;
    uint64_t badaddr;

    // temporary htif regs
    uint64_t mfromhost;
    uint64_t mtohost;

    uint64_t timecmp;

    // backup in machine.c?
    float_status fp_status;

    /* QEMU */
    CPU_COMMON

    /* Fields from here on are preserved across CPU reset. */
    const riscv_def_t *cpu_model;
    size_t memsize;
    void *irq[8];
    QEMUTimer *timer; /* Internal timer */
};

#ifndef QEMU_RISCV_CPU_QOM_H
#define QEMU_RISCV_CPU_QOM_H

#include "qom/cpu.h"

#define TYPE_RISCV_CPU "riscv-cpu"

#define RISCV_CPU_CLASS(klass) \
    OBJECT_CLASS_CHECK(RISCVCPUClass, (klass), TYPE_RISCV_CPU)
#define RISCV_CPU(obj) \
    OBJECT_CHECK(RISCVCPU, (obj), TYPE_RISCV_CPU)
#define RISCV_CPU_GET_CLASS(obj) \
    OBJECT_GET_CLASS(RISCVCPUClass, (obj), TYPE_RISCV_CPU)

/**
 * RISCVCPUClass:
 * @parent_realize: The parent class' realize handler.
 * @parent_reset: The parent class' reset handler.
 *
 * A RISCV CPU model.
 */
typedef struct RISCVCPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    DeviceRealize parent_realize;
    void (*parent_reset)(CPUState *cpu);
} RISCVCPUClass;

/**
 * RISCVCPU:
 * @env: #CPURISCVState
 *
 * A RISCV CPU.
 */
typedef struct RISCVCPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/

    CPURISCVState env;
} RISCVCPU;

static inline RISCVCPU *riscv_env_get_cpu(CPURISCVState *env)
{
    return container_of(env, RISCVCPU, env);
}

#define ENV_GET_CPU(e) CPU(riscv_env_get_cpu(e))

#define ENV_OFFSET offsetof(RISCVCPU, env)

void riscv_cpu_do_interrupt(CPUState *cpu);
void riscv_cpu_dump_state(CPUState *cpu, FILE *f, fprintf_function cpu_fprintf,
                         int flags);
hwaddr riscv_cpu_get_phys_page_debug(CPUState *cpu, vaddr addr);
int riscv_cpu_gdb_read_register(CPUState *cpu, uint8_t *buf, int reg);
int riscv_cpu_gdb_write_register(CPUState *cpu, uint8_t *buf, int reg);
bool riscv_cpu_exec_interrupt(CPUState *cs, int interrupt_request);
void  riscv_cpu_do_unaligned_access(CPUState *cs,
                                              target_ulong addr, int rw,
                                              int is_user, uintptr_t retaddr);
#endif

#if !defined(CONFIG_USER_ONLY)
void riscv_cpu_unassigned_access(CPUState *cpu, hwaddr addr, bool is_write,
        bool is_exec, int unused, unsigned size);
#endif

void riscv_cpu_list (FILE *f, fprintf_function cpu_fprintf);

#define cpu_exec cpu_riscv_exec
#define cpu_signal_handler cpu_riscv_signal_handler
#define cpu_list riscv_cpu_list

// TODO I think this is related to VMState stuff
// commenting it out breaks stuff, and there's an #ifdef CPU_SAVE_VERSION
// in include/qemu-common.h
#define CPU_SAVE_VERSION 3

static inline int cpu_mmu_index (CPURISCVState *env, bool ifetch)
{
    target_ulong mode = env->priv;
    if (!ifetch) {
         if(get_field(env->csr[CSR_MSTATUS], MSTATUS_MPRV)) {
             mode = get_field(env->csr[CSR_MSTATUS], MSTATUS_MPP);
         }
    }
    if (get_field(env->csr[CSR_MSTATUS], MSTATUS_VM) == VM_MBARE) {
        mode = PRV_M;
    }
    return mode;
}

static int ctz(target_ulong val);

static int ctz(target_ulong val)
{
  int res = 0;
  if (val)
    while ((val & 1) == 0)
      val >>= 1, res++;
  return res;
}

/*
 * Return RISC-V IRQ number if an interrupt should be taken, else -1.
 * Used in cpu-exec.c
 */
static inline int cpu_riscv_hw_interrupts_pending(CPURISCVState *env)
{

    target_ulong pending_interrupts = env->csr[CSR_MIP] & env->csr[CSR_MIE];

    target_ulong mie = get_field(env->csr[CSR_MSTATUS], MSTATUS_MIE);
    target_ulong m_enabled = env->priv < PRV_M || (env->priv == PRV_M && mie);
    target_ulong enabled_interrupts = pending_interrupts & ~env->csr[CSR_MIDELEG] & -m_enabled;

    target_ulong sie = get_field(env->csr[CSR_MSTATUS], MSTATUS_SIE);
    target_ulong s_enabled = env->priv < PRV_S || (env->priv == PRV_S && sie);
    enabled_interrupts |= pending_interrupts & env->csr[CSR_MIDELEG] & -s_enabled;

    if (enabled_interrupts) {
        target_ulong counted = ctz(enabled_interrupts);
        if (counted == IRQ_HOST) {
            // we're handing it to the cpu now, so get rid of the qemu irq
            qemu_irq_lower(env->irq[4]); // get rid of the irq request
        } else if (counted == IRQ_M_TIMER) {
            // we're handing it to the cpu now, so get rid of the qemu irq
            qemu_irq_lower(env->irq[7]); // get rid of the irq request
        } else if (counted == IRQ_S_TIMER || counted == IRQ_H_TIMER) {
            // don't lower irq here
        }
        return counted;
    } else {
        // indicates no pending interrupt to handler in cpu-exec.c
        return -1;
    }
}

#include "exec/cpu-all.h"

int cpu_riscv_exec(CPUState *cpu);
void riscv_tcg_init(void);
RISCVCPU *cpu_riscv_init(const char *cpu_model);
int cpu_riscv_signal_handler(int host_signum, void *pinfo, void *puc);

#define cpu_init(cpu_model) CPU(cpu_riscv_init(cpu_model))

/* TODO QOM'ify CPU reset and remove */
void cpu_state_reset(CPURISCVState *s);

/* hw/riscv/riscv_rtc.c  - supplies instret by approximating */
uint64_t cpu_riscv_read_instret(CPURISCVState *env);

/* hw/riscv/riscv_int.c */
void cpu_riscv_soft_irq(CPURISCVState *env, int irq, int level);

/* helper.c */
int riscv_cpu_handle_mmu_fault(CPUState *cpu, vaddr address, int rw,
                              int mmu_idx);
#if !defined(CONFIG_USER_ONLY)
hwaddr cpu_riscv_translate_address (CPURISCVState *env, target_ulong address,
		                               int rw);
#endif

static inline void cpu_get_tb_cpu_state(CPURISCVState *env, target_ulong *pc,
                                        target_ulong *cs_base, int *flags)
{
    *pc = env->active_tc.PC;
    *cs_base = 0;
    *flags = 0; // necessary to avoid compiler warning
}

#ifndef CONFIG_USER_ONLY
void csr_write_helper(CPURISCVState *env, target_ulong val_to_write,
        target_ulong csrno);
target_ulong csr_read_helper(CPURISCVState *env, target_ulong csrno);
#endif

void validate_csr(CPURISCVState *env, uint64_t which, uint64_t write, uint64_t
        new_pc);

#include "exec/exec-all.h"


#endif /* !defined (__RISCV_CPU_H__) */
