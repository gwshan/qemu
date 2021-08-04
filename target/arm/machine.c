#include "qemu/osdep.h"
#include "cpu.h"
#include "qemu/error-report.h"
#include "sysemu/kvm.h"
#include "kvm_arm.h"
#include "internals.h"
#include "migration/cpu.h"

static bool vfp_needed(void *opaque)
{
    ARMCPU *cpu = opaque;

    return (arm_feature(&cpu->env, ARM_FEATURE_AARCH64)
            ? cpu_isar_feature(aa64_fp_simd, cpu)
            : cpu_isar_feature(aa32_vfp_simd, cpu));
}

static int get_fpscr(QEMUFile *f, void *opaque, size_t size,
                     const VMStateField *field)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;
    uint32_t val = qemu_get_be32(f);

    vfp_set_fpscr(env, val);
    return 0;
}

static int put_fpscr(QEMUFile *f, void *opaque, size_t size,
                     const VMStateField *field, JSONWriter *vmdesc)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    qemu_put_be32(f, vfp_get_fpscr(env));
    return 0;
}

static const VMStateInfo vmstate_fpscr = {
    .name = "fpscr",
    .get = get_fpscr,
    .put = put_fpscr,
};

static const VMStateDescription vmstate_vfp = {
    .name = "cpu/vfp",
    .version_id = 3,
    .minimum_version_id = 3,
    .needed = vfp_needed,
    .fields = (VMStateField[]) {
        /* For compatibility, store Qn out of Zn here.  */
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[0].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[1].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[2].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[3].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[4].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[5].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[6].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[7].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[8].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[9].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[10].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[11].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[12].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[13].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[14].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[15].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[16].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[17].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[18].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[19].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[20].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[21].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[22].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[23].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[24].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[25].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[26].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[27].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[28].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[29].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[30].d, ARMCPU, 0, 2),
        VMSTATE_UINT64_SUB_ARRAY(env.vfp.zregs[31].d, ARMCPU, 0, 2),

        /* The xregs array is a little awkward because element 1 (FPSCR)
         * requires a specific accessor, so we have to split it up in
         * the vmstate:
         */
        VMSTATE_UINT32(env.vfp.xregs[0], ARMCPU),
        VMSTATE_UINT32_SUB_ARRAY(env.vfp.xregs, ARMCPU, 2, 14),
        {
            .name = "fpscr",
            .version_id = 0,
            .size = sizeof(uint32_t),
            .info = &vmstate_fpscr,
            .flags = VMS_SINGLE,
            .offset = 0,
        },
        VMSTATE_END_OF_LIST()
    }
};

static bool iwmmxt_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return arm_feature(env, ARM_FEATURE_IWMMXT);
}

static const VMStateDescription vmstate_iwmmxt = {
    .name = "cpu/iwmmxt",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = iwmmxt_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT64_ARRAY(env.iwmmxt.regs, ARMCPU, 16),
        VMSTATE_UINT32_ARRAY(env.iwmmxt.cregs, ARMCPU, 16),
        VMSTATE_END_OF_LIST()
    }
};

#ifdef TARGET_AARCH64
/* The expression ARM_MAX_VQ - 2 is 0 for pure AArch32 build,
 * and ARMPredicateReg is actively empty.  This triggers errors
 * in the expansion of the VMSTATE macros.
 */

static bool sve_needed(void *opaque)
{
    ARMCPU *cpu = opaque;

    return cpu_isar_feature(aa64_sve, cpu);
}

/* The first two words of each Zreg is stored in VFP state.  */
static const VMStateDescription vmstate_zreg_hi_reg = {
    .name = "cpu/sve/zreg_hi",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT64_SUB_ARRAY(d, ARMVectorReg, 2, ARM_MAX_VQ - 2),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_preg_reg = {
    .name = "cpu/sve/preg",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT64_ARRAY(p, ARMPredicateReg, 2 * ARM_MAX_VQ / 8),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_sve = {
    .name = "cpu/sve",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = sve_needed,
    .fields = (VMStateField[]) {
        VMSTATE_STRUCT_ARRAY(env.vfp.zregs, ARMCPU, 32, 0,
                             vmstate_zreg_hi_reg, ARMVectorReg),
        VMSTATE_STRUCT_ARRAY(env.vfp.pregs, ARMCPU, 17, 0,
                             vmstate_preg_reg, ARMPredicateReg),
        VMSTATE_END_OF_LIST()
    }
};
#endif /* AARCH64 */

static bool serror_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return env->serror.pending != 0;
}

static const VMStateDescription vmstate_serror = {
    .name = "cpu/serror",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = serror_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT8(env.serror.pending, ARMCPU),
        VMSTATE_UINT8(env.serror.has_esr, ARMCPU),
        VMSTATE_UINT64(env.serror.esr, ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

static bool irq_line_state_needed(void *opaque)
{
    return true;
}

static const VMStateDescription vmstate_irq_line_state = {
    .name = "cpu/irq-line-state",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = irq_line_state_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(env.irq_line_state, ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

static bool m_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return arm_feature(env, ARM_FEATURE_M);
}

static const VMStateDescription vmstate_m_faultmask_primask = {
    .name = "cpu/m/faultmask-primask",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = m_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(env.v7m.faultmask[M_REG_NS], ARMCPU),
        VMSTATE_UINT32(env.v7m.primask[M_REG_NS], ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

/* CSSELR is in a subsection because we didn't implement it previously.
 * Migration from an old implementation will leave it at zero, which
 * is OK since the only CPUs in the old implementation make the
 * register RAZ/WI.
 * Since there was no version of QEMU which implemented the CSSELR for
 * just non-secure, we transfer both banks here rather than putting
 * the secure banked version in the m-security subsection.
 */
static bool csselr_vmstate_validate(void *opaque, int version_id)
{
    ARMCPU *cpu = opaque;

    return cpu->env.v7m.csselr[M_REG_NS] <= R_V7M_CSSELR_INDEX_MASK
        && cpu->env.v7m.csselr[M_REG_S] <= R_V7M_CSSELR_INDEX_MASK;
}

static bool m_csselr_needed(void *opaque)
{
    ARMCPU *cpu = opaque;

    return !arm_v7m_csselr_razwi(cpu);
}

static const VMStateDescription vmstate_m_csselr = {
    .name = "cpu/m/csselr",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = m_csselr_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32_ARRAY(env.v7m.csselr, ARMCPU, M_REG_NUM_BANKS),
        VMSTATE_VALIDATE("CSSELR is valid", csselr_vmstate_validate),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_m_scr = {
    .name = "cpu/m/scr",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = m_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(env.v7m.scr[M_REG_NS], ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_m_other_sp = {
    .name = "cpu/m/other-sp",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = m_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(env.v7m.other_sp, ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

static bool m_v8m_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return arm_feature(env, ARM_FEATURE_M) && arm_feature(env, ARM_FEATURE_V8);
}

static const VMStateDescription vmstate_m_v8m = {
    .name = "cpu/m/v8m",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = m_v8m_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32_ARRAY(env.v7m.msplim, ARMCPU, M_REG_NUM_BANKS),
        VMSTATE_UINT32_ARRAY(env.v7m.psplim, ARMCPU, M_REG_NUM_BANKS),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_m_fp = {
    .name = "cpu/m/fp",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = vfp_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32_ARRAY(env.v7m.fpcar, ARMCPU, M_REG_NUM_BANKS),
        VMSTATE_UINT32_ARRAY(env.v7m.fpccr, ARMCPU, M_REG_NUM_BANKS),
        VMSTATE_UINT32_ARRAY(env.v7m.fpdscr, ARMCPU, M_REG_NUM_BANKS),
        VMSTATE_UINT32_ARRAY(env.v7m.cpacr, ARMCPU, M_REG_NUM_BANKS),
        VMSTATE_UINT32(env.v7m.nsacr, ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

static bool mve_needed(void *opaque)
{
    ARMCPU *cpu = opaque;

    return cpu_isar_feature(aa32_mve, cpu);
}

static const VMStateDescription vmstate_m_mve = {
    .name = "cpu/m/mve",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = mve_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(env.v7m.vpr, ARMCPU),
        VMSTATE_UINT32(env.v7m.ltpsize, ARMCPU),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_m = {
    .name = "cpu/m",
    .version_id = 4,
    .minimum_version_id = 4,
    .needed = m_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(env.v7m.vecbase[M_REG_NS], ARMCPU),
        VMSTATE_UINT32(env.v7m.basepri[M_REG_NS], ARMCPU),
        VMSTATE_UINT32(env.v7m.control[M_REG_NS], ARMCPU),
        VMSTATE_UINT32(env.v7m.ccr[M_REG_NS], ARMCPU),
        VMSTATE_UINT32(env.v7m.cfsr[M_REG_NS], ARMCPU),
        VMSTATE_UINT32(env.v7m.hfsr, ARMCPU),
        VMSTATE_UINT32(env.v7m.dfsr, ARMCPU),
        VMSTATE_UINT32(env.v7m.mmfar[M_REG_NS], ARMCPU),
        VMSTATE_UINT32(env.v7m.bfar, ARMCPU),
        VMSTATE_UINT32(env.v7m.mpu_ctrl[M_REG_NS], ARMCPU),
        VMSTATE_INT32(env.v7m.exception, ARMCPU),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription*[]) {
        &vmstate_m_faultmask_primask,
        &vmstate_m_csselr,
        &vmstate_m_scr,
        &vmstate_m_other_sp,
        &vmstate_m_v8m,
        &vmstate_m_fp,
        &vmstate_m_mve,
        NULL
    }
};

static bool thumb2ee_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return arm_feature(env, ARM_FEATURE_THUMB2EE);
}

static const VMStateDescription vmstate_thumb2ee = {
    .name = "cpu/thumb2ee",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = thumb2ee_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(env.teecr, ARMCPU),
        VMSTATE_UINT32(env.teehbr, ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

static bool pmsav7_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return arm_feature(env, ARM_FEATURE_PMSA) &&
           arm_feature(env, ARM_FEATURE_V7) &&
           !arm_feature(env, ARM_FEATURE_V8);
}

static bool pmsav7_rgnr_vmstate_validate(void *opaque, int version_id)
{
    ARMCPU *cpu = opaque;

    return cpu->env.pmsav7.rnr[M_REG_NS] < cpu->pmsav7_dregion;
}

static const VMStateDescription vmstate_pmsav7 = {
    .name = "cpu/pmsav7",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = pmsav7_needed,
    .fields = (VMStateField[]) {
        VMSTATE_VARRAY_UINT32(env.pmsav7.drbar, ARMCPU, pmsav7_dregion, 0,
                              vmstate_info_uint32, uint32_t),
        VMSTATE_VARRAY_UINT32(env.pmsav7.drsr, ARMCPU, pmsav7_dregion, 0,
                              vmstate_info_uint32, uint32_t),
        VMSTATE_VARRAY_UINT32(env.pmsav7.dracr, ARMCPU, pmsav7_dregion, 0,
                              vmstate_info_uint32, uint32_t),
        VMSTATE_VALIDATE("rgnr is valid", pmsav7_rgnr_vmstate_validate),
        VMSTATE_END_OF_LIST()
    }
};

static bool pmsav7_rnr_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    /* For R profile cores pmsav7.rnr is migrated via the cpreg
     * "RGNR" definition in helper.h. For M profile we have to
     * migrate it separately.
     */
    return arm_feature(env, ARM_FEATURE_M);
}

static const VMStateDescription vmstate_pmsav7_rnr = {
    .name = "cpu/pmsav7-rnr",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = pmsav7_rnr_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(env.pmsav7.rnr[M_REG_NS], ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

static bool pmsav8_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return arm_feature(env, ARM_FEATURE_PMSA) &&
        arm_feature(env, ARM_FEATURE_V8);
}

static const VMStateDescription vmstate_pmsav8 = {
    .name = "cpu/pmsav8",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = pmsav8_needed,
    .fields = (VMStateField[]) {
        VMSTATE_VARRAY_UINT32(env.pmsav8.rbar[M_REG_NS], ARMCPU, pmsav7_dregion,
                              0, vmstate_info_uint32, uint32_t),
        VMSTATE_VARRAY_UINT32(env.pmsav8.rlar[M_REG_NS], ARMCPU, pmsav7_dregion,
                              0, vmstate_info_uint32, uint32_t),
        VMSTATE_UINT32(env.pmsav8.mair0[M_REG_NS], ARMCPU),
        VMSTATE_UINT32(env.pmsav8.mair1[M_REG_NS], ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

static bool s_rnr_vmstate_validate(void *opaque, int version_id)
{
    ARMCPU *cpu = opaque;

    return cpu->env.pmsav7.rnr[M_REG_S] < cpu->pmsav7_dregion;
}

static bool sau_rnr_vmstate_validate(void *opaque, int version_id)
{
    ARMCPU *cpu = opaque;

    return cpu->env.sau.rnr < cpu->sau_sregion;
}

static bool m_security_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return arm_feature(env, ARM_FEATURE_M_SECURITY);
}

static const VMStateDescription vmstate_m_security = {
    .name = "cpu/m-security",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = m_security_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(env.v7m.secure, ARMCPU),
        VMSTATE_UINT32(env.v7m.other_ss_msp, ARMCPU),
        VMSTATE_UINT32(env.v7m.other_ss_psp, ARMCPU),
        VMSTATE_UINT32(env.v7m.basepri[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.v7m.primask[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.v7m.faultmask[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.v7m.control[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.v7m.vecbase[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.pmsav8.mair0[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.pmsav8.mair1[M_REG_S], ARMCPU),
        VMSTATE_VARRAY_UINT32(env.pmsav8.rbar[M_REG_S], ARMCPU, pmsav7_dregion,
                              0, vmstate_info_uint32, uint32_t),
        VMSTATE_VARRAY_UINT32(env.pmsav8.rlar[M_REG_S], ARMCPU, pmsav7_dregion,
                              0, vmstate_info_uint32, uint32_t),
        VMSTATE_UINT32(env.pmsav7.rnr[M_REG_S], ARMCPU),
        VMSTATE_VALIDATE("secure MPU_RNR is valid", s_rnr_vmstate_validate),
        VMSTATE_UINT32(env.v7m.mpu_ctrl[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.v7m.ccr[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.v7m.mmfar[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.v7m.cfsr[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.v7m.sfsr, ARMCPU),
        VMSTATE_UINT32(env.v7m.sfar, ARMCPU),
        VMSTATE_VARRAY_UINT32(env.sau.rbar, ARMCPU, sau_sregion, 0,
                              vmstate_info_uint32, uint32_t),
        VMSTATE_VARRAY_UINT32(env.sau.rlar, ARMCPU, sau_sregion, 0,
                              vmstate_info_uint32, uint32_t),
        VMSTATE_UINT32(env.sau.rnr, ARMCPU),
        VMSTATE_VALIDATE("SAU_RNR is valid", sau_rnr_vmstate_validate),
        VMSTATE_UINT32(env.sau.ctrl, ARMCPU),
        VMSTATE_UINT32(env.v7m.scr[M_REG_S], ARMCPU),
        /* AIRCR is not secure-only, but our implementation is R/O if the
         * security extension is unimplemented, so we migrate it here.
         */
        VMSTATE_UINT32(env.v7m.aircr, ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

static int get_cpsr(QEMUFile *f, void *opaque, size_t size,
                    const VMStateField *field)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;
    uint32_t val = qemu_get_be32(f);

    if (arm_feature(env, ARM_FEATURE_M)) {
        if (val & XPSR_EXCP) {
            /* This is a CPSR format value from an older QEMU. (We can tell
             * because values transferred in XPSR format always have zero
             * for the EXCP field, and CPSR format will always have bit 4
             * set in CPSR_M.) Rearrange it into XPSR format. The significant
             * differences are that the T bit is not in the same place, the
             * primask/faultmask info may be in the CPSR I and F bits, and
             * we do not want the mode bits.
             * We know that this cleanup happened before v8M, so there
             * is no complication with banked primask/faultmask.
             */
            uint32_t newval = val;

            assert(!arm_feature(env, ARM_FEATURE_M_SECURITY));

            newval &= (CPSR_NZCV | CPSR_Q | CPSR_IT | CPSR_GE);
            if (val & CPSR_T) {
                newval |= XPSR_T;
            }
            /* If the I or F bits are set then this is a migration from
             * an old QEMU which still stored the M profile FAULTMASK
             * and PRIMASK in env->daif. For a new QEMU, the data is
             * transferred using the vmstate_m_faultmask_primask subsection.
             */
            if (val & CPSR_F) {
                env->v7m.faultmask[M_REG_NS] = 1;
            }
            if (val & CPSR_I) {
                env->v7m.primask[M_REG_NS] = 1;
            }
            val = newval;
        }
        /* Ignore the low bits, they are handled by vmstate_m. */
        xpsr_write(env, val, ~XPSR_EXCP);
        return 0;
    }

    env->aarch64 = ((val & PSTATE_nRW) == 0);

    if (is_a64(env)) {
        pstate_write(env, val);
        return 0;
    }

    cpsr_write(env, val, 0xffffffff, CPSRWriteRaw);
    return 0;
}

static int put_cpsr(QEMUFile *f, void *opaque, size_t size,
                    const VMStateField *field, JSONWriter *vmdesc)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;
    uint32_t val;

    if (arm_feature(env, ARM_FEATURE_M)) {
        /* The low 9 bits are v7m.exception, which is handled by vmstate_m. */
        val = xpsr_read(env) & ~XPSR_EXCP;
    } else if (is_a64(env)) {
        val = pstate_read(env);
    } else {
        val = cpsr_read(env);
    }

    qemu_put_be32(f, val);
    return 0;
}

static const VMStateInfo vmstate_cpsr = {
    .name = "cpsr",
    .get = get_cpsr,
    .put = put_cpsr,
};

static int get_power(QEMUFile *f, void *opaque, size_t size,
                    const VMStateField *field)
{
    ARMCPU *cpu = opaque;
    bool powered_off = qemu_get_byte(f);
    cpu->power_state = powered_off ? PSCI_OFF : PSCI_ON;
    return 0;
}

static int put_power(QEMUFile *f, void *opaque, size_t size,
                    const VMStateField *field, JSONWriter *vmdesc)
{
    ARMCPU *cpu = opaque;

    /* Migration should never happen while we transition power states */

    if (cpu->power_state == PSCI_ON ||
        cpu->power_state == PSCI_OFF) {
        bool powered_off = (cpu->power_state == PSCI_OFF) ? true : false;
        qemu_put_byte(f, powered_off);
        return 0;
    } else {
        return 1;
    }
}

static const VMStateInfo vmstate_powered_off = {
    .name = "powered_off",
    .get = get_power,
    .put = put_power,
};

#if defined(CONFIG_KVM) && defined(TARGET_AARCH64)

#define SDEI_DEBUG(...) fprintf(stdout, __VA_ARGS__)

static bool sdei_needed(void *opaque)
{
    ARMCPU*cpu = opaque;
    CPUState *cs = CPU(cpu);
    KVMSdeiCmd *cmd = NULL;
    bool needed = true;
    int ret;

    SDEI_DEBUG("%s (%d): enter\n", __func__, cs->cpu_index);

    if (!(kvm_enabled() && kvm_arm_sdei_supported())) {
        SDEI_DEBUG("   not supported\n");
        return false;
    }

    /* v1.0.0 is the minimal required version */
    cmd = g_new(KVMSdeiCmd, 1);
    cmd->cmd = KVM_SDEI_CMD_GET_VERSION;
    ret = kvm_vm_ioctl(kvm_state, KVM_ARM_SDEI_COMMAND, cmd);
    if (ret || cmd->version < 0x10000) {
        SDEI_DEBUG("   ioctl error (%d, 0x%08x)\n", ret, cmd->version);
        needed = false;
    }

    g_free(cmd);
    return needed;
}

static bool sdei_pre_save_kevent(ARMCPU *cpu, KVMSdeiCmd *cmd)
{
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;
    bool success = true;
    int index, ret;

    if (cs->cpu_index != 0) {
        return true;
    }

    SDEI_DEBUG("%s (%d): enter\n", __func__, cs->cpu_index);

    env->sdei.kske_num = 0;
    g_free(env->sdei.kske);

    /* Retrieve number of KVM events */
    cmd->cmd = KVM_SDEI_CMD_GET_KEVENT_COUNT;
    ret = kvm_vm_ioctl(kvm_state, KVM_ARM_SDEI_COMMAND, cmd);
    if (ret) {
        SDEI_DEBUG("   count ioctl error (%d)\n", ret);
        return false;
    }

    if (cmd->count <= 0) {
        SDEI_DEBUG("   invalid count (%d)\n", cmd->count);
        return true;
    }

    /* Retrieve the KVM events */
    env->sdei.kske_num = cmd->count;
    env->sdei.kske = g_new(KVMSdeiKvmEventState, env->sdei.kske_num);
    cmd->cmd = KVM_SDEI_CMD_GET_KEVENT;
    cmd->kske_state.num = KVM_SDEI_INVALID_NUM;

    for (index = 0; index < env->sdei.kske_num; index++) {
        ret = kvm_vm_ioctl(kvm_state, KVM_ARM_SDEI_COMMAND, cmd);
        if (ret) {
            SDEI_DEBUG("   ioctl error (%d)\n", ret);
            env->sdei.kske_num = index;
            success = false;
            break;
        }

        env->sdei.kske[index] = cmd->kske_state;
    }

    return success;
}

static bool sdei_pre_save_vevent(ARMCPU *cpu, KVMSdeiCmd *cmd)
{
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;
    bool success = true;
    int index, ret;

    SDEI_DEBUG("%s (%d): enter\n", __func__, cs->cpu_index);

    env->sdei.ksve_num = 0;
    g_free(env->sdei.ksve);

    /* Retrieve number of vCPU events */
    cmd->cmd = KVM_SDEI_CMD_GET_VEVENT_COUNT;
    ret = kvm_vcpu_ioctl(cs, KVM_ARM_SDEI_COMMAND, cmd);
    if (ret) {
        SDEI_DEBUG("   count ioctl error (%d)\n", ret);
        return false;
    }

    if (cmd->count <= 0) {
        SDEI_DEBUG("   invalid count (%d)\n", cmd->count);
        return true;
    }

    /* Retrieve vCPU events */
    env->sdei.ksve_num = cmd->count;
    env->sdei.ksve = g_new(KVMSdeiVcpuEventState, env->sdei.ksve_num);
    cmd->cmd = KVM_SDEI_CMD_GET_VEVENT;
    cmd->ksve_state.num = KVM_SDEI_INVALID_NUM;

    for (index = 0; index < env->sdei.ksve_num; index++) {
        ret = kvm_vcpu_ioctl(cs, KVM_ARM_SDEI_COMMAND, cmd);
        if (ret) {
            SDEI_DEBUG("   ioctl error (%d)\n", ret);
            env->sdei.ksve_num = index;
            success = false;
            break;
        }

        env->sdei.ksve[index] = cmd->ksve_state;
    }

    return success;
}

static bool sdei_pre_save_vcpu_state(ARMCPU *cpu, KVMSdeiCmd *cmd)
{
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;
    bool success = true;
    int index, ret;

    SDEI_DEBUG("%s (%d): enter\n", __func__, cs->cpu_index);

    env->sdei.ksv_num = 0;
    g_free(env->sdei.ksv);

    /* Retrieve vCPU state and we have only one */
    env->sdei.ksv_num = 1;
    env->sdei.ksv = g_new(KVMSdeiVcpuState, env->sdei.ksv_num);
    cmd->cmd = KVM_SDEI_CMD_GET_VCPU_STATE;

    for (index = 0; index < env->sdei.ksv_num; index++) {
        ret = kvm_vcpu_ioctl(cs, KVM_ARM_SDEI_COMMAND, cmd);
        if (ret) {
            SDEI_DEBUG("   ioctl error (%d)\n", ret);
            env->sdei.ksv_num = index;
            success = false;
            break;
        }

        env->sdei.ksv[index] = cmd->ksv_state;
    }

    return success;
}

static int sdei_pre_save(void *opaque)
{
    ARMCPU *cpu = opaque;
    KVMSdeiCmd *cmd = g_new(KVMSdeiCmd, 1);

    if (!sdei_pre_save_kevent(cpu, cmd)) {
        goto out;
    }

    if (!sdei_pre_save_vevent(cpu, cmd)) {
        goto out;
    }

    sdei_pre_save_vcpu_state(cpu, cmd);

out:
    g_free(cmd);
    return 0;
}

static bool sdei_post_load_kevent(ARMCPU *cpu, KVMSdeiCmd *cmd)
{
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;
    bool success = true;
    int index, ret;

    if (cs->cpu_index != 0) {
        return true;
    }

    SDEI_DEBUG("%s (%d): enter\n", __func__, cs->cpu_index);

    if (env->sdei.kske_num <= 0) {
        SDEI_DEBUG("   invalid count (%d)\n", env->sdei.kske_num);
        return true;
    }

    for (index = 0; index < env->sdei.kske_num; index++) {
        cmd->cmd = KVM_SDEI_CMD_SET_KEVENT;
        cmd->kske_state = env->sdei.kske[index];
        ret = kvm_vm_ioctl(kvm_state, KVM_ARM_SDEI_COMMAND, cmd);
        if (ret) {
            SDEI_DEBUG("   ioctl error (%d)\n", ret);
            success = false;
            break;
        }
    }

    env->sdei.kske_num = 0;
    g_free(env->sdei.kske);
    return success;
}

static bool sdei_post_load_vevent(ARMCPU *cpu, KVMSdeiCmd *cmd)
{
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;
    bool success = true;
    int index, ret;

    SDEI_DEBUG("%s (%d): enter\n", __func__, cs->cpu_index);

    if (env->sdei.ksve_num <= 0) {
        SDEI_DEBUG("   invalid count (%d)\n", env->sdei.ksve_num);
        return true;
    }

    for (index = 0; index < env->sdei.ksve_num; index++) {
        cmd->cmd = KVM_SDEI_CMD_SET_VEVENT;
        cmd->ksve_state = env->sdei.ksve[index];
        ret = kvm_vcpu_ioctl(cs, KVM_ARM_SDEI_COMMAND, cmd);
        if (ret) {
            SDEI_DEBUG("   ioctl error (%d)\n", ret);
            success = false;
            break;
        }
    }

    env->sdei.ksve_num = 0;
    g_free(env->sdei.ksve);
    return success;
}

static bool sdei_post_load_vcpu_state(ARMCPU *cpu, KVMSdeiCmd *cmd)
{
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;
    bool success = true;
    int index, ret;

    SDEI_DEBUG("%s (%d): enter\n", __func__, cs->cpu_index);

    if (env->sdei.ksv_num <= 0) {
        SDEI_DEBUG("   invalid count (%d)\n", env->sdei.ksv_num);
        return true;
    }

    for (index = 0; index < env->sdei.ksv_num; index++) {
        cmd->cmd = KVM_SDEI_CMD_SET_VCPU_STATE;
        cmd->ksv_state = env->sdei.ksv[index];
        ret = kvm_vcpu_ioctl(cs, KVM_ARM_SDEI_COMMAND, cmd);
        if (ret) {
            SDEI_DEBUG("   ioctl error (%d)\n", ret);
            success = false;
            break;
        }
    }

    env->sdei.ksv_num = 0;
    g_free(env->sdei.ksv);
    return success;
}

static int sdei_post_load(void *opaque, int version_id)
{
    ARMCPU *cpu = opaque;
    KVMSdeiCmd *cmd = g_new(KVMSdeiCmd, 1);

    if (!sdei_post_load_kevent(cpu, cmd)) {
        goto out;
    }

    if (!sdei_post_load_vevent(cpu, cmd)) {
        goto out;
    }

    sdei_post_load_vcpu_state(cpu, cmd);

out:
    g_free(cmd);
    return 0;
}

static const VMStateDescription vmstate_sdei_kske = {
    .name = "cpu/sdei/kske",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_U64(num, KVMSdeiKvmEventState),
        VMSTATE_U32(refcount, KVMSdeiKvmEventState),
        VMSTATE_U8(route_mode, KVMSdeiKvmEventState),
        VMSTATE_U64(route_affinity, KVMSdeiKvmEventState),
        VMSTATE_U64_ARRAY(entries, KVMSdeiKvmEventState, KVM_SDEI_MAX_VCPUS),
        VMSTATE_U64_ARRAY(params, KVMSdeiKvmEventState, KVM_SDEI_MAX_VCPUS),
        VMSTATE_U64_ARRAY(registered, KVMSdeiKvmEventState,
                          KVM_SDEI_MAX_VCPUS / 64),
        VMSTATE_U64_ARRAY(enabled, KVMSdeiKvmEventState,
                          KVM_SDEI_MAX_VCPUS / 64),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_sdei_ksve = {
    .name = "cpu/sdei/ksve",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_U64(num, KVMSdeiVcpuEventState),
        VMSTATE_U32(refcount, KVMSdeiVcpuEventState),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_sdei_ksv = {
    .name = "cpu/sdei/ksv",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_U8(masked, KVMSdeiVcpuState),
        VMSTATE_U64(critical_num, KVMSdeiVcpuState),
        VMSTATE_U64(normal_num, KVMSdeiVcpuState),
        VMSTATE_U64_ARRAY(critical_regs.regs, KVMSdeiVcpuState, 18),
        VMSTATE_U64(critical_regs.pc, KVMSdeiVcpuState),
        VMSTATE_U64(critical_regs.pstate, KVMSdeiVcpuState),
        VMSTATE_U64_ARRAY(normal_regs.regs, KVMSdeiVcpuState, 18),
        VMSTATE_U64(normal_regs.pc, KVMSdeiVcpuState),
        VMSTATE_U64(normal_regs.pstate, KVMSdeiVcpuState),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_sdei = {
    .name = "cpu/sdei",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = sdei_needed,
    .pre_save = sdei_pre_save,
    .post_load = sdei_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_INT32(env.sdei.kske_num, ARMCPU),
        VMSTATE_INT32(env.sdei.ksve_num, ARMCPU),
        VMSTATE_INT32(env.sdei.ksv_num,  ARMCPU),
        VMSTATE_STRUCT_VARRAY_ALLOC(env.sdei.kske, ARMCPU, env.sdei.kske_num,
                                    0, vmstate_sdei_kske,
                                    KVMSdeiKvmEventState),
        VMSTATE_STRUCT_VARRAY_ALLOC(env.sdei.ksve, ARMCPU, env.sdei.ksve_num,
                                    0, vmstate_sdei_ksve,
                                    KVMSdeiVcpuEventState),
        VMSTATE_STRUCT_VARRAY_ALLOC(env.sdei.ksv, ARMCPU, env.sdei.ksv_num,
                                    0, vmstate_sdei_ksv,
                                    KVMSdeiVcpuState),
        VMSTATE_END_OF_LIST()
    },
};

#define ASYNC_PF_DEBUG(...) fprintf(stdout, __VA_ARGS__)

static bool async_pf_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUState *cs = CPU(cpu);
    struct kvm_arm_async_pf_cmd cmd;
    int ret;

    ASYNC_PF_DEBUG("%s (%d): enter\n", __func__, cs->cpu_index);

    if (!(kvm_enabled() && kvm_arm_async_pf_supported())) {
        ASYNC_PF_DEBUG("   not supported\n");
        return false;
    }

    cmd.cmd = KVM_ARM_ASYNC_PF_CMD_GET_VERSION;
    ret = kvm_vm_ioctl(kvm_state, KVM_ARM_ASYNC_PF_COMMAND, &cmd);
    if (ret || cmd.version < 0x10000) {
        ASYNC_PF_DEBUG("   ioctl error (%d, 0x%08x)\n", ret, cmd.version);
        return false;
    }

    return true;
}

static int async_pf_pre_save(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;
    struct kvm_arm_async_pf_cmd cmd;
    int ret;

    ASYNC_PF_DEBUG("%s (%d): enter\n", __func__, cs->cpu_index);

    cmd.cmd = KVM_ARM_ASYNC_PF_CMD_GET_SDEI;
    ret = kvm_vcpu_ioctl(cs, KVM_ARM_ASYNC_PF_COMMAND, &cmd);
    if (ret) {
        ASYNC_PF_DEBUG("   GET_SDEI ioctl error (%d)\n", ret);
        return 0;
    }

    env->apf.sdei = cmd.sdei;
    cmd.cmd = KVM_ARM_ASYNC_PF_CMD_GET_IRQ;
    ret = kvm_vcpu_ioctl(cs, KVM_ARM_ASYNC_PF_COMMAND, &cmd);
    if (ret) {
        ASYNC_PF_DEBUG("   GET_IRQ ioctl error (%d)\n", ret);
        return 0;
    }

    env->apf.irq = cmd.irq;
    cmd.cmd = KVM_ARM_ASYNC_PF_CMD_GET_CONTROL;
    ret = kvm_vcpu_ioctl(cs, KVM_ARM_ASYNC_PF_COMMAND, &cmd);
    if (ret) {
        ASYNC_PF_DEBUG("   GET_CONTROL ioctl error (%d)\n", ret);
        return 0;
    }

    env->apf.control = cmd.control;

    return 0;
}

static int async_pf_post_load(void *opaque, int version_id)
{
    ARMCPU *cpu = opaque;
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;
    struct kvm_arm_async_pf_cmd cmd;
    int ret;

    ASYNC_PF_DEBUG("%s (%d): enter (%016lx-%08x-%016lx)\n",
                   __func__, cs->cpu_index, env->apf.sdei,
                   env->apf.irq, env->apf.control);

    if (env->apf.sdei) {
        cmd.cmd = KVM_ARM_ASYNC_PF_CMD_SET_SDEI;
        cmd.sdei = env->apf.sdei;
        ret = kvm_vcpu_ioctl(cs, KVM_ARM_ASYNC_PF_COMMAND, &cmd);
        if (ret) {
            ASYNC_PF_DEBUG("   SET_SDEI ioctl error (%d)\n", ret);
            return 0;
        }
    }

    if (env->apf.irq) {
        cmd.cmd = KVM_ARM_ASYNC_PF_CMD_SET_IRQ;
        cmd.irq = env->apf.irq;
        ret = kvm_vcpu_ioctl(cs, KVM_ARM_ASYNC_PF_COMMAND, &cmd);
        if (ret) {
            ASYNC_PF_DEBUG("   SET_IRQ ioctl_error (%d)\n", ret);
            return 0;
        }
    }

    if (env->apf.control) {
        cmd.cmd = KVM_ARM_ASYNC_PF_CMD_SET_CONTROL;
        cmd.control = env->apf.control;
        ret = kvm_vcpu_ioctl(cs, KVM_ARM_ASYNC_PF_COMMAND, &cmd);
        if (ret) {
            ASYNC_PF_DEBUG("   SET_CONTROL ioctl error (%d)\n", ret);
            return 0;
        }
    }

    return 0;
}

static const VMStateDescription vmstate_async_pf = {
    .name = "cpu/async_pf",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = async_pf_needed,
    .pre_save = async_pf_pre_save,
    .post_load = async_pf_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT64(env.apf.sdei, ARMCPU),
        VMSTATE_UINT32(env.apf.irq,  ARMCPU),
        VMSTATE_UINT64(env.apf.control, ARMCPU),
        VMSTATE_END_OF_LIST()
    },
};
#endif

static int cpu_pre_save(void *opaque)
{
    ARMCPU *cpu = opaque;

    if (!kvm_enabled()) {
        pmu_op_start(&cpu->env);
    }

    if (kvm_enabled()) {
        if (!write_kvmstate_to_list(cpu)) {
            /* This should never fail */
            abort();
        }

        /*
         * kvm_arm_cpu_pre_save() must be called after
         * write_kvmstate_to_list()
         */
        kvm_arm_cpu_pre_save(cpu);
    } else {
        if (!write_cpustate_to_list(cpu, false)) {
            /* This should never fail. */
            abort();
        }
    }

    cpu->cpreg_vmstate_array_len = cpu->cpreg_array_len;
    memcpy(cpu->cpreg_vmstate_indexes, cpu->cpreg_indexes,
           cpu->cpreg_array_len * sizeof(uint64_t));
    memcpy(cpu->cpreg_vmstate_values, cpu->cpreg_values,
           cpu->cpreg_array_len * sizeof(uint64_t));

    return 0;
}

static int cpu_post_save(void *opaque)
{
    ARMCPU *cpu = opaque;

    if (!kvm_enabled()) {
        pmu_op_finish(&cpu->env);
    }

    return 0;
}

static int cpu_pre_load(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    /*
     * Pre-initialize irq_line_state to a value that's never valid as
     * real data, so cpu_post_load() can tell whether we've seen the
     * irq-line-state subsection in the incoming migration state.
     */
    env->irq_line_state = UINT32_MAX;

    if (!kvm_enabled()) {
        pmu_op_start(&cpu->env);
    }

    return 0;
}

static int cpu_post_load(void *opaque, int version_id)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;
    int i, v;

    /*
     * Handle migration compatibility from old QEMU which didn't
     * send the irq-line-state subsection. A QEMU without it did not
     * implement the HCR_EL2.{VI,VF} bits as generating interrupts,
     * so for TCG the line state matches the bits set in cs->interrupt_request.
     * For KVM the line state is not stored in cs->interrupt_request
     * and so this will leave irq_line_state as 0, but this is OK because
     * we only need to care about it for TCG.
     */
    if (env->irq_line_state == UINT32_MAX) {
        CPUState *cs = CPU(cpu);

        env->irq_line_state = cs->interrupt_request &
            (CPU_INTERRUPT_HARD | CPU_INTERRUPT_FIQ |
             CPU_INTERRUPT_VIRQ | CPU_INTERRUPT_VFIQ);
    }

    /* Update the values list from the incoming migration data.
     * Anything in the incoming data which we don't know about is
     * a migration failure; anything we know about but the incoming
     * data doesn't specify retains its current (reset) value.
     * The indexes list remains untouched -- we only inspect the
     * incoming migration index list so we can match the values array
     * entries with the right slots in our own values array.
     */

    for (i = 0, v = 0; i < cpu->cpreg_array_len
             && v < cpu->cpreg_vmstate_array_len; i++) {
        if (cpu->cpreg_vmstate_indexes[v] > cpu->cpreg_indexes[i]) {
            /* register in our list but not incoming : skip it */
            continue;
        }
        if (cpu->cpreg_vmstate_indexes[v] < cpu->cpreg_indexes[i]) {
            /* register in their list but not ours: fail migration */
            return -1;
        }
        /* matching register, copy the value over */
        cpu->cpreg_values[i] = cpu->cpreg_vmstate_values[v];
        v++;
    }

    if (kvm_enabled()) {
        if (!write_list_to_kvmstate(cpu, KVM_PUT_FULL_STATE)) {
            return -1;
        }
        /* Note that it's OK for the TCG side not to know about
         * every register in the list; KVM is authoritative if
         * we're using it.
         */
        write_list_to_cpustate(cpu);
        kvm_arm_cpu_post_load(cpu);
    } else {
        if (!write_list_to_cpustate(cpu)) {
            return -1;
        }
    }

    hw_breakpoint_update_all(cpu);
    hw_watchpoint_update_all(cpu);

    if (!kvm_enabled()) {
        pmu_op_finish(&cpu->env);
    }
    arm_rebuild_hflags(&cpu->env);

    return 0;
}

const VMStateDescription vmstate_arm_cpu = {
    .name = "cpu",
    .version_id = 22,
    .minimum_version_id = 22,
    .pre_save = cpu_pre_save,
    .post_save = cpu_post_save,
    .pre_load = cpu_pre_load,
    .post_load = cpu_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32_ARRAY(env.regs, ARMCPU, 16),
        VMSTATE_UINT64_ARRAY(env.xregs, ARMCPU, 32),
        VMSTATE_UINT64(env.pc, ARMCPU),
        {
            .name = "cpsr",
            .version_id = 0,
            .size = sizeof(uint32_t),
            .info = &vmstate_cpsr,
            .flags = VMS_SINGLE,
            .offset = 0,
        },
        VMSTATE_UINT32(env.spsr, ARMCPU),
        VMSTATE_UINT64_ARRAY(env.banked_spsr, ARMCPU, 8),
        VMSTATE_UINT32_ARRAY(env.banked_r13, ARMCPU, 8),
        VMSTATE_UINT32_ARRAY(env.banked_r14, ARMCPU, 8),
        VMSTATE_UINT32_ARRAY(env.usr_regs, ARMCPU, 5),
        VMSTATE_UINT32_ARRAY(env.fiq_regs, ARMCPU, 5),
        VMSTATE_UINT64_ARRAY(env.elr_el, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.sp_el, ARMCPU, 4),
        /* The length-check must come before the arrays to avoid
         * incoming data possibly overflowing the array.
         */
        VMSTATE_INT32_POSITIVE_LE(cpreg_vmstate_array_len, ARMCPU),
        VMSTATE_VARRAY_INT32(cpreg_vmstate_indexes, ARMCPU,
                             cpreg_vmstate_array_len,
                             0, vmstate_info_uint64, uint64_t),
        VMSTATE_VARRAY_INT32(cpreg_vmstate_values, ARMCPU,
                             cpreg_vmstate_array_len,
                             0, vmstate_info_uint64, uint64_t),
        VMSTATE_UINT64(env.exclusive_addr, ARMCPU),
        VMSTATE_UINT64(env.exclusive_val, ARMCPU),
        VMSTATE_UINT64(env.exclusive_high, ARMCPU),
        VMSTATE_UNUSED(sizeof(uint64_t)),
        VMSTATE_UINT32(env.exception.syndrome, ARMCPU),
        VMSTATE_UINT32(env.exception.fsr, ARMCPU),
        VMSTATE_UINT64(env.exception.vaddress, ARMCPU),
        VMSTATE_TIMER_PTR(gt_timer[GTIMER_PHYS], ARMCPU),
        VMSTATE_TIMER_PTR(gt_timer[GTIMER_VIRT], ARMCPU),
        {
            .name = "power_state",
            .version_id = 0,
            .size = sizeof(bool),
            .info = &vmstate_powered_off,
            .flags = VMS_SINGLE,
            .offset = 0,
        },
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription*[]) {
        &vmstate_vfp,
        &vmstate_iwmmxt,
        &vmstate_m,
        &vmstate_thumb2ee,
        /* pmsav7_rnr must come before pmsav7 so that we have the
         * region number before we test it in the VMSTATE_VALIDATE
         * in vmstate_pmsav7.
         */
        &vmstate_pmsav7_rnr,
        &vmstate_pmsav7,
        &vmstate_pmsav8,
        &vmstate_m_security,
#ifdef TARGET_AARCH64
        &vmstate_sve,
#endif
        &vmstate_serror,
        &vmstate_irq_line_state,
#if defined(CONFIG_KVM) && defined(TARGET_AARCH64)
        &vmstate_sdei,
        &vmstate_async_pf,
#endif
        NULL
    }
};
