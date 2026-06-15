/*
 * QEMU Arm RME support
 *
 * Copyright Linaro 2024
 */

#include "qemu/osdep.h"

#include "hw/core/boards.h"
#include "hw/core/cpu.h"
#include "hw/core/loader.h"
#include "kvm_arm.h"
#include "migration/blocker.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qom/object_interfaces.h"
#include "system/confidential-guest-support.h"
#include "system/kvm.h"
#include "system/runstate.h"

#define TYPE_RME_GUEST "rme-guest"
OBJECT_DECLARE_SIMPLE_TYPE(RmeGuest, RME_GUEST)

#define RME_PAGE_SIZE qemu_real_host_page_size()

typedef struct {
    AddressSpace *as;
    MemoryRegion *mr;
    hwaddr base;
    hwaddr size;
    void   *data;
} RmeRamRegion;

struct RmeGuest {
    ConfidentialGuestSupport parent_obj;
    Notifier rom_load_notifier;
    GSList *ram_regions;
};

OBJECT_DEFINE_SIMPLE_TYPE_WITH_INTERFACES(RmeGuest, rme_guest, RME_GUEST,
                                          CONFIDENTIAL_GUEST_SUPPORT,
                                          { TYPE_USER_CREATABLE }, { })

static RmeGuest *rme_guest;

static int rme_populate_range(const RmeRamRegion *region,
                              bool measure, Error **errp)
{
    int ret;
    hwaddr start = QEMU_ALIGN_DOWN(region->base, RME_PAGE_SIZE);
    hwaddr end = QEMU_ALIGN_UP(region->base + region->size, RME_PAGE_SIZE);
    MemoryRegion *mr = region->mr;
    struct kvm_arm_rmi_populate req = {
        .base = start,
        .size = end - start,
        .flags = measure ? KVM_ARM_RMI_POPULATE_FLAGS_MEASURE : 0,
    };

    if (mr) {
        req.source_uaddr = (uintptr_t)memory_region_get_ram_ptr(region->mr);
        req.source_uaddr = QEMU_ALIGN_DOWN(req.source_uaddr, RME_PAGE_SIZE);
    } else {
        hwaddr addr1, l = end - start;

        mr = address_space_translate(region->as, start, &addr1,
                                     &l, false, MEMTXATTRS_UNSPECIFIED);
        if (!mr) {
            error_setg(errp, "Unable to find MemoryRegion at 0x%"HWADDR_PRIx, start);
            return -ENOENT;
        }

        if (!memory_region_supports_direct_access(mr)) {
            error_setg(errp, "MemoryRegion at 0x%"HWADDR_PRIx" not directly accessed",
                       start);
            return -EACCES;
        }

        /* The address should have been properly aligned */
        req.source_uaddr = (uintptr_t)qemu_map_ram_ptr(mr->ram_block, addr1);
    }

    ret = kvm_vm_ioctl(kvm_state, KVM_ARM_RMI_POPULATE, &req);
    if (ret) {
        error_setg_errno(errp, -ret,
            "failed to populate realm [0x%"HWADDR_PRIx", 0x%"HWADDR_PRIx") 0x%"PRIx64"",
            start, end, (uint64_t)(req.source_uaddr));
    }

    return ret;
}

static void rme_populate_ram_region(gpointer data, gpointer err)
{
    const RmeRamRegion *region = data;
    Error **errp = err;

    if (*errp) {
        return;
    }

    rme_populate_range(region, /* measure */ true, errp);
}

static int rme_create_realm(Error **errp)
{
    g_slist_foreach(rme_guest->ram_regions, rme_populate_ram_region, errp);
    g_slist_free_full(g_steal_pointer(&rme_guest->ram_regions), g_free);
    if (*errp) {
        return -1;
    }

    kvm_mark_guest_state_protected();
    return 0;
}

static void rme_vm_state_change(void *opaque, bool running, RunState state)
{
    Error *err = NULL;

    if (!running) {
        return;
    }

    if (rme_create_realm(&err)) {
        error_propagate_prepend(&error_fatal, err, "RME: ");
    }
}

static void rme_guest_class_init(ObjectClass *oc, const void *data)
{
}

static void rme_guest_init(Object *obj)
{
    if (rme_guest) {
        error_report("a single instance of RmeGuest is supported");
        exit(1);
    }
    rme_guest = RME_GUEST(obj);
}

static void rme_guest_finalize(Object *obj)
{
}

static gint rme_compare_ram_regions(gconstpointer a, gconstpointer b)
{
        const RmeRamRegion *ra = a;
        const RmeRamRegion *rb = b;

        g_assert(ra->base != rb->base);
        return ra->base < rb->base ? -1 : 1;
}

static void rme_rom_load_notify(Notifier *notifier, void *data)
{
    RmeRamRegion *region;
    RomLoaderNotifyData *rom = data;

    if (rom->addr == -1) {
        /*
         * These blobs (ACPI tables) are not loaded into guest RAM at reset.
         * Instead the firmware will load them via fw_cfg and measure them
         * itself.
         */
        return;
    }

    region = g_new0(RmeRamRegion, 1);
    region->as = rom->as;
    region->mr = rom->mr;
    region->base = rom->addr;
    region->size = rom->len;
    region->data = rom->data;

    /*
     * The Realm Initial Measurement (RIM) depends on the order in which we
     * initialize and populate the RAM regions. To help a verifier
     * independently calculate the RIM, sort regions by GPA.
     */
    rme_guest->ram_regions = g_slist_insert_sorted(rme_guest->ram_regions,
                                                   region,
                                                   rme_compare_ram_regions);
}

int kvm_arm_rme_init(MachineState *ms)
{
    static Error *rme_mig_blocker;
    ConfidentialGuestSupport *cgs = ms->cgs;

    if (!rme_guest) {
        return 0;
    }

    if (!cgs) {
        error_report("missing -machine confidential-guest-support parameter");
        return -EINVAL;
    }

    if (!kvm_check_extension(kvm_state, KVM_CAP_ARM_RMI)) {
        return -ENODEV;
    }

    error_setg(&rme_mig_blocker, "RME: migration is not implemented");
    migrate_add_blocker(&rme_mig_blocker, &error_fatal);

    /*
     * The realm activation is done last, when the VM starts, after all images
     * have been loaded and all vcpus finalized.
     */
    qemu_add_vm_change_state_handler(rme_vm_state_change, NULL);

    rme_guest->rom_load_notifier.notify = rme_rom_load_notify;
    rom_add_load_notifier(&rme_guest->rom_load_notifier);

    cgs->require_guest_memfd = true;
    cgs->ready = true;
    return 0;
}

int kvm_arm_rme_vcpu_init(CPUState *cs)
{
    ARMCPU *cpu = ARM_CPU(cs);

    if (rme_guest) {
        cpu->kvm_rme = true;
    }
    return 0;
}

int kvm_arm_rme_vm_type(MachineState *ms)
{
    if (rme_guest) {
        return KVM_VM_TYPE_ARM_REALM;
    }
    return 0;
}
