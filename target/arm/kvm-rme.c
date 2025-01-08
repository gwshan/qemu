/*
 * QEMU Arm RME support
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright Linaro 2026
 */

#include "qemu/osdep.h"

#include "hw/core/boards.h"
#include "hw/core/cpu.h"
#include "hw/core/loader.h"
#include "hw/pci/pci.h"
#include "kvm_arm.h"
#include "migration/blocker.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/memalign.h"
#include "qemu/units.h"
#include "qom/object_interfaces.h"
#include "system/confidential-guest-support.h"
#include "system/kvm.h"
#include "system/runstate.h"

#define TYPE_RME_GUEST "rme-guest"
OBJECT_DECLARE_SIMPLE_TYPE(RmeGuest, RME_GUEST)

/*
 * Realms have a split guest-physical address space: the bottom half is private
 * to the realm, and the top half is shared with the host. Within QEMU, we use a
 * merged view of both halves. Most of RAM is private to the guest and not
 * accessible to us, but the guest shares some pages with us.
 *
 * RealmDmaRegion performs remapping of top-half accesses to system memory.
 */
struct RealmDmaRegion {
    IOMMUMemoryRegion parent_obj;
};

#define TYPE_REALM_DMA_REGION "realm-dma-region"
OBJECT_DECLARE_SIMPLE_TYPE(RealmDmaRegion, REALM_DMA_REGION)
OBJECT_DEFINE_SIMPLE_TYPE(RealmDmaRegion, realm_dma_region,
                          REALM_DMA_REGION, IOMMU_MEMORY_REGION);

struct RmeGuest {
    ConfidentialGuestSupport parent_obj;
    Notifier rom_load_notifier;
    GSList *ram_regions;
    uint8_t ipa_bits;

    RealmDmaRegion *dma_region;
    AddressSpace dma_as;
};

typedef struct RmeAlignedSlab {
    hwaddr aligned_start, aligned_end;
    hwaddr end;
    GList *region_list;
} RmeAlignedSlab;


OBJECT_DEFINE_SIMPLE_TYPE_WITH_INTERFACES(RmeGuest, rme_guest, RME_GUEST,
                                          CONFIDENTIAL_GUEST_SUPPORT,
                                          { TYPE_USER_CREATABLE }, { })

static RmeGuest *rme_guest;

static void rme_populate_slab(gpointer data, gpointer err)
{
    RmeAlignedSlab *slab = data;
    hwaddr aligned_start = slab->aligned_start;
    hwaddr aligned_end = slab->aligned_end;
    unsigned long page_size = qemu_real_host_page_size();
    size_t aligned_size = aligned_end - aligned_start;
    struct kvm_arm_rmi_populate populate_args;
    GList *list = slab->region_list;
    Error **errp = err;
    void *buffer;
    int ret;

    if (*errp) {
        return;
    }

    ret = kvm_set_memory_attributes_private(aligned_start, aligned_size);
    if (ret) {
        error_setg_errno(errp, -ret, "RME: failed to configure initial"
                         "private guest memory");
        return;
    }

    /* Allocate page-aligned memory */
    buffer = qemu_memalign(page_size, aligned_size);
    if (!buffer) {
        return;
    }

    memset(buffer, 0, aligned_size);

    for (GList *elem = g_list_first(list); elem; elem = g_list_next(elem)) {
        RomLoaderNotifyData *region = elem->data;
        hwaddr offset = region->addr - aligned_start;
        memcpy(buffer + offset, region->data, region->len);
    }

    g_list_free_full(g_steal_pointer(&slab->region_list), g_free);

    populate_args = (struct kvm_arm_rmi_populate) {
        .base = aligned_start,
        .size = aligned_size,
        .source_uaddr = (uintptr_t)buffer,
        .flags = KVM_ARM_RMI_POPULATE_FLAGS_MEASURE,
    };

    while (populate_args.size > 0) {
        ret = kvm_vm_ioctl(kvm_state, KVM_ARM_RMI_POPULATE, &populate_args, 0);
        if (ret) {
            error_setg_errno(errp, -ret,
                "failed to populate realm [0x%"HWADDR_PRIx", 0x%"HWADDR_PRIx")",
                aligned_start, aligned_end);
            break;
        }
    }

    qemu_vfree(buffer);
}

static RmeAlignedSlab *
rme_init_aligned_slab(RomLoaderNotifyData *region)
{
    RmeAlignedSlab *slab = g_malloc0(sizeof(RmeAlignedSlab));
    unsigned long page_size = qemu_real_host_page_size();
    hwaddr base = region->addr;
    hwaddr size = region->len;

    slab->aligned_start = QEMU_ALIGN_DOWN(base, page_size);
    slab->aligned_end = QEMU_ALIGN_UP(base + size, page_size);
    slab->end = base + size;

    slab->region_list = g_list_append(slab->region_list, region);

    return slab;
}

static void rme_insert_in_aligned_slab(RmeAlignedSlab *slab,
                                       RomLoaderNotifyData *region)
{
    slab->end = region->addr + region->len;
    slab->region_list = g_list_append(slab->region_list, region);
}

static GList *rme_swizzle_memory_regions(void)
{
    GSList *tmp, *node = g_steal_pointer(&rme_guest->ram_regions);
    GList *slab_list = NULL;
    RomLoaderNotifyData *region;
    RmeAlignedSlab *slab;

    /* Memory regions, i.e @node, appear in ascending order */
    while (node) {
        region = (RomLoaderNotifyData *)node->data;
        tmp = node;
        node = g_slist_remove_link(node, tmp);
        g_slist_free(tmp);

        /*
         * The slab list is empty, so simply create a slab based on the first
         * entry we got from @rme_guest->ram_regions.  Since ->ram_regions are
         * sorted, we are guaranteed to start with the lowest region.
         */
        if (!slab_list) {
            slab = rme_init_aligned_slab(region);
            slab_list = g_list_append(slab_list, slab);
            continue;
        }

        /*
         * Slabs and ->ram_regions are sorted, so we know the last slab in the
         * list is always the current one.
         */
        slab = g_list_last(slab_list)->data;

        /*
         * TODO: Add support for memory region that straddle two pages if we
         * think it is important.  Doing so may lead to large memory areas that
         * may not be accommodated easily by qemu_memalign() in
         * rme_populate_slab().
         */
        if (region->addr < slab->aligned_end &&
            region->addr + region->len > slab->aligned_end) {
            error_report("Memory region [0x%"HWADDR_PRIx", 0x%lx]"
                         "straddles two pages",
                         region->addr, region->len);
            g_free(region);
            continue;
        }

        /* Add the memory region in the current slab if it fits */
        if (region->addr >= slab->end &&
            region->addr + region->len <= slab->aligned_end) {
            rme_insert_in_aligned_slab(slab, region);
            continue;
        }

        /*
         * Allocate a new page aligned slab if the region can't be fitted
         * in the current slab.
         */
        slab = rme_init_aligned_slab(region);
        slab_list = g_list_append(slab_list, slab);
    }

    return slab_list;
}

static void rme_vm_state_change(void *opaque, bool running, RunState state)
{
    Error *errp = NULL;
    GList *slab_list;

    if (!running) {
        return;
    }

    slab_list = rme_swizzle_memory_regions();
    g_list_foreach(slab_list, rme_populate_slab, &errp);
    g_list_free_full(slab_list, g_free);
    if (errp) {
        return;
    }

    kvm_mark_guest_state_protected();
}

static gint rme_compare_ram_regions(gconstpointer a, gconstpointer b)
{
    const RomLoaderNotifyData *ra = a;
    const RomLoaderNotifyData *rb = b;

    g_assert(ra->addr != rb->addr);
    return ra->addr < rb->addr ? -1 : 1;
}

static void rme_rom_load_notify(Notifier *notifier, void *data)
{
    /* Each memory region is free'ed in rme_populate_slab() */
    RomLoaderNotifyData *region = g_memdup2(data,
                                            sizeof(struct RomLoaderNotifyData));

    /*
     * The Realm Initial Measurement (RIM) depends on the order in which we
     * initialize and populate the RAM regions. To help a verifier
     * independently calculate the RIM, sort regions by GPA.
     */
    rme_guest->ram_regions = g_slist_insert_sorted(rme_guest->ram_regions,
                                                   region,
                                                   rme_compare_ram_regions);
}

static int kvm_arm_rme_init(ConfidentialGuestSupport *cgs, Error **errp)
{
    KVMState *s = KVM_STATE(current_accel());
    static Error *rme_mig_blocker;

    if (!rme_guest) {
        return 0;
    }

    if (!kvm_vm_check_extension(s, KVM_CAP_ARM_RMI)) {
        error_setg(errp, "VM doesn't support Realms");
        return -ENODEV;
    }

    error_setg(&rme_mig_blocker, "RME: migration is not implemented");
    migrate_add_blocker(&rme_mig_blocker, &error_fatal);

    rme_guest->rom_load_notifier.notify = rme_rom_load_notify;
    rom_add_load_notifier(&rme_guest->rom_load_notifier);

    /*
     * The realm activation is done last, when the VM starts, after all images
     * have been loaded and all vcpus finalized.
     */
    qemu_add_vm_change_state_handler(rme_vm_state_change, NULL);

    cgs->require_guest_memfd = true;
    cgs->ready = true;
    return 0;
}

static void rme_guest_class_init(ObjectClass *oc, const void *data)
{
    ConfidentialGuestSupportClass *klass = CONFIDENTIAL_GUEST_SUPPORT_CLASS(oc);

    klass->kvm_init = kvm_arm_rme_init;
}

static void rme_guest_init(Object *obj)
{
    ConfidentialGuestSupport *cgs = CONFIDENTIAL_GUEST_SUPPORT(obj);

    if (rme_guest) {
        error_report("a single instance of RmeGuest is supported");
        exit(1);
    }
    rme_guest = RME_GUEST(obj);
    cgs->convert_in_place = true;
}

static void rme_guest_finalize(Object *obj)
{
}

static AddressSpace *rme_dma_get_address_space(PCIBus *bus, void *opaque,
                                               int devfn)
{
    return &rme_guest->dma_as;
}

static const PCIIOMMUOps rme_dma_ops = {
    .get_address_space = rme_dma_get_address_space,
};

void kvm_arm_rme_init_gpa_space(hwaddr highest_gpa, PCIBus *pci_bus)
{
    RealmDmaRegion *dma_region;
    const unsigned int ipa_bits = 64 - clz64(highest_gpa) + 1;

    if (!rme_guest) {
        return;
    }

    assert(ipa_bits < 64);

    /*
     * Setup a DMA translation from the shared top half of the guest-physical
     * address space to our merged view of RAM.
     */
    dma_region = g_new0(RealmDmaRegion, 1);

    memory_region_init_iommu(dma_region, sizeof(*dma_region),
                             TYPE_REALM_DMA_REGION, OBJECT(rme_guest),
                             "realm-dma-region", 1ULL << ipa_bits);
    address_space_init(&rme_guest->dma_as, MEMORY_REGION(dma_region),
                       TYPE_REALM_DMA_REGION);
    rme_guest->dma_region = dma_region;
    rme_guest->ipa_bits = ipa_bits;

    pci_setup_iommu(pci_bus, &rme_dma_ops, NULL);
}

static void realm_dma_region_init(Object *obj)
{
}

static IOMMUTLBEntry realm_dma_region_translate(IOMMUMemoryRegion *mr,
                                                hwaddr addr,
                                                IOMMUAccessFlags flag,
                                                int iommu_idx)
{
    const hwaddr address_mask = MAKE_64BIT_MASK(0, rme_guest->ipa_bits - 1);
    IOMMUTLBEntry entry = {
        .target_as = &address_space_memory,
        .iova = addr,
        .translated_addr = addr & address_mask,
        /*
         * Somewhat arbitrary granule for users that need one, such as
         * address_space_get_iotlb_entry(). Should be relatively large to
         * avoid frequent TLB misses. It can't be larger than memory region
         * alignment (eg. address_mask) because that would mask the whole
         * address, preventing vhost from finding the correct memory region.
         */
        .addr_mask = 4 * KiB - 1,
        .perm = IOMMU_RW,
    };

    return entry;
}

static void realm_dma_region_replay(IOMMUMemoryRegion *mr, IOMMUNotifier *n)
{
    /* Nothing is shared at boot */
}

static void realm_dma_region_finalize(Object *obj)
{
}

static void realm_dma_region_class_init(ObjectClass *oc, const void *data)
{
    IOMMUMemoryRegionClass *imrc = IOMMU_MEMORY_REGION_CLASS(oc);

    imrc->translate = realm_dma_region_translate;
    imrc->replay = realm_dma_region_replay;
}
