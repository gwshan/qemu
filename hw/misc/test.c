/**
 * Gavin's PCI device emulation
 *
 * Copyright 2024 Gavin Shan <gshan@redhat.com>
 */

#include "qemu/osdep.h"
#include "hw/pci/pci_device.h"
#include "hw/hw.h"
#include "hw/pci/msi.h"
#include "standard-headers/linux/virtio_ring.h"

#define TYPE_TEST_PCI_DEVICE    "test"
typedef struct TestState TestState;
DECLARE_INSTANCE_CHECKER(TestState, TEST, TYPE_TEST_PCI_DEVICE)

struct TestState {
    PCIDevice pdev;
    MemoryRegion mmio;
    QemuThread thread;

    uint32_t num;
    uint64_t desc_phys;
    uint64_t avail_phys;
    uint64_t used_phys;

    vring_desc_t *desc;
    vring_avail_t *avail;
    vring_used_t *used;

    uint16_t avail_idx;
    uint16_t last_avail_idx;
    uint16_t last_used_idx;

    uint64_t stats_read_cnt;
};

static void test_reader_pull_desc(TestState *t)
{
    uint16_t last_avail_idx;
    uint32_t head;

    last_avail_idx = t->last_avail_idx;
    if (t->avail_idx == last_avail_idx) {
        t->avail_idx = t->avail->idx;
        if (t->avail_idx == last_avail_idx) {
            return;
        }

        __asm__ volatile("dmb ishld" : : : "memory");
    }

    head = t->avail->ring[last_avail_idx & (t->num - 1)];
    assert(head < t->num);
    t->last_avail_idx++;

    t->used->ring[t->last_used_idx & (t->num - 1)].id  = head;
    t->used->ring[t->last_used_idx & (t->num - 1)].len = 0;
    t->last_used_idx++;

    __asm__ volatile("dmb ishst" : : : "memory");

    t->used->idx = t->last_used_idx;

#if 0
    if (++t->stats_read_cnt % 1000000 == 0) {
        fprintf(stdout, "Read count: %ld\n", t->stats_read_cnt);
    }
#endif
}

static void *test_reader_thread(void *arg)
{
    TestState *t = arg;

    /* Wait until the queue setup is completed */
    do { sleep(1); } while (!t->used);

    while (true) {
        test_reader_pull_desc(t);
    }

    return NULL;
}

static uint64_t test_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    return -1UL;
}

static void test_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    TestState *t = opaque;
    hwaddr l;

    fprintf(stdout, "%s: addr=0x%lx, val=0x%lx\n", __func__, (uint64_t)addr, val);

    switch (addr) {
    case 0:   /* number of elements in vring */
        t->num = (uint32_t)val;
        break;
    case 8:   /* GPA of desctipors */
        t->desc_phys = val;
        l = t->num * sizeof(struct vring_desc);
        t->desc = cpu_physical_memory_map(val, &l, true);
        break;
    case 16: /* GPA of available queue */
        t->avail_phys = val;
        l = (t->num + 3) * sizeof(uint16_t);
        t->avail = cpu_physical_memory_map(val, &l, true);
        break;
    case 24: /* GPA of used queue */
        t->used_phys = val;
        l = 3 * sizeof(uint16_t) + t->num * sizeof(struct vring_used_elem);
        t->used = cpu_physical_memory_map(val, &l, true);
        break;
    default:
    }
}

static const MemoryRegionOps test_mmio_ops = {
    .read = test_mmio_read,
    .write = test_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 8,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 8,
        .max_access_size = 8,
    },

};

static void test_realize(PCIDevice *pdev, Error **errp)
{
    TestState *t = TEST(pdev);

    pci_config_set_interrupt_pin(pdev->config, 1);
    if (msi_init(pdev, 0, 1, true, false, errp)) {
        return;
    }

    memory_region_init_io(&t->mmio, OBJECT(t), &test_mmio_ops, t,
			  "test-mmio", 0x10000);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &t->mmio); 

    qemu_thread_create(&t->thread, "test_reader", test_reader_thread,
                       t, QEMU_THREAD_JOINABLE);
}

static void test_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = test_realize;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = 0x1234;
    k->revision = 0x0;
    k->class_id = PCI_CLASS_OTHERS;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static void test_instance_init(Object *obj)
{
    TestState *t = TEST(obj);

    t->num = 0;
    t->desc_phys = 0;
    t->avail_phys = 0;
    t->used_phys = 0;
    t->desc = NULL;
    t->avail = NULL;
    t->used = NULL;
}

static const TypeInfo test_info = {
    .name           = TYPE_TEST_PCI_DEVICE, 
    .parent         = TYPE_PCI_DEVICE,
    .instance_size  = sizeof(TestState),
    .class_init     = test_class_init,
    .instance_init  = test_instance_init,
    .interfaces     = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};	

static void test_register_types(void)
{
	type_register_static(&test_info);
}

type_init(test_register_types)
