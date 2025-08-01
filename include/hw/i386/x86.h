/*
 * Copyright (c) 2019 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HW_I386_X86_H
#define HW_I386_X86_H

#include "exec/hwaddr.h"
#include "system/memory.h"

#include "hw/boards.h"
#include "hw/i386/topology.h"
#include "hw/intc/ioapic.h"
#include "hw/isa/isa.h"
#include "qom/object.h"
#include "system/igvm-cfg.h"

struct X86MachineClass {
    MachineClass parent;

    /* use DMA capable linuxboot option rom */
    bool fwcfg_dma_enabled;
    /* CPU and apic information: */
    bool apic_xrupt_override;
};

struct X86MachineState {
    /*< private >*/
    MachineState parent;

    /*< public >*/

    /* Pointers to devices and objects: */
    ISADevice *rtc;
    FWCfgState *fw_cfg;
    qemu_irq *gsi;
    DeviceState *ioapic2;
    GMappedFile *initrd_mapped_file;
    HotplugHandler *acpi_dev;

    /*
     * Map the whole BIOS just underneath the 4 GiB address boundary. Only used
     * in the ROM (-bios) case.
     */
    MemoryRegion bios;

    /*
     * Map the upper 128 KiB of the BIOS just underneath the 1 MiB address
     * boundary.
     */
    MemoryRegion isa_bios;

    /* RAM information (sizes, addresses, configuration): */
    ram_addr_t below_4g_mem_size, above_4g_mem_size;

    /* Start address of the initial RAM above 4G */
    uint64_t above_4g_mem_start;

    /* CPU and apic information: */
    unsigned pci_irq_mask;
    unsigned apic_id_limit;
    uint16_t boot_cpus;
    SgxEPCList *sgx_epc_list;

    OnOffAuto smm;
    OnOffAuto acpi;
    OnOffAuto pit;
    OnOffAuto pic;

    char *oem_id;
    char *oem_table_id;
    /*
     * Address space used by IOAPIC device. All IOAPIC interrupts
     * will be translated to MSI messages in the address space.
     */
    AddressSpace *ioapic_as;

    /*
     * Ratelimit enforced on detected bus locks in guest.
     * The default value of the bus_lock_ratelimit is 0 per second,
     * which means no limitation on the guest's bus locks.
     */
    uint64_t bus_lock_ratelimit;

    IgvmCfg *igvm;
};

#define X86_MACHINE_SMM              "smm"
#define X86_MACHINE_ACPI             "acpi"
#define X86_MACHINE_PIT              "pit"
#define X86_MACHINE_PIC              "pic"
#define X86_MACHINE_OEM_ID           "x-oem-id"
#define X86_MACHINE_OEM_TABLE_ID     "x-oem-table-id"
#define X86_MACHINE_BUS_LOCK_RATELIMIT  "bus-lock-ratelimit"

#define TYPE_X86_MACHINE   MACHINE_TYPE_NAME("x86")
OBJECT_DECLARE_TYPE(X86MachineState, X86MachineClass, X86_MACHINE)

void init_topo_info(X86CPUTopoInfo *topo_info, const X86MachineState *x86ms);
uint32_t x86_cpu_apic_id_from_index(X86MachineState *x86ms,
                                    unsigned int cpu_index);

void x86_cpus_init(X86MachineState *pcms, int default_cpu_version);
void x86_rtc_set_cpus_count(ISADevice *rtc, uint16_t cpus_count);
void x86_cpu_pre_plug(HotplugHandler *hotplug_dev,
                      DeviceState *dev, Error **errp);
void x86_cpu_plug(HotplugHandler *hotplug_dev,
                  DeviceState *dev, Error **errp);
void x86_cpu_unplug_request_cb(HotplugHandler *hotplug_dev,
                               DeviceState *dev, Error **errp);
void x86_cpu_unplug_cb(HotplugHandler *hotplug_dev,
                       DeviceState *dev, Error **errp);

void x86_isa_bios_init(MemoryRegion *isa_bios, MemoryRegion *isa_memory,
                       MemoryRegion *bios, bool read_only);
void x86_bios_rom_init(X86MachineState *x86ms, const char *default_firmware,
                       MemoryRegion *rom_memory, bool isapc_ram_fw);

void x86_load_linux(X86MachineState *x86ms,
                    FWCfgState *fw_cfg,
                    int acpi_data_size,
                    bool pvh_enabled);

bool x86_machine_is_smm_enabled(const X86MachineState *x86ms);
bool x86_machine_is_acpi_enabled(const X86MachineState *x86ms);

/* Global System Interrupts */

#define ACPI_BUILD_PCI_IRQS ((1<<5) | (1<<9) | (1<<10) | (1<<11))

typedef struct GSIState {
    qemu_irq i8259_irq[ISA_NUM_IRQS];
    qemu_irq ioapic_irq[IOAPIC_NUM_PINS];
    qemu_irq ioapic2_irq[IOAPIC_NUM_PINS];
} GSIState;

qemu_irq x86_allocate_cpu_irq(void);
void gsi_handler(void *opaque, int n, int level);
void ioapic_init_gsi(GSIState *gsi_state, Object *parent);
DeviceState *ioapic_init_secondary(GSIState *gsi_state);

/* pc_sysfw.c */
void x86_firmware_configure(hwaddr gpa, void *ptr, int size);

#endif
