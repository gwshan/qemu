#ifndef __QEMU_DEBUG_H__
#define __QEMU_DEBUG_H__

extern bool global_track_memory;

static inline bool qemu_dbg_matched_name(const char *name)
{
    if (strlen(name) == strlen("virtio-iommu") &&
        !strcmp(name, "virtio-iommu")) {
        return true;
    }

    return false;
}

#define QEMU_DBG(debug, fmt, ...)			\
    do {						\
        if (debug) {					\
            fprintf(stdout, fmt, ##__VA_ARGS__);	\
        }						\
    } while (0)

#endif /* __QEMU_DEBUG_H__ */
