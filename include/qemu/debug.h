#ifndef __QEMU_DEBUG_H__
#define __QEMU_DEBUG_H__

static inline bool qemu_dbg_matched_name(const char *name)
{
    if (name && strlen(name) == strlen("virtio-net-pci") &&
        !strcmp(name, "virtio-net-pci")) {
        return true;
    }

    return false;
}

static inline bool qemu_dbg_target_class(ObjectClass *klass)
{
    return qemu_dbg_matched_name(object_class_get_name(klass));
}

static inline bool qemu_dbg_target_object(const Object *obj)
{
    return qemu_dbg_matched_name(object_get_typename(obj));

}

#define qemu_dbg(debug, fmt, ...)			\
    do {						\
        if (debug) {					\
            fprintf(stdout, fmt, ##__VA_ARGS__);	\
        }						\
    } while(0)

#endif /* __QEMU_DEBUG_H__ */
