#ifndef QEMU_DEBUG_H
#define QEMU_DEBUG_H

#define QEMU_DBG_CPU_TYPENAME0		"host-arm-cpu"
#define QEMU_DBG_CPU_TYPENAME1		"cortex-a710-arm-cpu"

static inline bool qemu_is_debug_typename(const char *name)
{
    if (!strcmp(name, QEMU_DBG_CPU_TYPENAME0) ||
        !strcmp(name, QEMU_DBG_CPU_TYPENAME1)) {
        return true;
    }

    return false;
}

static inline bool qemu_is_debug_class(ObjectClass *klass)
{
    if (!klass) {
        return false;
    }

    return qemu_is_debug_typename(object_class_get_name(klass));
}

static inline bool qemu_is_debug_object(Object *obj)
{
    if (!obj) {
        return false;
    }

    return qemu_is_debug_typename(object_get_typename(obj));
}

#define QEMU_DBG(debug, fmt, ...)			\
    do {						\
        if ((debug)) {					\
            fprintf(stdout, fmt, ##__VA_ARGS__);	\
        }						\
    } while (0)

#endif /* QEMU_DEBUG_H */
