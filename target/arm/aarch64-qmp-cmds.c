/*
 * Support QMP command for AARCH64
 *
 */

#include "qemu/osdep.h"
#include "kvm_arm.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-misc-arm.h"
#include "qapi/qapi-commands-qom.h"
#include "system/kvm.h"

static RmeMeasurementAlgorithm *rme_measurement_algo_section(void)
{
    RmeMeasurementAlgorithm *malgo;
    RmeGuestMeasurementAlgorithmList *head = NULL, **tail = &head;

    malgo = g_new0(RmeMeasurementAlgorithm, 1);

    QAPI_LIST_APPEND(tail, RME_GUEST_MEASUREMENT_ALGORITHM_SHA256);
    QAPI_LIST_APPEND(tail, RME_GUEST_MEASUREMENT_ALGORITHM_SHA512);

    malgo->measurement_algorithms = head;

    return malgo;
}

RmeGuestCapabilities *qmp_query_rme_guest_capabilities(Error **errp)
{
    RmeGuestCapabilities *info = NULL;

    if (!kvm_enabled()) {
        error_setg(errp, "KVM not enabled");
        return NULL;
    }

    if (!kvm_check_extension(kvm_state, KVM_CAP_ARM_RME)) {
        error_setg(errp, "RME is not enabled in KVM");
        return NULL;
    }

    info = g_new0(RmeGuestCapabilities, 1);
    info->section = rme_measurement_algo_section();

    return info;
}

