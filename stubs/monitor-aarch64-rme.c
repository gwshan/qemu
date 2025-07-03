/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-misc-arm.h"


RmeGuestCapabilities *qmp_query_rme_guest_capabilities(Error **errp)
{
    error_setg(errp, "ARM RME is not available on this target");
    return NULL;
}
