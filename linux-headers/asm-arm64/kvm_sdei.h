/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Definitions of various KVM SDEI event states.
 *
 * Copyright (C) 2021 Red Hat, Inc.
 *
 * Author(s): Gavin Shan <gshan@redhat.com>
 */

#ifndef _UAPI__ASM_KVM_SDEI_H
#define _UAPI__ASM_KVM_SDEI_H

#define KVM_SDEI_MAX_VCPUS     512
#define KVM_SDEI_INVALID_NUM   0
#define KVM_SDEI_DEFAULT_NUM   0x40400000

struct kvm_sdei_event_state {
	uint64_t	num;

	uint8_t		type;
	uint8_t		signaled;
	uint8_t		priority;
};

struct kvm_sdei_kvm_event_state {
	uint64_t	num;
	uint32_t	refcount;

	uint8_t		route_mode;
	uint64_t	route_affinity;
	uint64_t	entries[KVM_SDEI_MAX_VCPUS];
	uint64_t	params[KVM_SDEI_MAX_VCPUS];
	uint64_t	registered[KVM_SDEI_MAX_VCPUS/64];
	uint64_t	enabled[KVM_SDEI_MAX_VCPUS/64];
};

struct kvm_sdei_vcpu_event_state {
	uint64_t	num;
	uint32_t	refcount;
};

struct kvm_sdei_vcpu_regs {
	uint64_t	regs[18];
	uint64_t	pc;
	uint64_t	pstate;
};

struct kvm_sdei_vcpu_state {
	uint8_t				masked;
	uint64_t			critical_num;
	uint64_t			normal_num;
	struct kvm_sdei_vcpu_regs	critical_regs;
	struct kvm_sdei_vcpu_regs	normal_regs;
};

#define KVM_SDEI_CMD_GET_VERSION		0
#define KVM_SDEI_CMD_SET_EVENT			1
#define KVM_SDEI_CMD_GET_KEVENT_COUNT		2
#define KVM_SDEI_CMD_GET_KEVENT			3
#define KVM_SDEI_CMD_SET_KEVENT			4
#define KVM_SDEI_CMD_GET_VEVENT_COUNT		5
#define KVM_SDEI_CMD_GET_VEVENT			6
#define KVM_SDEI_CMD_SET_VEVENT			7
#define KVM_SDEI_CMD_GET_VCPU_STATE		8
#define KVM_SDEI_CMD_SET_VCPU_STATE		9
#define KVM_SDEI_CMD_INJECT_EVENT		10

struct kvm_sdei_cmd {
	uint32_t					cmd;
	union {
		uint32_t				version;
		uint32_t				count;
		uint64_t				num;
		struct kvm_sdei_event_state		kse_state;
		struct kvm_sdei_kvm_event_state		kske_state;
		struct kvm_sdei_vcpu_event_state	ksve_state;
		struct kvm_sdei_vcpu_state		ksv_state;
	};
};

#endif /* _UAPI__ASM_KVM_SDEI_H */
