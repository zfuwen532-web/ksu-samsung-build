// SPDX-License-Identifier: GPL-2.0-only
/*
 * AVC audit spoof: rewrite the target SID of SELinux denials that concern the
 * KernelSU domain before the audit record is emitted.
 *
 * slow_avc_audit() is the point every denied access ends up in before it is
 * printed as "avc: denied { ... } tcontext=...". Swapping the tclass target SID
 * with a cover context keeps the log line but makes it point at a harmless
 * domain, so dmesg/logcat no longer shows the su context.
 */
#include <linux/atomic.h>
#include <linux/kprobes.h>
#include <linux/moduleparam.h>
#include <linux/security.h>
#include <linux/version.h>

#include "include/arch.h"
#include "include/klog.h"
#include "selinux/selinux.h"
#include "feature/avc_spoof.h"

static bool avc_spoof_enabled;
static bool avc_spoof_registered;
static atomic64_t avc_sid_pair = ATOMIC64_INIT(0);

static bool avc_spoof_param = true;
module_param_named(avc_spoof, avc_spoof_param, bool, 0644);

static int avc_spoof_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long tsid;
	u64 sid_pair;

	if (!smp_load_acquire(&avc_spoof_enabled))
		return 0;
	sid_pair = atomic64_read(&avc_sid_pair);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	tsid = PT_REGS_PARM3(regs);
#else
	tsid = PT_REGS_PARM2(regs);
#endif
	if ((u32)tsid != (u32)(sid_pair >> 32))
		return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	PT_REGS_PARM3(regs) = (u32)sid_pair;
#else
	PT_REGS_PARM2(regs) = (u32)sid_pair;
#endif
	return 0;
}

static struct kprobe avc_spoof_probe = {
	.symbol_name = "slow_avc_audit",
	.pre_handler = avc_spoof_pre_handler,
};

void __init ksu_avc_spoof_init(void)
{
	const char *cover = "u:r:priv_app:s0:c512,c768";
	u32 ksu_sid = 0, cover_sid = 0;
	int ret;

	if (!avc_spoof_param)
		return;

	ret = register_kprobe(&avc_spoof_probe);
	if (ret) {
		pr_warn("avc_spoof: probe unavailable: %d\n", ret);
		return;
	}
	avc_spoof_registered = true;

	ret = security_secctx_to_secid(KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT), &ksu_sid);
	if (ret || !ksu_sid) {
		pr_warn("avc_spoof: cannot resolve su sid: %d\n", ret);
		return;
	}
	ret = security_secctx_to_secid(cover, strlen(cover), &cover_sid);
	if (ret || !cover_sid) {
		pr_warn("avc_spoof: cannot resolve cover sid: %d\n", ret);
		return;
	}
	if (ksu_sid == cover_sid) {
		pr_warn("avc_spoof: su sid equals cover sid, nothing to do\n");
		return;
	}

	atomic64_set(&avc_sid_pair, ((u64)ksu_sid << 32) | cover_sid);
	/* Publish both SIDs before allowing probe callbacks to use them. */
	smp_store_release(&avc_spoof_enabled, true);
	pr_info("avc_spoof: enabled (su=%u -> cover=%u)\n", ksu_sid, cover_sid);
}

void __exit ksu_avc_spoof_exit(void)
{
	WRITE_ONCE(avc_spoof_enabled, false);
	if (!avc_spoof_registered)
		return;
	unregister_kprobe(&avc_spoof_probe);
	avc_spoof_registered = false;
}
