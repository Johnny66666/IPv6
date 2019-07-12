#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x6dff6778, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xba96bdd2, __VMLINUX_SYMBOL_STR(unregister_qdisc) },
	{ 0x77d0e865, __VMLINUX_SYMBOL_STR(register_qdisc) },
	{ 0x593a99b, __VMLINUX_SYMBOL_STR(init_timer_key) },
	{ 0x1ab7b371, __VMLINUX_SYMBOL_STR(fifo_create_dflt) },
	{ 0x4d1cd580, __VMLINUX_SYMBOL_STR(bfifo_qdisc_ops) },
	{ 0xc996d097, __VMLINUX_SYMBOL_STR(del_timer) },
	{ 0x4f391d0e, __VMLINUX_SYMBOL_STR(nla_parse) },
	{ 0xda3e43d1, __VMLINUX_SYMBOL_STR(_raw_spin_unlock) },
	{ 0x8834396c, __VMLINUX_SYMBOL_STR(mod_timer) },
	{ 0x7d11c268, __VMLINUX_SYMBOL_STR(jiffies) },
	{ 0x9e763530, __VMLINUX_SYMBOL_STR(reciprocal_value) },
	{ 0xd52bf1ce, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x6b2dc060, __VMLINUX_SYMBOL_STR(dump_stack) },
	{ 0xba63339c, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_bh) },
	{ 0xa75ed49f, __VMLINUX_SYMBOL_STR(qdisc_tree_decrease_qlen) },
	{ 0x1637ff0f, __VMLINUX_SYMBOL_STR(_raw_spin_lock_bh) },
	{ 0x85670f1d, __VMLINUX_SYMBOL_STR(rtnl_is_locked) },
	{ 0xd04611fe, __VMLINUX_SYMBOL_STR(noop_qdisc) },
	{ 0x16305289, __VMLINUX_SYMBOL_STR(warn_slowpath_null) },
	{ 0xc39d5154, __VMLINUX_SYMBOL_STR(skb_trim) },
	{ 0x8d7c4d2f, __VMLINUX_SYMBOL_STR(nla_put) },
	{ 0x275414d3, __VMLINUX_SYMBOL_STR(__qdisc_calculate_pkt_len) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x57ed22ef, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0xdc08cea8, __VMLINUX_SYMBOL_STR(qdisc_reset) },
	{ 0xda4af5e7, __VMLINUX_SYMBOL_STR(qdisc_destroy) },
	{ 0xd5f2172f, __VMLINUX_SYMBOL_STR(del_timer_sync) },
	{ 0xc87c1f84, __VMLINUX_SYMBOL_STR(ktime_get) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x7097bcc0, __VMLINUX_SYMBOL_STR(gnet_stats_copy_app) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "B8EF7997CCC899842F78036");
