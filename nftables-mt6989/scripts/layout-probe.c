/* SPDX-License-Identifier: GPL-2.0 */
/* Compile with the module's exact Kbuild configuration; never load this probe. */
#include <linux/module.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <linux/netfilter.h>
struct module probe_module;
struct net probe_net;
struct netns_nf probe_netns_nf;
struct netns_ct probe_netns_ct;
struct nf_conn probe_nf_conn;
struct nf_conntrack_net probe_nf_conntrack_net;
struct nf_ct_ext probe_nf_ct_ext;
struct nf_hook_state probe_nf_hook_state;
struct nf_hook_ops probe_nf_hook_ops;
