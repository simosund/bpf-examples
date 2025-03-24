#ifndef __VMLINUX_NET_H__
#define __VMLINUX_NET_H__

typedef __u32 __wsum;

typedef unsigned int sk_buff_data_t; // Assumes 64-bit. FIXME see below
/*
// BITS_PER_LONG can be wrong with -target bpf
#if BITS_PER_LONG > 32
#define NET_SKBUFF_DATA_USES_OFFSET 1
#endif

#ifdef NET_SKBUFF_DATA_USES_OFFSET
typedef unsigned int sk_buff_data_t;
#else
typedef unsigned char *sk_buff_data_t;
#endif
*/

struct sk_buff {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
			union {
				struct net_device *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
	};
	union {
		struct sock *sk;
		int ip_defrag_offset;
	};
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff *);
		};
		struct list_head tcp_tsorted_anchor;
	};
	long unsigned int _nfct;
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 active_extensions;
	__u32 headers_start[0];
	__u8 __pkt_type_offset[0];
	__u8 pkt_type: 3;
	__u8 ignore_df: 1;
	__u8 nf_trace: 1;
	__u8 ip_summed: 2;
	__u8 ooo_okay: 1;
	__u8 l4_hash: 1;
	__u8 sw_hash: 1;
	__u8 wifi_acked_valid: 1;
	__u8 wifi_acked: 1;
	__u8 no_fcs: 1;
	__u8 encapsulation: 1;
	__u8 encap_hdr_csum: 1;
	__u8 csum_valid: 1;
	__u8 __pkt_vlan_present_offset[0];
	__u8 vlan_present: 1;
	__u8 csum_complete_sw: 1;
	__u8 csum_level: 2;
	__u8 csum_not_inet: 1;
	__u8 dst_pending_confirm: 1;
	__u8 ndisc_nodetype: 2;
	__u8 ipvs_property: 1;
	__u8 inner_protocol_type: 1;
	__u8 remcsum_offload: 1;
	__u8 offload_fwd_mark: 1;
	__u8 offload_l3_fwd_mark: 1;
	__u8 tc_skip_classify: 1;
	__u8 tc_at_ingress: 1;
	__u8 redirected: 1;
	__u8 from_ingress: 1;
	__u8 decrypted: 1;
	__u16 tc_index;
	union {
		__wsum csum;
		struct {
			__u16 csum_start;
			__u16 csum_offset;
		};
	};
	__u32 priority;
	int skb_iif;
	__u32 hash;
	__be16 vlan_proto;
	__u16 vlan_tci;
	union {
		unsigned int napi_id;
		unsigned int sender_cpu;
	};
	__u32 secmark;
	union {
		__u32 mark;
		__u32 reserved_tailroom;
	};
	union {
		__be16 inner_protocol;
		__u8 inner_ipproto;
	};
	__u16 inner_transport_header;
	__u16 inner_network_header;
	__u16 inner_mac_header;
	__be16 protocol;
	__u16 transport_header;
	__u16 network_header;
	__u16 mac_header;
	__u32 headers_end[0];
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
};

struct nf_conn {
	unsigned long status;
};

enum ip_conntrack_status {
	/* Connection is confirmed: originating packet has left box */
	IPS_CONFIRMED_BIT = 3,
	IPS_CONFIRMED = (1 << IPS_CONFIRMED_BIT),
};

struct scm_timestamping_internal {
        struct timespec64 ts[3];
};

struct sk_buff_list {
	struct sk_buff *next;
	struct sk_buff *prev;
};

struct sk_buff_head {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
		};
		struct sk_buff_list list;
	};
	__u32 qlen;
	/* spinlock_t lock; */
};

struct sock {
	/* struct sock_common __sk_common; */
	/* __u8 __cacheline_group_begin__sock_write_rx[0]; */
	/* atomic_t sk_drops; */
	/* __s32 sk_peek_off; */
	struct sk_buff_head sk_error_queue;
	struct sk_buff_head sk_receive_queue;
	/* struct { */
	/* 	atomic_t rmem_alloc; */
	/* 	int len; */
	/* 	struct sk_buff *head; */
	/* 	struct sk_buff *tail; */
	/* } sk_backlog; */
	/* __u8 __cacheline_group_end__sock_write_rx[0]; */
	/* __u8 __cacheline_group_begin__sock_read_rx[0]; */
	/* struct dst_entry *sk_rx_dst; */
	/* int sk_rx_dst_ifindex; */
	/* u32 sk_rx_dst_cookie; */
	/* unsigned int sk_ll_usec; */
	/* unsigned int sk_napi_id; */
	/* u16 sk_busy_poll_budget; */
	/* u8 sk_prefer_busy_poll; */
	/* u8 sk_userlocks; */
	/* int sk_rcvbuf; */
	/* struct sk_filter *sk_filter; */
	/* union { */
	/* 	struct socket_wq *sk_wq; */
	/* 	struct socket_wq *sk_wq_raw; */
	/* }; */
	/* void (*sk_data_ready)(struct sock *); */
	/* long int sk_rcvtimeo; */
	/* int sk_rcvlowat; */
	/* __u8 __cacheline_group_end__sock_read_rx[0]; */
	/* __u8 __cacheline_group_begin__sock_read_rxtx[0]; */
	/* int sk_err; */
	/* struct socket *sk_socket; */
	/* struct mem_cgroup *sk_memcg; */
	/* struct xfrm_policy *sk_policy[2]; */
	/* __u8 __cacheline_group_end__sock_read_rxtx[0]; */
	/* __u8 __cacheline_group_begin__sock_write_rxtx[0]; */
	/* socket_lock_t sk_lock; */
	/* u32 sk_reserved_mem; */
	/* int sk_forward_alloc; */
	/* u32 sk_tsflags; */
	/* __u8 __cacheline_group_end__sock_write_rxtx[0]; */
	/* __u8 __cacheline_group_begin__sock_write_tx[0]; */
	/* int sk_write_pending; */
	/* atomic_t sk_omem_alloc; */
	/* int sk_sndbuf; */
	/* int sk_wmem_queued; */
	/* refcount_t sk_wmem_alloc; */
	/* long unsigned int sk_tsq_flags; */
	/* union { */
	/* 	struct sk_buff *sk_send_head; */
	/* 	struct rb_root tcp_rtx_queue; */
	/* }; */
	/* struct sk_buff_head sk_write_queue; */
	/* u32 sk_dst_pending_confirm; */
	/* u32 sk_pacing_status; */
	/* struct page_frag sk_frag; */
	/* struct timer_list sk_timer; */
	/* long unsigned int sk_pacing_rate; */
	/* atomic_t sk_zckey; */
	/* atomic_t sk_tskey; */
	/* __u8 __cacheline_group_end__sock_write_tx[0]; */
	/* __u8 __cacheline_group_begin__sock_read_tx[0]; */
	/* long unsigned int sk_max_pacing_rate; */
	/* long int sk_sndtimeo; */
	/* u32 sk_priority; */
	/* u32 sk_mark; */
	/* struct dst_entry *sk_dst_cache; */
	/* netdev_features_t sk_route_caps; */
	/* u16 sk_gso_type; */
	/* u16 sk_gso_max_segs; */
	/* unsigned int sk_gso_max_size; */
	/* gfp_t sk_allocation; */
	/* u32 sk_txhash; */
	/* u8 sk_pacing_shift; */
	/* bool sk_use_task_frag; */
	/* __u8 __cacheline_group_end__sock_read_tx[0]; */
	/* u8 sk_gso_disabled : 1; */
	/* u8 sk_kern_sock : 1; */
	/* u8 sk_no_check_tx : 1; */
	/* u8 sk_no_check_rx : 1; */
	/* u8 sk_shutdown; */
	/* u16 sk_type; */
	/* u16 sk_protocol; */
	/* long unsigned int sk_lingertime; */
	/* struct proto *sk_prot_creator; */
	/* rwlock_t sk_callback_lock; */
	/* int sk_err_soft; */
	/* u32 sk_ack_backlog; */
	/* u32 sk_max_ack_backlog; */
	/* kuid_t sk_uid; */
	/* spinlock_t sk_peer_lock; */
	/* int sk_bind_phc; */
	/* struct pid *sk_peer_pid; */
	/* const struct cred *sk_peer_cred; */
	/* ktime_t sk_stamp; */
	/* int sk_disconnects; */
	/* u8 sk_txrehash; */
	/* u8 sk_clockid; */
	/* u8 sk_txtime_deadline_mode : 1; */
	/* u8 sk_txtime_report_errors : 1; */
	/* u8 sk_txtime_unused : 6; */
	/* void *sk_user_data; */
	/* void *sk_security; */
	/* struct sock_cgroup_data sk_cgrp_data; */
	/* void (*sk_state_change)(struct sock *); */
	/* void (*sk_write_space)(struct sock *); */
	/* void (*sk_error_report)(struct sock *); */
	/* int (*sk_backlog_rcv)(struct sock *, struct sk_buff *); */
	/* void (*sk_destruct)(struct sock *); */
	/* struct sock_reuseport *sk_reuseport_cb; */
	/* struct bpf_local_storage *sk_bpf_storage; */
	/* struct callback_head sk_rcu; */
	/* netns_tracker ns_tracker; */
	/* struct xarray sk_user_frags; */
};

#endif /* __VMLINUX_NET_H__ */
