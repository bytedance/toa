

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>

#include <linux/err.h>
#include <linux/time.h>

#include <linux/skbuff.h>
#include <linux/netdevice.h>

#include <net/tcp.h>
#include <net/inet_common.h>
#include <net/net_namespace.h>
#include <net/ipv6.h>
#include <net/transp_v6.h>
#include <net/sock.h>

#include <linux/sysctl.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>



#include "toa.h"


// #include "toa.h"
// #include <linux/list.h>

// // #define CONFIG_IP_VS_TOA_IPV6

// /*
//  *	TOA: Address is a new TCP Option
//  *	Address include ip+port, Now only support IPV4
//  */

// unsigned long sk_data_ready_addr = 0;

// /* sk_user_data type */
// enum sk_user_data_type {
//     TOA_SK_USER_DATA_IP4 = 0,
//     TOA_SK_USER_DATA_IP4_EXTRA = 1,
//     TOA_SK_USER_DATA_LAST
// };

// /* toa list table array */
// #define TOA_TAB_BITS    12
// #define TOA_TAB_SIZE    (1 << TOA_TAB_BITS)
// #define TOA_TAB_MASK    (TOA_TAB_SIZE - 1)

// struct toa_entry {
//     struct toa_extra_data toa_data;
//     struct sock *sk;

//     struct list_head list;
// };

// struct toa_list_head {
//     struct list_head toa_head;
//     spinlock_t lock;
// } __attribute__((__aligned__(SMP_CACHE_BYTES)));

// static struct toa_list_head
// __toa_list_tab[TOA_TAB_SIZE] __cacheline_aligned;

// /* per-cpu lock for toa */
// struct toa_sk_lock {
//     /* lock for sk of toa */
//     spinlock_t __percpu *lock;
// };

// static struct toa_sk_lock toa_sk_lock;

// /*
//  * Statistics of toa in proc /proc/net/toa_stats
//  */

// struct toa_stats_entry toa_stats[] = {
// 	TOA_STAT_ITEM("syn_recv_sock_toa", SYN_RECV_SOCK_TOA_CNT),
// 	TOA_STAT_ITEM("syn_recv_sock_no_toa", SYN_RECV_SOCK_NO_TOA_CNT),
// 	TOA_STAT_ITEM("getname_toa_ok", GETNAME_TOA_OK_CNT),
// 	TOA_STAT_ITEM("getname_toa_mismatch", GETNAME_TOA_MISMATCH_CNT),
// 	TOA_STAT_ITEM("getname_toa_bypass", GETNAME_TOA_BYPASS_CNT),
// 	TOA_STAT_ITEM("getname_toa_empty", GETNAME_TOA_EMPTY_CNT),
// 	TOA_STAT_ITEM("toa_entry_alloc", TOA_ENTRY_ADDR_ALLOC_CNT),
// 	TOA_STAT_ITEM("toa_entry_free", TOA_ENTRY_ADDR_FREE_CNT),
// 	TOA_STAT_END
// };

// DEFINE_TOA_STAT(struct toa_stat_mib, ext_stats);

// /* calculate toa entry hash key */
// static inline __u32
// cal_toa_entry_hash(struct toa_extra_data *ptr_toa_data)
// {
// 	__u32 hash_key =
//         jhash_3words(ntohl(ptr_toa_data->legacy_data.ip),
//                      ptr_toa_data->legacy_data.port, ptr_toa_data->dst_ip,
//                      ptr_toa_data->dst_port) & TOA_TAB_MASK;

//     return hash_key;
// }

// static void
// toa_entry_hash(struct toa_entry *ptr_entry)
// {
//     struct toa_extra_data *ptr_toa_data = &ptr_entry->toa_data;
//     __u32 hash_key = cal_toa_entry_hash(ptr_toa_data);

//     spin_lock_bh(&__toa_list_tab[hash_key].lock);

//     list_add(&ptr_entry->list, &__toa_list_tab[hash_key].toa_head);

//     spin_unlock_bh(&__toa_list_tab[hash_key].lock);

//     return;
// }

// static void
// toa_entry_unhash(struct toa_entry *ptr_entry)
// {
//     struct toa_extra_data *ptr_toa_data = &ptr_entry->toa_data;
//     __u32 hash_key = cal_toa_entry_hash(ptr_toa_data);

//     spin_lock_bh(&__toa_list_tab[hash_key].lock);

//     list_del(&ptr_entry->list);

//     spin_unlock_bh(&__toa_list_tab[hash_key].lock);
// }

// static void
// lock_all_toa_sk(void)
// {
//     int i;
//     for_each_possible_cpu(i) {
//         spinlock_t *lock;

//         lock = per_cpu_ptr(toa_sk_lock.lock, i);
//         spin_lock_bh(lock);
//     }
// }

// static void
// unlock_all_toa_sk(void)
// {
//     int i;
//     for_each_possible_cpu(i) {
//         spinlock_t *lock;

//         lock = per_cpu_ptr(toa_sk_lock.lock, i);
//         spin_unlock_bh(lock);
//     }
// }

// static void
// lock_cpu_toa_sk(void)
// {
//     spinlock_t *lock = this_cpu_ptr(toa_sk_lock.lock);
//     spin_lock_bh(lock);
// }

// static void
// unlock_cpu_toa_sk(void)
// {
//     spinlock_t *lock = this_cpu_ptr(toa_sk_lock.lock);
//     spin_unlock_bh(lock);
// }

// static int
// init_toa_entry(void)
// {
//     int i;

//     for_each_possible_cpu(i) {
//         spinlock_t *lock;

//         lock = per_cpu_ptr(toa_sk_lock.lock, i);
//         spin_lock_init(lock);
//     }

//     for (i = 0; i < TOA_TAB_SIZE; ++i) {
//         INIT_LIST_HEAD(&__toa_list_tab[i].toa_head);
//         spin_lock_init(&__toa_list_tab[i].lock);
//     }

//     toa_sk_lock.lock = alloc_percpu(spinlock_t);
//     if (toa_sk_lock.lock == NULL) {
//         TOA_INFO("fail to alloc per cpu toa entry destruct lock\n");
//         return -ENOMEM;
//     }

//     return 0;
// }

// static void 
// tcp_sk_destruct_toa(struct sock *sk) {

//         lock_cpu_toa_sk();

//         if (sk->sk_user_data) {
//                 struct toa_entry* ptr_entry = sk->sk_user_data;
//                 toa_entry_unhash(ptr_entry);
//                 sk->sk_destruct = inet_sock_destruct;
//                 sk->sk_user_data = NULL;
//                 kfree(ptr_entry);
//                 TOA_INC_STATS(ext_stats, TOA_ENTRY_ADDR_FREE_CNT);
//         }

//         inet_sock_destruct(sk);

//         unlock_cpu_toa_sk();
// }

// static int
// exit_toa_entry(void)
// {
//     int i;
//     struct list_head *head;
//     struct toa_entry *ptr_entry;
//     struct sock *sk;

//     lock_all_toa_sk();

//     for (i = 0; i < TOA_TAB_SIZE; ++i) {

//         spin_lock_bh(&__toa_list_tab[i].lock);

//         head = &__toa_list_tab[i].toa_head;
//         while (!list_empty(head)) {
//             ptr_entry = list_first_entry(head, struct toa_entry, list);
//             sk = ptr_entry->sk;

//             if (sk && sk->sk_user_data &&
//                 (sk->sk_destruct == tcp_sk_destruct_toa)) {

//                 sk->sk_destruct = inet_sock_destruct;
//                 sk->sk_user_data = NULL;

//                 TOA_DBG("free toa_entry in __toa_list_tab succ. "
//                         "ptr_entry : %p, src_ip : "TOA_NIPQUAD_FMT", src_port : %u, "
// 						"vip: "TOA_NIPQUAD_FMT", dst_port: %u\n",
//                         ptr_entry,
//                         NIPQUAD(ptr_entry->toa_data.legacy_data.ip), ntohs(ptr_entry->toa_data.legacy_data.port),
// 						NIPQUAD(ptr_entry->toa_data.dst_ip), ntohs(ptr_entry->toa_data.dst_port));
//             } else {
//                 TOA_DBG("update sk of toa_entry fail. "
//                         "ptr_entry : %p\n",
//                         ptr_entry);
//             }

//             TOA_INC_STATS(ext_stats, TOA_ENTRY_ADDR_FREE_CNT);

//             list_del(&ptr_entry->list);
//             kfree(ptr_entry);
//         }

//         spin_unlock_bh(&__toa_list_tab[i].lock);
//     }

//     unlock_all_toa_sk();

//     synchronize_net();

//     free_percpu(toa_sk_lock.lock);
//     return 0;
// }
























// /*
//  * Funcs for toa hooks
//  */

// // toa get name --------------------------------------------------

// /* Parse TCP options in skb, try to get client ip, port
//  * @param skb [in] received skb, it should be a ack/get-ack packet.
//  * @return NULL if we don't get client ip/port;
//  *         value of toa_data in ret_ptr if we get client ip/port.
//  */
// static void *get_toa_data(struct sk_buff *skb, enum sk_user_data_type *type)
// {
// 	struct tcphdr *th;
// 	int length;
// 	unsigned char *ptr;

// 	unsigned char buff[(15 * 4) - sizeof(struct tcphdr)];

// 	TOA_DBG("get_toa_data called\n");

// 	if (NULL != skb) {
// 		th = tcp_hdr(skb);
// 		length = (th->doff * 4) - sizeof(struct tcphdr);
// 		ptr = skb_header_pointer(skb, sizeof(struct tcphdr),
// 					length, buff);
// 		if (!ptr)
// 			return NULL;

// 		while (length > 0) {
// 			int opcode = *ptr++;
// 			int opsize;
// 			switch (opcode) {
// 			case TCPOPT_EOL:
// 				return NULL;
// 			case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
// 				length--;
// 				continue;
// 			default:
// 				opsize = *ptr++;
// 				if (opsize < 2)	/* "silly options" */
// 					return NULL;
// 				if (opsize > length)
// 					/* don't parse partial options */
// 					return NULL;
// 				if (TCPOPT_TOA == opcode &&
// 				    (TCPOLEN_TOA_V1 == opsize || TCPOLEN_TOA_V2 == opsize)) {
// 					struct toa_extra_data *ptr_toa_data;
// 					struct toa_entry *ptr_entry = kzalloc(sizeof(struct toa_entry), GFP_ATOMIC);
// 					if (!ptr_entry) {
// 						return NULL;
// 					}
// 					TOA_INC_STATS(ext_stats, TOA_ENTRY_ADDR_ALLOC_CNT);

// 					ptr_toa_data = &ptr_entry->toa_data;
// 					if (TCPOLEN_TOA_V1 == opsize) {
// 						memcpy(&ptr_toa_data->legacy_data, ptr - 2,
// 						       sizeof(ptr_toa_data->legacy_data));
// 						TOA_DBG("find toa data: ip = "
// 							"%u.%u.%u.%u, port = %u\n",
// 							NIPQUAD(ptr_toa_data->legacy_data.ip),
// 							ntohs(ptr_toa_data->legacy_data.port));
// 						*type = TOA_SK_USER_DATA_IP4;
// 					} else {
// 						memcpy(ptr_toa_data, ptr - 2, sizeof(struct toa_extra_data));

// 						TOA_DBG("find toa data : src_ip = "
// 							TOA_NIPQUAD_FMT", src_port = %u, vip = "
// 							TOA_NIPQUAD_FMT", dst_port = %u,"
// 							" coded toa entry data: %p\n",
// 							NIPQUAD(ptr_toa_data->legacy_data.ip),
// 							ntohs(ptr_toa_data->legacy_data.port),
// 							NIPQUAD(ptr_toa_data->dst_ip),
// 							ntohs(ptr_toa_data->dst_port),
// 							ptr_toa_data);
// 						*type = TOA_SK_USER_DATA_IP4_EXTRA;
// 					}

// 					return ptr_entry;					
// 				}

// 				ptr += opsize - 2;
// 				length -= opsize;
// 			}
// 		}
// 	}
// 	return NULL;
// }

// /* get client ip from socket
//  * @param sock [in] the socket to getpeername() or getsockname()
//  * @param uaddr [out] the place to put client ip, port
//  * @param uaddr_len [out] lenth of @uaddr
//  * @peer [in] if(peer), try to get remote address; if(!peer),
//  *  try to get local address
//  * @return return what the original inet_getname() returns.
//  */
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
// static int
// inet_getname_toa(struct socket *sock, struct sockaddr *uaddr,
// 		int peer)
// #else
// static int
// inet_getname_toa(struct socket *sock, struct sockaddr *uaddr,
// 		int *uaddr_len, int peer)
// #endif
// {
// 	int retval = 0;
// 	struct sock *sk = sock->sk;
// 	struct sockaddr_in *sin = (struct sockaddr_in *) uaddr;
// 	struct toa_extra_data extra_tdata;


// 	/* call orginal one */
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
// 	retval = inet_getname(sock, uaddr, peer);
// #else
// 	retval = inet_getname(sock, uaddr, uaddr_len, peer)
// #endif

// 	/* set our value if need */
// 	if (retval >= 0 && NULL != sk->sk_user_data) {
// 		if (sk_data_ready_addr == (unsigned long) sk->sk_data_ready) {
// 			memcpy(&extra_tdata, sk->sk_user_data, sizeof(extra_tdata));
// 			TOA_DBG("toa.opcode:%d, toa.opsize:%d", extra_tdata.legacy_data.opcode, extra_tdata.legacy_data.opsize);
// 			if (TCPOPT_TOA == extra_tdata.legacy_data.opcode &&
// 			    TCPOLEN_TOA_V1 == extra_tdata.legacy_data.opsize && peer) {
// 				TOA_INC_STATS(ext_stats, GETNAME_TOA_OK_CNT);
// 				TOA_DBG("inet_getname_toa peer: set new sockaddr, "
// 					"ip %u.%u.%u.%u -> %u.%u.%u.%u, port "
// 					"%u -> %u\n",
// 					NIPQUAD(sin->sin_addr.s_addr),
// 					NIPQUAD(extra_tdata.legacy_data.ip), ntohs(sin->sin_port),
// 					ntohs(extra_tdata.legacy_data.port));
// 				sin->sin_port = extra_tdata.legacy_data.port;
// 				sin->sin_addr.s_addr = extra_tdata.legacy_data.ip;
// 			} else if (TCPOPT_TOA == extra_tdata.legacy_data.opcode &&
// 				TCPOLEN_TOA_V2 == extra_tdata.legacy_data.opsize) {
// 				TOA_INC_STATS(ext_stats, GETNAME_TOA_OK_CNT);
// 				if (peer) {
// 					TOA_DBG("inet_getname_toa: set new sockaddr peer, "
// 						"ip %u.%u.%u.%u -> %u.%u.%u.%u, port "
// 						"%u -> %u\n",
// 						NIPQUAD(sin->sin_addr.s_addr),
// 						NIPQUAD(extra_tdata.legacy_data.ip), ntohs(sin->sin_port),
// 						ntohs(extra_tdata.legacy_data.port));
// 					sin->sin_port = extra_tdata.legacy_data.port;
// 					sin->sin_addr.s_addr = extra_tdata.legacy_data.ip;
// 				} else {
// 					TOA_DBG("inet_getname_toa: set new sockaddr local, "
// 						"ip %u.%u.%u.%u -> %u.%u.%u.%u, port "
// 						"%u -> %u\n",
// 						NIPQUAD(sin->sin_addr.s_addr),
// 						NIPQUAD(extra_tdata.dst_ip), ntohs(sin->sin_port),
// 						ntohs(extra_tdata.dst_port));
// 					sin->sin_port = extra_tdata.dst_port;
// 					sin->sin_addr.s_addr = extra_tdata.dst_ip;
// 				}
// 			} else { /* sk_user_data doesn't belong to us */
// 				TOA_INC_STATS(ext_stats,
// 						GETNAME_TOA_MISMATCH_CNT);
// 				TOA_DBG("inet_getname_toa: invalid toa data, "
// 					"ip %u.%u.%u.%u port %u opcode %u "
// 					"opsize %u\n",
// 					NIPQUAD(extra_tdata.legacy_data.ip), ntohs(extra_tdata.legacy_data.port),
// 					extra_tdata.legacy_data.opcode, extra_tdata.legacy_data.opsize);
// 			}
// 		} else {
// 			TOA_INC_STATS(ext_stats, GETNAME_TOA_BYPASS_CNT);
// 		}
// 	} else { /* no need to get client ip */
// 		TOA_INC_STATS(ext_stats, GETNAME_TOA_EMPTY_CNT);
// 	}

// 	return retval;
// }

// #ifdef CONFIG_IP_VS_TOA_IPV6
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
// static int
// inet6_getname_toa(struct socket *sock, struct sockaddr *uaddr,
// 		  int peer)
// #else
// static int
// inet6_getname_toa(struct socket *sock, struct sockaddr *uaddr,
// 		  int *uaddr_len, int peer)
// #endif
// {
// 	int retval = 0;
// 	struct sock *sk = sock->sk;
// 	struct sockaddr_in6 *sin = (struct sockaddr_in6 *) uaddr;
// 	struct toa_data tdata;

// 	TOA_DBG("inet6_getname_toa called, sk->sk_user_data is %p\n",
// 		sk->sk_user_data);

// 	/* call orginal one */
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
// 	retval = inet6_getname(sock, uaddr, peer);
// #else
// 	retval = inet6_getname(sock, uaddr, uaddr_len, peer);
// #endif

// 	/* set our value if need */
// 	if (retval >= 0 && NULL != sk->sk_user_data && peer) {
// 		if (sk_data_ready_addr == (unsigned long) sk->sk_data_ready) {
// 			memcpy(&tdata, &sk->sk_user_data, sizeof(tdata));
// 			if (TCPOPT_TOA == tdata.opcode &&
// 			    TCPOLEN_TOA == tdata.opsize) {
// 				TOA_INC_STATS(ext_stats, GETNAME_TOA_OK_CNT);
// 				sin->sin6_port = tdata.port;
// 				ipv6_addr_set(&sin->sin6_addr, 0, 0,
// 					      htonl(0x0000FFFF), tdata.ip);
// 			} else { /* sk_user_data doesn't belong to us */
// 				TOA_INC_STATS(ext_stats,
// 					      GETNAME_TOA_MISMATCH_CNT);
// 			}
// 		} else {
// 			TOA_INC_STATS(ext_stats, GETNAME_TOA_BYPASS_CNT);
// 		}
// 	} else { /* no need to get client ip */
// 		TOA_INC_STATS(ext_stats, GETNAME_TOA_EMPTY_CNT);
// 	}

// 	return retval;
// }
// #endif
















// // toa hook -----------------------------------------------------

// /* The three way handshake has completed - we got a valid synack -
//  * now create the new socket.
//  * We need to save toa data into the new socket.
//  * @param sk [out]  the socket
//  * @param skb [in] the ack/ack-get packet
//  * @param req [in] the open request for this connection
//  * @param dst [out] route cache entry
//  * @return NULL if fail new socket if succeed.
//  */
//  #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
//  static struct sock *
//  tcp_v4_syn_recv_sock_toa(const struct sock *sk, struct sk_buff *skb,
// 			struct request_sock *req,
// 			struct dst_entry *dst,
// 			struct request_sock *req_unhash,
// 			bool *own_req)
// #else
// static struct sock *
// tcp_v4_syn_recv_sock_toa(struct sock *sk, struct sk_buff *skb,
// 			struct request_sock *req, struct dst_entry *dst)
// #endif
// {
// 	struct sock *newsock = NULL;
//     enum sk_user_data_type type;

// 	TOA_DBG("tcp_v4_syn_recv_sock_toa called\n");

// 	/* call orginal one */
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
// 	newsock = tcp_v4_syn_recv_sock(sk, skb, req, dst, req_unhash, own_req);
// #else
// 	newsock = tcp_v4_syn_recv_sock(sk, skb, req, dst);
// #endif

//     // struct sockaddr addr;
// 	// sizeof(struct sockaddr);
// 	// struct sockaddr_in addr;
// 	// sizeof(struct sockaddr_in6);
// 	// sizeof(struct in6_addr);
// 	// sizeof(struct sockaddr_storage);

// 	/* set our value if need */
// 	if (NULL != newsock && NULL == newsock->sk_user_data) {

// 		newsock->sk_user_data = get_toa_data(skb, &type);
		
// 		if (NULL != newsock->sk_user_data) {
// 			if (type == TOA_SK_USER_DATA_IP4 || type == TOA_SK_USER_DATA_IP4_EXTRA) {
// 			struct toa_entry *ptr_entry = newsock->sk_user_data;
// 			ptr_entry->sk = newsock;
// 			toa_entry_hash(ptr_entry);

// 			newsock->sk_destruct = tcp_sk_destruct_toa;
// 			TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_TOA_CNT);
// 			}
// 		} else
// 			TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_NO_TOA_CNT);

// 		TOA_DBG("tcp_v4_syn_recv_sock_toa: set "
// 			"sk->sk_user_data to %p\n",
// 			newsock->sk_user_data);
// 	}
// 	return newsock;
// }

// #ifdef CONFIG_IP_VS_TOA_IPV6
// static struct sock *
// tcp_v6_syn_recv_sock_toa(struct sock *sk, struct sk_buff *skb,
// 			 struct request_sock *req, struct dst_entry *dst)
// {
// 	struct sock *newsock = NULL;
// 	enum toa_sk_user_data_type type;

// 	TOA_DBG("tcp_v4_syn_recv_sock_toa called\n");

// 	/* call orginal one */
// 	newsock = tcp_v6_syn_recv_sock(sk, skb, req, dst);

// 	/* set our value if need */
// 	if (NULL != newsock && NULL == newsock->sk_user_data) {
// 		newsock->sk_user_data = get_toa_data(skb, &type);
// 		if (NULL != newsock->sk_user_data)
// 			TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_TOA_CNT);
// 		else
// 			TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_NO_TOA_CNT);
// 	}
// 	return newsock;
// }
// #endif

// /*
//  * HOOK FUNCS
//  */

// /* replace the functions with our functions */
// static inline int
// hook_toa_functions(void)
// {
// 	unsigned int level;
// 	pte_t *pte;

// 	/* hook inet_getname for ipv4 */
// 	struct proto_ops *inet_stream_ops_p =
// 			(struct proto_ops *)&inet_stream_ops;
// 	/* hook tcp_v4_syn_recv_sock for ipv4 */
// 	struct inet_connection_sock_af_ops *ipv4_specific_p =
// 			(struct inet_connection_sock_af_ops *)&ipv4_specific;
// #ifdef CONFIG_IP_VS_TOA_IPV6
// 	/* hook inet6_getname for ipv6 */
// 	struct proto_ops *inet6_stream_ops_p =
// 			(struct proto_ops *)&inet6_stream_ops;
// 	/* hook tcp_v6_syn_recv_sock for ipv6 */
// 	struct inet_connection_sock_af_ops *ipv6_specific_p =
// 			(struct inet_connection_sock_af_ops *)&ipv6_specific;
// #endif

// 	pte = lookup_address((unsigned long )inet_stream_ops_p, &level);
// 	if (pte == NULL)
// 		return 1;
// 	if (pte->pte & ~_PAGE_RW) {
// 		pte->pte |= _PAGE_RW;
// 	}

// 	inet_stream_ops_p->getname = inet_getname_toa;
// 	TOA_INFO("CPU [%u] hooked inet_getname <%p> --> <%p>\n",
// 		smp_processor_id(), inet_getname, inet_stream_ops_p->getname);

// #ifdef CONFIG_IP_VS_TOA_IPV6
// 	inet6_stream_ops_p->getname = inet6_getname_toa;
// 	TOA_INFO("CPU [%u] hooked inet6_getname <%p> --> <%p>\n",
// 		smp_processor_id(), inet6_getname, inet6_stream_ops_p->getname);
// #endif

// 	ipv4_specific_p->syn_recv_sock = tcp_v4_syn_recv_sock_toa;
// 	TOA_INFO("CPU [%u] hooked tcp_v4_syn_recv_sock <%p> --> <%p>\n",
// 		smp_processor_id(), tcp_v4_syn_recv_sock,
// 		ipv4_specific_p->syn_recv_sock);

// #ifdef CONFIG_IP_VS_TOA_IPV6
// 	ipv6_specific_p->syn_recv_sock = tcp_v6_syn_recv_sock_toa;
// 	TOA_INFO("CPU [%u] hooked tcp_v6_syn_recv_sock <%p> --> <%p>\n",
// 		smp_processor_id(), tcp_v6_syn_recv_sock,
// 		ipv6_specific_p->syn_recv_sock);
// #endif

// 	pte = lookup_address((unsigned long )inet_stream_ops_p, &level);
// 	if (pte == NULL)
// 		return 1;
// 	pte->pte |= pte->pte &~_PAGE_RW;

// 	return 0;
// }

// /* replace the functions to original ones */
// static int
// unhook_toa_functions(void)
// {
// 	unsigned int level;
// 	pte_t *pte;

// 	/* unhook inet_getname for ipv4 */
// 	struct proto_ops *inet_stream_ops_p =
// 			(struct proto_ops *)&inet_stream_ops;
// 	/* unhook tcp_v4_syn_recv_sock for ipv4 */
// 	struct inet_connection_sock_af_ops *ipv4_specific_p =
// 			(struct inet_connection_sock_af_ops *)&ipv4_specific;

// #ifdef CONFIG_IP_VS_TOA_IPV6
// 	/* unhook inet6_getname for ipv6 */
// 	struct proto_ops *inet6_stream_ops_p =
// 			(struct proto_ops *)&inet6_stream_ops;
// 	/* unhook tcp_v6_syn_recv_sock for ipv6 */
// 	struct inet_connection_sock_af_ops *ipv6_specific_p =
// 			(struct inet_connection_sock_af_ops *)&ipv6_specific;
// #endif

// 	pte = lookup_address((unsigned long )inet_stream_ops_p, &level);
// 	if (pte == NULL)
// 		return 1;
// 	if (pte->pte & ~_PAGE_RW) {
// 		pte->pte |= _PAGE_RW;
// 	}

// 	inet_stream_ops_p->getname = inet_getname;
// 	TOA_INFO("CPU [%u] unhooked inet_getname\n",
// 		smp_processor_id());

// #ifdef CONFIG_IP_VS_TOA_IPV6
// 	inet6_stream_ops_p->getname = inet6_getname;
// 	TOA_INFO("CPU [%u] unhooked inet6_getname\n",
// 		smp_processor_id());
// #endif

// 	ipv4_specific_p->syn_recv_sock = tcp_v4_syn_recv_sock;
// 	TOA_INFO("CPU [%u] unhooked tcp_v4_syn_recv_sock\n",
// 		smp_processor_id());

// #ifdef CONFIG_IP_VS_TOA_IPV6
// 	ipv6_specific_p->syn_recv_sock = tcp_v6_syn_recv_sock;
// 	TOA_INFO("CPU [%u] unhooked tcp_v6_syn_recv_sock\n",
// 		smp_processor_id());
// #endif

// 	pte = lookup_address((unsigned long )inet_stream_ops_p, &level);
// 	if (pte == NULL)
// 		return 1;
// 	pte->pte |= pte->pte &~_PAGE_RW;

// 	return 0;
// }


// // toa statistic -----------------------------------------------------------------------------

// /*
//  * Statistics of toa in proc /proc/net/toa_stats
//  */
// static int toa_stats_show(struct seq_file *seq, void *v)
// {
// 	int i, j, cpu_nr;

// 	/* print CPU first */
// 	seq_printf(seq, "                                  ");
// 	cpu_nr = num_possible_cpus();
// 	for (i = 0; i < cpu_nr; i++)
// 		if (cpu_online(i))
// 			seq_printf(seq, "CPU%d       ", i);
// 	seq_putc(seq, '\n');

// 	i = 0;
// 	while (NULL != toa_stats[i].name) {
// 		seq_printf(seq, "%-25s:", toa_stats[i].name);
// 		for (j = 0; j < cpu_nr; j++) {
// 			if (cpu_online(j)) {
// 				seq_printf(seq, "%10lu ", *(
// 					((unsigned long *) per_cpu_ptr(
// 					ext_stats, j)) + toa_stats[i].entry
// 					));
// 			}
// 		}
// 		seq_putc(seq, '\n');
// 		i++;
// 	}
// 	return 0;
// }

// static int toa_stats_seq_open(struct inode *inode, struct file *file)
// {
// 	return single_open(file, toa_stats_show, NULL);
// }

// static const struct file_operations toa_stats_fops = {
// 	.owner = THIS_MODULE,
// 	.open = toa_stats_seq_open,
// 	.read = seq_read,
// 	.llseek = seq_lseek,
// 	.release = single_release,
// };


// // toa module init -------------------------------------------------

// /*
//  * TOA module init and destory
//  */

// /* module init */
// static int __init
// toa_init(void)
// {
// 	/* alloc statistics array for toa */
// 	ext_stats = alloc_percpu(struct toa_stat_mib);
// 	if (NULL == ext_stats)
// 		return 1;
// 	proc_create("toa_stats", 0, init_net.proc_net, &toa_stats_fops);

// 	/* get the address of function sock_def_readable
// 	 * so later we can know whether the sock is for rpc, tux or others
// 	 */
// 	sk_data_ready_addr = kallsyms_lookup_name("sock_def_readable");
// 	TOA_INFO("CPU [%u] sk_data_ready_addr = "
// 		"kallsyms_lookup_name(sock_def_readable) = %lu\n",
// 		 smp_processor_id(), sk_data_ready_addr);
// 	if (0 == sk_data_ready_addr) {
// 		TOA_INFO("cannot find sock_def_readable.\n");
// 		goto err;
// 	}

//     if (0 != init_toa_entry()) {
//         TOA_INFO("init toa entry fail.\n");
//         goto err;
//     }

// 	/* hook funcs for parse and get toa */
// 	if (0 != hook_toa_functions()) {
// 		TOA_INFO("cannot hook toa functions.\n");
// 		goto err;
// 	}

// 	TOA_INFO("toa loaded\n");
// 	return 0;

// err:
// 	remove_proc_entry("toa_stats",init_net.proc_net);
// 	if (NULL != ext_stats) {
// 		free_percpu(ext_stats);
// 		ext_stats = NULL;
// 	}

// 	return 1;
// }

// /* module cleanup*/
// static void __exit
// toa_exit(void)
// {
// 	unhook_toa_functions();
// 	synchronize_net();

//     if (0 != exit_toa_entry()) {
//         TOA_INFO("exit toa entry fail.\n");
//     }    

// 	remove_proc_entry("toa_stats",init_net.proc_net);
// 	if (NULL != ext_stats) {
// 		free_percpu(ext_stats);
// 		ext_stats = NULL;
// 	}
// 	TOA_INFO("toa unloaded\n");

// 	pr_debug("-----------------------------------------\n");
// }

static int __init toa_init(void)
{
	pr_debug("%s: 1", __func__);

	pr_info("toa inserted\n");
	return 0;
}

static void __exit toa_exit(void)
{
	pr_info("toa rmeoved\n");
	pr_debug("---------------------------------------------");
}

module_init(toa_init);
module_exit(toa_exit);
MODULE_LICENSE("GPL");
