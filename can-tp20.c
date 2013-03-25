#include <linux/can.h>
#include <linux/can/core.h>
#include <net/sock.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/kernel.h>

#define TP20_INFO_IDSPEC 0x00
#define TP20_INFO_IDUNSPEC 0x02
#define TP20_APPTYPE_DIAGNOSTICS 0x01
#define TP20_INITIAL_TXID 0x200
#define TP20_INITIAL_RXID 0x300

#define TP20_DEBUG(n, args...) \
  do { printk(KERN_DEBUG args); } while (0)

MODULE_DESCRIPTION("PF_CAN TP2.0 SAE 2819 protocol");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Dan Skorupski <dan.skorupski@gmail.com>");

enum tp20_opcode {
  TP20_OPCODE_CHANNEL_SETUP = 0xC0,
  TP20_OPCODE_CHANNEL_SETUP_ACK = 0xD0
};

enum tp20_state {
  TP20_CHANNEL_SETUP,
  TP20_CHANNEL_SETUP_ACK,
  TP20_TIMING_SETUP,
  TP20_TIMING_SETUP_ACK,
  TP20_DONE, /* must be below all connect related states */
	TP20_CLOSE, /* see sk->sk_err for details */ 
  TP20_ESTABLISHED 
};

struct tp20_sock {
  struct sock sk;
  int ifindex;
  int destination;
  int app_type;
  canid_t tx_id;
  canid_t rx_id;
  struct notifier_block notifier;
};

struct tp20_channel_setup {
  __u8 destination;
  __u8 opcode;
  __u8 tx_id_low;
  __u8 tx_id_high_info;
  __u8 rx_id_low;
  __u8 rx_id_high_info;
  __u8 app_type;
} __attribute__((packed));

struct tp20_timing_setup {
  __u8 tpc1;
  __u8 tpc2;
  __u8 t1;
  __u8 t2;
  __u8 t3;
  __u8 t4;
} __attribute__((packed));

static inline struct tp20_sock* tp20_sk(struct sock* sk)
{
  return (struct tp20_sock*)sk;
}

static inline int tx_id(struct tp20_channel_setup* cs)
{
  return ((cs->tx_id_high_info & 7) << 8) | cs->tx_id_low;
}

static inline int rx_id(struct tp20_channel_setup* cs)
{
  return ((cs->rx_id_high_info & 7) << 8) | cs->rx_id_low;
}

static inline int tx_info(struct tp20_channel_setup* cs)
{
  return cs->tx_id_high_info >> 3;
}

static inline int rx_info(struct tp20_channel_setup* cs)
{
  return cs->rx_id_high_info >> 3;
}

static int send_channel_setup(struct tp20_sock* so, struct net_device* dev)
{
  struct sk_buff* skb = NULL;
  struct can_frame* cf;
  struct tp20_channel_setup* cs;

  skb = alloc_skb(sizeof(struct can_frame), gfp_any());
  if(!skb)
    return -ENOMEM; /* out of memory */

  skb->dev = dev;
  skb->sk = &so->sk;

  /* build the telegram */
  cf = (struct can_frame*)skb->data;
  cs = (struct tp20_channel_setup*)cf->data;

  cf->can_dlc = sizeof(struct tp20_channel_setup);
  cf->can_id = so->tx_id;
  cs->destination = so->destination;
  cs->opcode = TP20_OPCODE_CHANNEL_SETUP;
  cs->tx_id_low = 0;
	cs->tx_id_high_info = (TP20_INFO_IDUNSPEC << 3);
  cs->rx_id_low = so->rx_id;
  cs->rx_id_high_info = (TP20_INFO_IDSPEC << 3) | (so->rx_id >> 8);
  cs->app_type = so->app_type;

  /* send the telegram */
  return can_send(skb, 1);
}

static int send_timing_setup(struct tp20_sock* so, struct net_device* dev)
{
  /* TODO */
  return 0;
}

static void tp20_rcv_channel_setup_ack(struct sock* sk, struct sk_buff* skb)
{
  /* sock locked in tp20_connect */
  struct tp20_sock* so = tp20_sk(sk);
  struct can_frame* cf = (struct can_frame*)skb->data;
  struct tp20_channel_setup* cs = (struct tp20_channel_setup*)cf->data;
  struct net_device* dev = NULL;
  int err;

  if(cf->can_id != so->rx_id) { /* we have a filter so we shouldn't be getting anything we don't want */
    TP20_DEBUG(0, "bad can_id in rcv_channel_setup_ack");
    goto out_err;
  }

  if(cs->destination != (so->tx_id & 0xFF)) {
    TP20_DEBUG(0, "bad destination in rcv_channel_setup_ack");
    goto out_err;
  }

  if(cs->opcode != TP20_CHANNEL_SETUP_ACK) {
    TP20_DEBUG(0, "bad opcode in rcv_channel_setup_ack");
    goto out_err;
  }

  if(cf->can_dlc != sizeof(struct tp20_channel_setup)) {
    TP20_DEBUG(0, "bad dlc in rcv_channel_setup_ack");
    goto out_err;
  }

  if(tx_info(cs) != TP20_INFO_IDSPEC) {
    TP20_DEBUG(0, "bad tx_info in rcv_channel_setup_ack");
    goto out_err;
  }

  if(rx_info(cs) != TP20_INFO_IDSPEC) {
    TP20_DEBUG(0, "bad rx_info in rcv_channel_setup_ack");
    goto out_err;
  }

  so->rx_id = tx_id(cs);

  if(rx_id(cs) != so->tx_id) {
    TP20_DEBUG(0, "bad rx_id in rcv_channel_setup_ack");
    goto out_err;
  }

  if(cs->app_type != so->app_type) {
    TP20_DEBUG(0, "bad app_type in rcv_channel_setup_ack");
    goto out_err;
  }

  dev = dev_get_by_index(&init_net, so->ifindex);
  if(!dev)
    goto out_err;

  err = send_timing_setup(so, dev);
  if(err)
    goto out_err;

  sk->sk_state = TP20_TIMING_SETUP_ACK;
  goto out;

out_err:
  sk->sk_state = TP20_CLOSE;
  sk->sk_err = ECONNRESET;
  wake_up_interruptible(sk_sleep(sk));

out:
  if(dev != NULL)
    dev_put(dev);
}

static void tp20_rcv_timing_setup_ack(struct sock* sk, struct sk_buff* skb)
{
  /* sock locked in tp20_connected */
  /* TODO */
}

static void tp20_rcv_established(struct sock* sk, struct sk_buff* skb)
{
  /* TODO */
}

static void tp20_rcv(struct sk_buff* skb, void* data)
{
  struct sock* sk = (struct sock*)data;

  switch(sk->sk_state) {
  case TP20_CHANNEL_SETUP_ACK:
    tp20_rcv_channel_setup_ack(sk, skb);
    break;
  case TP20_TIMING_SETUP_ACK:
    tp20_rcv_timing_setup_ack(sk, skb);
    break;
  case TP20_ESTABLISHED:
    tp20_rcv_established(sk, skb);
    break;
  }
}

static int tp20_connect(struct socket* sock, struct sockaddr* uaddr, int len, int flags)
{
  struct sock* sk = sock->sk;
  struct tp20_sock* so = tp20_sk(sk);
  struct sockaddr_can* addr = (struct sockaddr_can*)uaddr;
  struct net_device* dev = NULL;
  int err;

  lock_sock(sk);

  if((addr->can_addr.tp.rx_id & 0x700) != 0x200) {
    err = -EAFNOSUPPORT; /* must be given a rx_id of the form 0x2XX */
    goto out;
  }

  if(sk->sk_state == TP20_ESTABLISHED && sock->state == SS_CONNECTING) {
    sock->state = SS_CONNECTED;
    err = 0; /* connect completed during signal */
    goto out;
  }
 
  if(sk->sk_state > TP20_DONE && sock->state == SS_CONNECTING) {
    sock->state = SS_UNCONNECTED;
    err = -sk->sk_err; /* connect failed during signal */
    goto out;
  }

  if(sk->sk_state == TP20_ESTABLISHED) {
    err = -EISCONN; /* already connected */
    goto out;
  }

  dev = dev_get_by_index(&init_net, addr->can_ifindex);
  if(!dev) {
    err = -ENODEV; /* device does not exist */
    goto out;
  }

  /* setup socket state */
  so->ifindex = addr->can_ifindex;
  so->destination = addr->can_addr.tp.rx_id;
  so->tx_id = TP20_INITIAL_TXID;
  so->rx_id = TP20_INITIAL_RXID;
  sk->sk_state = TP20_CHANNEL_SETUP_ACK;  
  sock->state = SS_CONNECTING;

  /* send channel setup telegram */
  err = send_channel_setup(so, dev);
  if(err)
    goto out;

  /* start listening for replies */
  err = can_rx_register(dev, so->rx_id, CAN_SFF_MASK, tp20_rcv, sk, "tp20");
  if(err)
    goto out;

  /* wait to connect */
  if(wait_event_interruptible(*(sk_sleep(sk)), sk->sk_state > TP20_DONE)) {
    err = -ERESTARTSYS; /* interrupted */
    goto out;
  }

  /* did we do good? */
  err = sk->sk_err;
  if(err)
    goto out;

  sock->state = SS_CONNECTED;

out:
  if(dev != NULL)
    dev_put(dev);

  release_sock(sk);

  return err;
}

static int tp20_notifier(struct notifier_block* nb, unsigned long msg, void* data)
{
  struct net_device* dev = (struct net_device*)data;
  struct tp20_sock* so = container_of(nb, struct tp20_sock, notifier);
  struct sock* sk = &so->sk;

  if(dev_net(dev) != &init_net)
    return NOTIFY_DONE;

  if(dev->type != ARPHRD_CAN)
    return NOTIFY_DONE;

  if(so->ifindex != dev->ifindex)
    return NOTIFY_DONE;

  switch(msg) {
  case NETDEV_UNREGISTER:
    lock_sock(sk);

    if(so->ifindex >= 0)
      can_rx_unregister(dev, so->rx_id, CAN_SFF_MASK, tp20_rcv, sk);
    so->ifindex = -1;

    sk->sk_err = ENODEV;
    if(!sock_flag(sk, SOCK_DEAD))
      sk->sk_error_report(sk);

    release_sock(sk);
    break;

  case NETDEV_DOWN:
    lock_sock(sk);

    sk->sk_err = ENETDOWN;
    if(!sock_flag(sk, SOCK_DEAD))
      sk->sk_error_report(sk);

    release_sock(sk);
    break;
  }

  return NOTIFY_DONE;
}

static int tp20_init(struct sock* sk)
{
  struct tp20_sock* so = tp20_sk(sk);
  int err;

  sk->sk_state = TP20_CLOSE;
  so->ifindex = -1;
  so->app_type = TP20_APPTYPE_DIAGNOSTICS;

  so->notifier.notifier_call = tp20_notifier;
  err = register_netdevice_notifier(&so->notifier);
  if(err)
    return err;

  return 0;
}

static int tp20_release(struct socket* sock)
{
  struct tp20_sock* so = tp20_sk(sock->sk);

  unregister_netdevice_notifier(&so->notifier);

  if(so->ifindex >= 0) {
    struct net_device* dev = dev_get_by_index(&init_net, so->ifindex);
    can_rx_unregister(dev, so->rx_id, CAN_SFF_MASK, tp20_rcv, &so->sk);
  }

	return 0;
}

static const struct proto_ops tp20_ops = {
  .family        = PF_CAN,
  .release       = tp20_release,
  .bind          = sock_no_bind,
  .connect       = tp20_connect,
  .socketpair    = sock_no_socketpair,
  .accept        = sock_no_accept,
  .getname       = sock_no_getname,
  .poll          = datagram_poll,
  .ioctl         = can_ioctl,	/* use can_ioctl() from af_can.c */
  .listen        = sock_no_listen,
  .shutdown      = sock_no_shutdown,
  .setsockopt    = sock_no_setsockopt,
  .getsockopt    = sock_no_getsockopt,
  .sendmsg       = sock_no_sendmsg,
  .recvmsg       = sock_no_recvmsg,
  .mmap          = sock_no_mmap,
  .sendpage      = sock_no_sendpage,
};

static struct proto tp20_proto __read_mostly = {
  .name = "CAN_TP20",
  .owner = THIS_MODULE,
  .obj_size = sizeof(struct tp20_sock),
  .init = tp20_init
};

static const struct can_proto tp20_can_proto = {
  .type = SOCK_SEQPACKET,
  .protocol = CAN_TP20,
  .ops = &tp20_ops,
  .prot = &tp20_proto
};

static __init int tp20_module_init(void)
{
  int err = can_proto_register(&tp20_can_proto);
  if(err < 0)
    printk(KERN_ERR "can: registration of tp20 protocol failed\n");
  return err;
}

static __exit void tp20_module_exit(void)
{
  can_proto_unregister(&tp20_can_proto);
}

module_init(tp20_module_init);
module_exit(tp20_module_exit);
