#include <linux/can.h>
#include <linux/can/core.h>
#include <net/sock.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/kernel.h>

#define TP20_INFO_IDSPEC 0x00
#define TP20_INFO_IDUNSPEC 0x02
#define TP20_APPTYPE_DIAGNOSTICS 0x01
#define TP20_APPTYPE_INFOTAINMENT 0x20
#define TP20_APPTYPE_APPROTOCOL 0x20
#define TP20_APPTYPE_WFS_WIV 0x21
#define TP20_TX_INITIAL_ID 0x200
#define TP20_RX_INITIAL_ID 0x300
#define TP20_TX_BLOCK_SIZE 15
#define TP20_MAX_BLOCK_SIZE 15
#define TP20_CR_TIMEOUT ktime_set(0, 500000000) /* T_RSP, 500 ms */
#define TP20_CR_MAX_TIMEOUTS 10 /* not given in spec */
#define TP20_CS_TIMEOUT ktime_set(0, 100000000) /* T_E, 100 ms */
#define TP20_CS_MAX_TIMEOUTS 10 /* MNTC */
#define TP20_CT_TIMEOUT ktime_set(1, 0) /* T_CTa, 1000 ms */
#define TP20_CT_MAX_TIMEOUTS 5 /* MNCT */

#define TP20_DEBUG(n, args...) \
  do { printk(KERN_DEBUG args); } while (0)

MODULE_DESCRIPTION("PF_CAN TP2.0 SAE 2819 protocol");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Dan Skorupski <dan.skorupski@gmail.com>");

enum tp20_op {
  TP20_OP_CR = 0xC0, /* CR = channel request */
  TP20_OP_CP = 0xD0, /* CP = channel positive reply */
  TP20_OP_CN = 0xD6, /* CN = channel negative reply, application type not supported */
  TP20_OP_CM = 0xD7, /* CM = channel negative reply, application type not available */
  TP20_OP_CO = 0xD8, /* CO = channel negative reply, temporarily out of resources */
  TP20_OP_CS = 0xA0, /* CS = channel setup */
  TP20_OP_CA = 0xA1, /* CA = connection acknowledge */
  TP20_OP_CT = 0xA3, /* CT = connection test */
  TP20_OP_BR = 0xA4, /* BR = break */
  TP20_OP_DC = 0xA8, /* DC = disconnect */
};

enum tp20_state {
  TP20_CR,
  TP20_CR_ACK,
  TP20_CS,
  TP20_CS_ACK,
  TP20_DONE, /* must be below all connect related states */
	TP20_CLOSE, /* see sk->sk_err for details */ 
  TP20_ESTABLISHED 
};

struct tp20_endpoint {
  canid_t id;
  canid_t block_size;
  int ack_timeout; /* 100ns units */
  int send_delay; /* 100ns units */
};

struct tp20_sock {
  struct sock sk;
  int ifindex;
  int destination;
  int app_type;
  int timeout_count; /* number of timeouts waiting for a reply */
  struct tp20_endpoint tx;
  struct tp20_endpoint rx;
  struct notifier_block notifier;
  struct hrtimer timer;
};

/*
 * utilities
 */
static inline struct tp20_sock* tp20_sk(struct sock* sk)
{
  return (struct tp20_sock*)sk;
}

static int send(struct tp20_sock* so, const struct can_frame* cf)
{
  struct net_device* dev = NULL;
  struct sk_buff* skb = NULL;
  int err = 0;

  dev = dev_get_by_index(&init_net, so->ifindex);
  if(!dev) {
    err = -ENODEV;
    goto out;
  }

  skb = alloc_skb(sizeof(struct can_frame), gfp_any());
  if(!skb) {
    err = -ENOMEM;
    goto out;
  }

  skb->dev = dev;
  skb->sk = &so->sk;

  memcpy(skb->data, cf, sizeof(struct can_frame));

  err = can_send(skb, 1);
  skb = NULL; /* can_send took ownership */

out:
  if(dev)
    dev_put(dev);

  if(skb)
    kfree_skb(skb);

  return err;
}

/*
 * connection test
 */
struct tp20_ct {
  __u8 tpc1;
} __attribute__((packed));

static int send_ct(struct tp20_sock* so)
{
  struct can_frame cf;
  struct tp20_ct* ct;

  cf.can_id = so->tx.id;
  cf.can_dlc = sizeof(struct tp20_ct);

  ct = (struct tp20_ct*)cf.data;
  ct->tpc1 = TP20_OP_CT;

  return send(so, &cf);
}

static enum hrtimer_restart ct_timeout(struct hrtimer* timer)
{
  struct tp20_sock* so = container_of(timer, struct tp20_sock, timer);

  /* TODO */
  send_ct(so);
  hrtimer_forward_now(timer, TP20_CT_TIMEOUT);
  return HRTIMER_RESTART;
}

/*
 * timing setup
 */
struct tp20_cs {
  __u8 tpc1;
  __u8 tpc2;
  __u8 t1;
  __u8 t2;
  __u8 t3;
  __u8 t4;
} __attribute__((packed));

static __u8 time_to_byte(int t) /* time in 100ns units */
{
  int time;
  int time_base;

  if(t < 0)
    return 0x00;
  if(t == INT_MAX)
    return 0xFF;
  if(t > 62000)
    return 0xFE; /* too large to encode */

  time = t;
  time_base = 0;

  while(time > 0x3F) {
    time /= 10;
    time_base++;
  }

  return (time_base << 6) | time;
}

static int byte_to_time(__u8 b)
{
  int time;
  int time_base;

  if(b == 0x00)
    return 0;
  if(b == 0xFF)
    return INT_MAX;

  time = b & 0x3F;
  time_base = b >> 6;

  while(time_base > 0) {
    time *= 10;
    time_base--;
  }

  return time;
}

static int send_cs(struct tp20_sock* so)
{
  struct can_frame cf;
  struct tp20_cs* cs;

  cf.can_id = so->tx.id;
  cf.can_dlc = sizeof(struct tp20_cs);

  cs = (struct tp20_cs*)cf.data;
  cs->tpc1 = TP20_OP_CS;
  cs->tpc2 = so->tx.block_size;
  cs->t1 = time_to_byte(so->tx.ack_timeout);
  cs->t2 = 0xFF;
  cs->t3 = time_to_byte(so->tx.send_delay);
  cs->t4 = 0xFF;

  return send(so, &cf);
}

static void handle_cs_ack(struct sock* sk, struct sk_buff* skb)
{
  struct tp20_sock* so = tp20_sk(sk);
  struct can_frame* cf = (struct can_frame*)skb->data;
  struct tp20_cs* ts = (struct tp20_cs*)cf->data;

  if(cf->can_id != so->rx.id) { /* we have a filter so we shouldn't be getting anything we don't want */
    TP20_DEBUG(0, "bad can_id in handle_cs_ack");
    goto out_err;
  }

  if(cf->can_dlc != sizeof(struct tp20_cs)) {
    TP20_DEBUG(0, "bad dlc in handle_cs_ack");
    goto out_err;
  }

  if(ts->tpc1 != TP20_OP_CA) {
    TP20_DEBUG(0, "bad tpc1 in handle_cs_ack");
    goto out_err;
  }

  if(ts->tpc2 < 1 || ts->tpc2 > TP20_MAX_BLOCK_SIZE) {
    TP20_DEBUG(0, "bad tpc2 in handle_cs_ack");
    goto out_err;
  }

  so->rx.ack_timeout = byte_to_time(ts->t1);
  so->rx.send_delay = byte_to_time(ts->t3);

  if(so->rx.ack_timeout <= 4 * so->rx.send_delay) {
    TP20_DEBUG(0, "bad t1/t3 combination in handle_cs_ack");
    goto out_err;
  }

  /* advance state */
  so->sk.sk_state = TP20_ESTABLISHED;
  wake_up_interruptible(sk_sleep(sk)); /* tp20_connect wants to know about this */

  /* start connection test timer */
  so->timeout_count = 0;
  so->timer.function = ct_timeout;
  hrtimer_start(&so->timer, TP20_CT_TIMEOUT, HRTIMER_MODE_REL);

  return;

out_err:
  sk->sk_state = TP20_CLOSE;
  sk->sk_err = ECONNRESET;
  wake_up_interruptible(sk_sleep(sk));
}

static enum hrtimer_restart cs_timeout(struct hrtimer* timer)
{
  struct tp20_sock* so = container_of(timer, struct tp20_sock, timer);
  struct sock* sk = &so->sk;

  if(sk->sk_state != TP20_CS_ACK)
    return HRTIMER_NORESTART;

  if(++so->timeout_count >= TP20_CS_MAX_TIMEOUTS) {
    sk->sk_state = TP20_CLOSE;
    sk->sk_err = ETIMEDOUT;
    wake_up_interruptible(sk_sleep(sk));
    return HRTIMER_NORESTART;
  }

  send_cs(so);
  hrtimer_forward_now(timer, TP20_CS_TIMEOUT);
  return HRTIMER_RESTART;
}

/*
 * channel request
 */
struct tp20_cr {
  __u8 destination;
  __u8 opcode;
  __u8 tx_id_low;
  __u8 tx_id_high_info;
  __u8 rx_id_low;
  __u8 rx_id_high_info;
  __u8 app_type;
} __attribute__((packed));

static inline int tx_id(struct tp20_cr* cs)
{
  return ((cs->tx_id_high_info & 7) << 8) | cs->tx_id_low;
}

static inline int rx_id(struct tp20_cr* cs)
{
  return ((cs->rx_id_high_info & 7) << 8) | cs->rx_id_low;
}

static inline int tx_info(struct tp20_cr* cs)
{
  return cs->tx_id_high_info >> 3;
}

static inline int rx_info(struct tp20_cr* cs)
{
  return cs->rx_id_high_info >> 3;
}

static int send_cr(struct tp20_sock* so)
{
  struct can_frame cf;
  struct tp20_cr* cr;

  cf.can_id = so->tx.id;
  cf.can_dlc = sizeof(struct tp20_cr);

  cr = (struct tp20_cr*)cf.data;
  cr->destination = so->destination;
  cr->opcode = TP20_OP_CR;
  cr->tx_id_low = 0;
	cr->tx_id_high_info = (TP20_INFO_IDUNSPEC << 3);
  cr->rx_id_low = so->rx.id;
  cr->rx_id_high_info = (TP20_INFO_IDSPEC << 3) | (so->rx.id >> 8);
  cr->app_type = so->app_type;

  return send(so, &cf);
}

static void handle_cr_ack(struct sock* sk, struct sk_buff* skb)
{
  struct tp20_sock* so = tp20_sk(sk);
  struct can_frame* cf = (struct can_frame*)skb->data;
  struct tp20_cr* cr = (struct tp20_cr*)cf->data;

  if(cf->can_id != so->rx.id) { /* we have a filter so we shouldn't be getting anything we don't want */
    TP20_DEBUG(0, "bad can_id in handle_cr_ack");
    goto out_err;
  }

  if(cf->can_dlc != sizeof(struct tp20_cr)) {
    TP20_DEBUG(0, "bad dlc in handle_cr_ack");
    goto out_err;
  }

  if(cr->destination != (so->tx.id & 0xFF)) {
    TP20_DEBUG(0, "bad destination in handle_cr_ack");
    goto out_err;
  }

  if(cr->opcode != TP20_OP_CP) {
    TP20_DEBUG(0, "bad opcode in handle_cr_ack");
    goto out_err;
  }

  if(tx_info(cr) != TP20_INFO_IDSPEC) {
    TP20_DEBUG(0, "bad tx_info in handle_cr_ack");
    goto out_err;
  }

  if(rx_info(cr) != TP20_INFO_IDSPEC) {
    TP20_DEBUG(0, "bad rx_info in handle_cr_ack");
    goto out_err;
  }

  so->rx.id = tx_id(cr);

  if(rx_id(cr) != so->tx.id) {
    TP20_DEBUG(0, "bad rx_id in rcv_channel_setup_ack");
    goto out_err;
  }

  if(cr->app_type != so->app_type) {
    TP20_DEBUG(0, "bad app_type in rcv_channel_setup_ack");
    goto out_err;
  }
 
  if(send_cs(so))
    goto out_err;

  /* advance state */
  so->sk.sk_state = TP20_CS_ACK;

  /* start timer in case we get no reply */
  so->timeout_count = 0;
  so->timer.function = cs_timeout;
  hrtimer_start(&so->timer, TP20_CS_TIMEOUT, HRTIMER_MODE_REL);

  return;

out_err:
  sk->sk_state = TP20_CLOSE;
  sk->sk_err = ECONNRESET;
  wake_up_interruptible(sk_sleep(sk));
}

static enum hrtimer_restart channel_setup_timeout(struct hrtimer* timer)
{
  struct tp20_sock* so = container_of(timer, struct tp20_sock, timer);
  struct sock* sk = &so->sk;
  
  if(sk->sk_state != TP20_CR_ACK)
    return HRTIMER_NORESTART;

  if(++so->timeout_count >= TP20_CR_MAX_TIMEOUTS) {
    sk->sk_state = TP20_CLOSE;
    sk->sk_err = ETIMEDOUT;
    wake_up_interruptible(sk_sleep(sk));
    return HRTIMER_NORESTART;
  }

  send_cr(so);
  hrtimer_forward_now(timer, TP20_CR_TIMEOUT);
  return HRTIMER_RESTART;
}

static void handle_established(struct sock* sk, struct sk_buff* skb)
{
  /* TODO */
}

/*
 * connection general
 */
static void tp20_rcv(struct sk_buff* skb, void* data)
{
  struct sock* sk = (struct sock*)data;

  switch(sk->sk_state) {
  case TP20_CR_ACK:
    handle_cr_ack(sk, skb);
    break;
  case TP20_CS_ACK:
    handle_cs_ack(sk, skb);
    break;
  case TP20_ESTABLISHED:
    handle_established(sk, skb);
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
  so->tx.id = TP20_TX_INITIAL_ID;
  so->tx.block_size = TP20_TX_BLOCK_SIZE;
  so->rx.id = TP20_RX_INITIAL_ID;
  sk->sk_state = TP20_CR_ACK;
  sock->state = SS_CONNECTING;

  /* send channel request telegram */
  err = send_cr(so);
  if(err)
    goto out;

  /* start listening for replies */
  err = can_rx_register(dev, so->rx.id, CAN_SFF_MASK, tp20_rcv, sk, "tp20");
  if(err)
    goto out;

  /* start timer in case we get no reply */
  so->timeout_count = 0;
  so->timer.function = channel_setup_timeout;
  hrtimer_start(&so->timer, TP20_CR_TIMEOUT, HRTIMER_MODE_REL);

  /* wait to connect */
  if(wait_event_interruptible(*(sk_sleep(sk)), sk->sk_state > TP20_DONE)) {
    err = -ERESTARTSYS; /* caught signal */
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

  lock_sock(sk);

  if(dev_net(dev) != &init_net)
    goto out;

  if(dev->type != ARPHRD_CAN)
    goto out;

  if(so->ifindex != dev->ifindex)
    goto out;

  switch(msg) {
  case NETDEV_UNREGISTER:
    if(so->ifindex >= 0)
      can_rx_unregister(dev, so->rx.id, CAN_SFF_MASK, tp20_rcv, sk);
    so->ifindex = -1;

    sk->sk_err = ENODEV;
    if(!sock_flag(sk, SOCK_DEAD))
      sk->sk_error_report(sk);

    break;

  case NETDEV_DOWN:
    sk->sk_err = ENETDOWN;
    if(!sock_flag(sk, SOCK_DEAD))
      sk->sk_error_report(sk);

    break;
  }

out:
  release_sock(sk);

  return NOTIFY_DONE;
}

/*
 * socket setup and teardown
 */
static int tp20_init(struct sock* sk)
{
  struct tp20_sock* so = tp20_sk(sk);
  int err;

  sk->sk_state = TP20_CLOSE;
  so->ifindex = -1;
  so->app_type = TP20_APPTYPE_DIAGNOSTICS;

  hrtimer_init(&so->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);

  so->notifier.notifier_call = tp20_notifier;
  err = register_netdevice_notifier(&so->notifier);
  if(err)
    return err;

  return 0;
}

static int tp20_release(struct socket* sock)
{
  struct tp20_sock* so = tp20_sk(sock->sk);

  hrtimer_cancel(&so->timer);

  unregister_netdevice_notifier(&so->notifier);

  if(so->ifindex >= 0) {
    struct net_device* dev = dev_get_by_index(&init_net, so->ifindex);
    can_rx_unregister(dev, so->rx.id, CAN_SFF_MASK, tp20_rcv, &so->sk);
  }

	return 0;
}

/*
 * module setup and teardown
 */
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
  if(err < 0) {
    printk(KERN_ERR "can-tp20: registration of tp20 protocol failed\n");
    return 0;
  }

  printk(KERN_INFO "can-tp20 loaded\n");

  return 0;
}

static __exit void tp20_module_exit(void)
{
  can_proto_unregister(&tp20_can_proto);

  printk(KERN_INFO "can-tp20 unloaded\n");
}

module_init(tp20_module_init);
module_exit(tp20_module_exit);
