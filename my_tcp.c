#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/kref.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <net/ip.h>
#include <net/secure_seq.h>
#include <linux/timer.h>


#define WORD_SIZE 4

#define MAX_CONNECTION_COUNT 1024

#define BUFFER_SIZE 1024

#define CLASS_NAME "mytcp"

static DEFINE_IDA(mytcp_ida);

static dev_t dev_num;
static struct class *mytcp_class;

static struct workqueue_struct *mytcp_queue;

static int mytcp_open(struct inode *inode, struct file *file);

static int mytcp_release(struct inode *inode, struct file *file);

static ssize_t mytcp_read(struct file *file, char __user *buf, size_t count,
                          loff_t *ppos);

static ssize_t mytcp_write(struct file *file, const char __user *buf,
                           size_t count, loff_t *ppos);

static const struct file_operations mytcp_fops = {
    .owner = THIS_MODULE,
    .open = mytcp_open,
    .release = mytcp_release,
    .read = mytcp_read,
    .write = mytcp_write,
};

enum connection_status {
  UNDEFINED,
  SYN_RECV,
  ESTABLISHED,
  CLOSE_WAIT,
  LAST_ACK,
  CLOASED,
};

struct connection_key {
  __be32 source_addr;
  __be32 dest_addr;
  __be16 dest_port;
  __be16 source_port;
} __attribute__((packed));

struct connection_entry {
  struct connection_entry *next;

  struct connection_key key;

  spinlock_t lock;
  struct kref refcount;

  struct cdev device;
  int device_id;
  struct work_struct create_device_work;
  struct work_struct remove_device_work;

  struct kfifo input_buffer;
  struct kfifo output_buffer;

  struct work_struct send_data_work;
  struct timer_list timer;

  struct net_device* net_dev;

  __u32 seq;
  __u32 client_seq;
  enum connection_status status;
};

struct bucket {
  spinlock_t lock;
  struct connection_entry *list;
};

#define BUCKETS_COUNT (__u32)256

static struct bucket bucket_array[BUCKETS_COUNT];

static __u32 hash_initval = 0;

static void send_package(struct work_struct* work);

static void init_hash(void) {
  get_random_bytes(&hash_initval, sizeof(hash_initval));
}

static __u32 hash_function(__be32 source_addr, __be16 source_port,
                           __be32 dest_addr, __be16 dest_port) {
  __be32 ports = ((__be32)source_port << 16) | (__be32)dest_port;

  return jhash_3words(source_addr, dest_addr, ports, hash_initval);
}

static void init_bucket_array(void) {
  for (int i = 0; i < BUCKETS_COUNT; ++i) {
    spin_lock_init(&bucket_array[i].lock);
    bucket_array[i].list = NULL;
  }
}

static void destroy_entry(struct work_struct *work) {
  struct connection_entry *entry;
  entry = container_of(work, struct connection_entry, remove_device_work);

  timer_shutdown_sync(&entry->timer);

  device_destroy(mytcp_class, MKDEV(MAJOR(dev_num), entry->device_id));
  cdev_del(&entry->device);
  ida_free(&mytcp_ida, entry->device_id);
  kfifo_free(&entry->input_buffer);
  kfree(entry);

  printk("mytcp: Connection device destroyed\n");
}

static void destroy_entry_callback(struct kref *kref) {
  struct connection_entry *entry;
  entry = container_of(kref, struct connection_entry, refcount);

  queue_work(mytcp_queue, &entry->remove_device_work);
}

static inline void put_entry(struct connection_entry *entry) {
  kref_put(&entry->refcount, destroy_entry_callback);
}

static void create_device_for_entry(struct work_struct *work) {
  struct connection_entry *entry =
      container_of(work, struct connection_entry, create_device_work);

  cdev_init(&entry->device, &mytcp_fops);
  entry->device.owner = THIS_MODULE;

  if (cdev_add(&entry->device, MKDEV(MAJOR(dev_num), entry->device_id), 1) <
      0) {
    printk("mytcp: Failed to add device\n");
    return;
  }

  struct device *device = device_create(
      mytcp_class, NULL, MKDEV(MAJOR(dev_num), entry->device_id), NULL,
      "mytcp/%pI4:%d", &entry->key.dest_addr, ntohs(entry->key.dest_port));
  if (IS_ERR(device)) {
    printk("mytcp: Failed to create device\n");
    return;
  }

  put_entry(entry);
}

static void timer_callback(struct timer_list *timer) {
  struct connection_entry *entry = container_of(timer, struct connection_entry, timer);

  queue_work(mytcp_queue, &entry->send_data_work);
}

static struct connection_entry *create_entry(__be32 source_addr,
                                             __be16 source_port,
                                             __be32 dest_addr,
                                             __be16 dest_port) {
  __u32 hash = hash_function(source_addr, source_port, dest_addr, dest_port) &
               (BUCKETS_COUNT - 1);

  struct connection_entry *entry =
      kmalloc(sizeof(struct connection_entry), GFP_ATOMIC);
  if (!entry) {
    return NULL;
  }

  if (kfifo_alloc(&entry->input_buffer, BUFFER_SIZE, GFP_ATOMIC)) {
    printk("mytcp: Failed to allocate memory for input buffer\n");
    return NULL;
  }

  if (kfifo_alloc(&entry->output_buffer, BUFFER_SIZE, GFP_ATOMIC)) {
    printk("mytcp: Failed to allocate memory for output buffer\n");
    kfifo_free(&entry->input_buffer);
    return NULL;
  }

  entry->key.dest_port = dest_port;
  entry->key.dest_addr = dest_addr;
  entry->key.source_addr = source_addr;
  entry->key.source_port = source_port;

  entry->status = UNDEFINED;
  entry->seq = 0;
  entry->client_seq = 0;

  entry->next = NULL;

  spin_lock_init(&entry->lock);

  entry->device_id =
      ida_alloc_max(&mytcp_ida, MAX_CONNECTION_COUNT, GFP_ATOMIC);
  if (entry->device_id < 0) {
    printk("mytcp: Failed to allocate device id\n");
    kfifo_free(&entry->input_buffer);
    kfifo_free(&entry->output_buffer);
    kfree(entry);
    return NULL;
  }

  INIT_WORK(&entry->create_device_work, create_device_for_entry);
  INIT_WORK(&entry->remove_device_work, destroy_entry);
  INIT_WORK(&entry->send_data_work, send_package);

  timer_setup(&entry->timer, timer_callback, 0);

  kref_init(&entry->refcount);

  spin_lock_bh(&bucket_array[hash].lock);

  struct connection_entry *next = bucket_array[hash].list;
  bucket_array[hash].list = entry;
  entry->next = next;

  kref_get(&entry->refcount);
  kref_get(&entry->refcount);

  spin_unlock_bh(&bucket_array[hash].lock);

  queue_work(mytcp_queue, &entry->create_device_work);

  return entry;
}

static struct connection_entry *get_entry(__be32 source_addr,
                                          __be16 source_port, __be32 dest_addr,
                                          __be16 dest_port) {
  __u32 hash = hash_function(source_addr, source_port, dest_addr, dest_port) &
               (BUCKETS_COUNT - 1);

  struct connection_key key;
  key.dest_addr = dest_addr;
  key.dest_port = dest_port;
  key.source_addr = source_addr;
  key.source_port = source_port;

  spin_lock_bh(&bucket_array[hash].lock);
  struct connection_entry *cur = bucket_array[hash].list;

  while (cur != NULL) {
    if (memcmp(&cur->key, &key, sizeof(struct connection_key)) == 0) {
      kref_get(&cur->refcount);
      spin_unlock_bh(&bucket_array[hash].lock);
      return cur;
    }

    cur = cur->next;
  }

  spin_unlock_bh(&bucket_array[hash].lock);
  return NULL;
}

static void remove_entry(__be32 source_addr, __be16 source_port,
                         __be32 dest_addr, __be16 dest_port) {
  __u32 hash = hash_function(source_addr, source_port, dest_addr, dest_port) &
               (BUCKETS_COUNT - 1);

  struct connection_key key;
  key.dest_addr = dest_addr;
  key.dest_port = dest_port;
  key.source_addr = source_addr;
  key.source_port = source_port;

  spin_lock_bh(&bucket_array[hash].lock);

  struct connection_entry *prev = NULL;
  struct connection_entry *cur = bucket_array[hash].list;

  while (cur != NULL) {
    if (memcmp(&cur->key, &key, sizeof(struct connection_key)) == 0) {
      if (prev == NULL) {
        bucket_array[hash].list = cur->next;
      } else {
        prev->next = cur->next;
      }

      cur->next = NULL;
      spin_unlock_bh(&bucket_array[hash].lock);

      put_entry(cur);

      return;
    }

    prev = cur;
    cur = cur->next;
  }

  spin_unlock_bh(&bucket_array[hash].lock);
}

static void remove_bucket_array(void) {
  for (int i = 0; i < BUCKETS_COUNT; ++i) {
    struct connection_entry *cur = bucket_array[i].list;

    while (cur != NULL) {
      struct connection_entry *tmp = cur->next;
      put_entry(cur);
      cur = tmp;
    }
  }
}

static struct sk_buff *create_new_tcp_package(unsigned int additional_size,
                                              struct net_device *dev) {
  unsigned int headroom = LL_RESERVED_SPACE(dev);
  unsigned int header_size = sizeof(struct iphdr) + sizeof(struct tcphdr);

  struct sk_buff *skb =
      alloc_skb(headroom + header_size + additional_size, GFP_ATOMIC);
  if (!skb) {
    printk("mytcp: failed to allocate skb\n");
    return NULL;
  }

  skb_reserve(skb, headroom);

  void *header_data = skb_put(skb, header_size);
  memset(header_data, 0, header_size);

  skb_set_network_header(skb, 0);
  skb_set_transport_header(skb, sizeof(struct iphdr));

  skb->dev = dev;
  skb->protocol = htons(ETH_P_IP);

  return skb;
}

static void fill_ip_header(struct sk_buff *skb, struct iphdr *iphdr,
                           __be32 saddr, __be32 daddr, unsigned long size) {
  iphdr->version = 4;
  iphdr->ihl = sizeof(struct iphdr) / WORD_SIZE;
  iphdr->tos = 0;
  iphdr->tot_len = htons(size);
  iphdr->frag_off = 0;
  iphdr->ttl = 64;
  iphdr->protocol = IPPROTO_TCP;
  iphdr->saddr = saddr;
  iphdr->daddr = daddr;

  ip_select_ident(dev_net(skb->dev), skb, NULL);

  iphdr->check = 0;
  iphdr->check = ip_fast_csum(iphdr, iphdr->ihl);
}

static int send_empty_package(struct net_device *dev, __be32 saddr,
                              __be32 daddr, __be16 sport, __be16 dport,
                              int is_syn, int is_fin, int is_ack) {
  struct flowi4 fl4;
  memset(&fl4, 0, sizeof(fl4));
  fl4.daddr = daddr;
  fl4.saddr = saddr;
  fl4.flowi4_proto = IPPROTO_TCP;

  struct rtable *rt;
  rt = ip_route_output_key(dev_net(dev), &fl4);
  if (IS_ERR(rt)) {
    printk("mytcp: Failed to find route to send package\n");
    return -1;
  }

  struct connection_entry *entry = get_entry(saddr, sport, daddr, dport);
  if (!entry) {
    printk("mytcp: Failed to find connection\n");
    ip_rt_put(rt);
    return -1;
  }

  struct sk_buff *skb = create_new_tcp_package(0, dev);
  if (!skb) {
    printk("mytcp: Failed to allocate socket buffer\n");
    ip_rt_put(rt);
    put_entry(entry);
    return -1;
  }

  struct iphdr *ip_header;
  struct tcphdr *tcp_header;

  ip_header = ip_hdr(skb);
  tcp_header = tcp_hdr(skb);

  skb_dst_set(skb, &rt->dst);

  fill_ip_header(skb, ip_header, saddr, daddr,
                 sizeof(struct iphdr) + sizeof(struct tcphdr));

  tcp_header->source = sport;
  tcp_header->dest = dport;
  tcp_header->doff = sizeof(struct tcphdr) / WORD_SIZE;

  if (is_ack == 1) {
    tcp_header->ack = 1;
  }

  if (is_syn == 1) {
    tcp_header->syn = 1;
  }

  if (is_fin == 1) {
    tcp_header->fin = 1;
  }

  spin_lock_bh(&entry->lock);

  tcp_header->seq = htonl(entry->seq);
  tcp_header->ack_seq = htonl(entry->client_seq);
  tcp_header->window = htons(kfifo_avail(&entry->input_buffer));

  spin_unlock_bh(&entry->lock);

  tcp_header->check = 0;
  tcp_header->check =
      csum_tcpudp_magic(saddr, daddr, sizeof(struct tcphdr), IPPROTO_TCP,
                        csum_partial(tcp_header, sizeof(struct tcphdr), 0));
  put_entry(entry);

  ip_local_out(dev_net(dev), NULL, skb);
  return 0;
}

static int send_fin_package(struct net_device *dev, __be32 saddr, __be32 daddr,
                            __be16 sport, __be16 dport) {
  struct connection_entry *entry = get_entry(saddr, sport, daddr, dport);
  spin_lock_bh(&entry->lock);
  if (entry->status != CLOSE_WAIT) {
    printk("mytcp: Invalid status for sending FIN\n");
    spin_unlock_bh(&entry->lock);
    put_entry(entry);
    return -1;
  }

  entry->seq += 1;
  entry->status = LAST_ACK;
  spin_unlock_bh(&entry->lock);
  put_entry(entry);

  int res = send_empty_package(dev, saddr, daddr, sport, dport, 0, 1, 1);
  if (res == 0) {
    printk("mytcp: FIN package sended\n");
  } else {
    printk("mytcp: FIN package failed\n");
  }

  return res;
}

static void send_package(struct work_struct* work) {
  struct connection_entry* entry = container_of(work, struct connection_entry, send_data_work);

  unsigned int payload_length;

  spin_lock_bh(&entry->lock);
  payload_length = kfifo_len(&entry->output_buffer);
  
  if (entry->status == CLOASED || payload_length == 0) {
    spin_unlock_bh(&entry->lock);
    put_entry(entry);
    return;
  }

  spin_unlock_bh(&entry->lock);
  
  struct flowi4 fl4;
  memset(&fl4, 0, sizeof(fl4));
  fl4.daddr = entry->key.dest_addr;
  fl4.saddr = entry->key.source_addr;
  fl4.flowi4_proto = IPPROTO_TCP;

  struct rtable *rt;
  rt = ip_route_output_key(dev_net(entry->net_dev), &fl4);
  if (IS_ERR(rt)) {
    printk("mytcp: Failed to find route to send package\n");
    put_entry(entry);
  }

  struct sk_buff* skb = create_new_tcp_package(payload_length, entry->net_dev);
  if (!skb) {
    printk("mytcp: Failed to allocate socket buffer\n");
    put_entry(entry);
    ip_rt_put(rt);
  }

  skb_dst_set(skb, &rt->dst);

  fill_ip_header(skb, ip_hdr(skb), entry->key.source_addr, entry->key.dest_addr,
                 sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_length);

  unsigned char *payload = skb_put(skb, payload_length);

  struct tcphdr *tcp_header;

  tcp_header = tcp_hdr(skb);

  tcp_header->source = entry->key.source_port;
  tcp_header->dest = entry->key.dest_port;
  tcp_header->doff = sizeof(struct tcphdr) / WORD_SIZE;

  tcp_header->ack = 1;
  
  spin_lock_bh(&entry->lock);
  tcp_header->seq = htonl(entry->seq);
  tcp_header->ack_seq = htonl(entry->client_seq);
  tcp_header->window = htons(kfifo_avail(&entry->input_buffer));

  unsigned int copied = kfifo_out_peek(&entry->output_buffer, payload, payload_length);

  spin_unlock_bh(&entry->lock);

  __u32 package_size = sizeof(struct tcphdr) + payload_length;

  tcp_header->check = 0;
  tcp_header->check =
      csum_tcpudp_magic(entry->key.source_addr, entry->key.dest_addr, package_size, IPPROTO_TCP,
                        csum_partial(tcp_header, package_size, 0));

  printk("mytcp: Send package with size %u\n", copied);

  mod_timer(&entry->timer, jiffies + msecs_to_jiffies(5000));

  ip_local_out(dev_net(entry->net_dev), NULL, skb);
}

static unsigned int mytcp_hook(void *, struct sk_buff *skb,
                               const struct nf_hook_state *) {
  if (!skb) {
    return NF_ACCEPT;
  }

  struct iphdr *iph;
  iph = ip_hdr(skb);
  if (!iph || iph->protocol != IPPROTO_TCP) {
    return NF_ACCEPT;
  }

  struct tcphdr *tcph;
  tcph = tcp_hdr(skb);

  if (tcph->syn) {
    printk("mytcp: Connection request from %pI4:%d\n", &iph->saddr,
           ntohs(tcph->source));
    __u32 seq =
        secure_tcp_seq(iph->saddr, iph->daddr, tcph->source, tcph->dest);

    struct connection_entry *entry =
        create_entry(iph->daddr, tcph->dest, iph->saddr, tcph->source);

    spin_lock_bh(&entry->lock);
    entry->status = SYN_RECV;
    entry->seq = seq;
    entry->client_seq = ntohl(tcph->seq) + 1;
    entry->net_dev = skb->dev;
    spin_unlock_bh(&entry->lock);

    send_empty_package(skb->dev, iph->daddr, iph->saddr, tcph->dest,
                       tcph->source, 1, 0, 1);

    spin_lock_bh(&entry->lock);
    entry->seq += 1;
    spin_unlock_bh(&entry->lock);

    put_entry(entry);

    return NF_DROP;
  }

  printk("mytcp: Accepted package from %pI4:%d\n", &iph->saddr,
         ntohs(tcph->source));

  struct connection_entry *entry =
      get_entry(iph->daddr, tcph->dest, iph->saddr, tcph->source);

  if (!entry) {
    printk("mytcp: Failed to find connection\n");
    return NF_DROP;
  }

  spin_lock_bh(&entry->lock);

  if (ntohl(tcph->seq) != entry->client_seq) {
    printk(
        "mytcp: Invalid package order, client send seq %u, wait for seq %u\n",
        ntohl(tcph->seq), entry->client_seq);
    spin_unlock_bh(&entry->lock);
    put_entry(entry);

    if (ntohl(tcph->seq) < entry->client_seq) {
      // missing ack package to client, need to ack again
      send_empty_package(skb->dev, iph->daddr, tcph->dest, iph->saddr,
                         tcph->source, 0, 0, 1);
    }

    return NF_DROP;
  }

  if (entry->status == SYN_RECV) {
    printk("mytcp: Connection established\n");
    entry->status = ESTABLISHED;
  }

  if (entry->status == LAST_ACK) {
    printk("mytcp: Connection was sucessfully closed\n");
    entry->status = CLOASED;
    spin_unlock_bh(&entry->lock);
    put_entry(entry);
    remove_entry(iph->daddr, tcph->dest, iph->saddr, tcph->source);
    return NF_DROP;
  }

  if (tcph->ack == 1) {
    if (ntohl(tcph->ack_seq) > entry->seq) {
      unsigned int delta = ntohl(tcph->ack_seq) - entry->seq;
      printk("mytcp: Client ack new data with size %u\n", delta);
      entry->seq = ntohl(tcph->ack_seq);
      kfifo_skip_count(&entry->output_buffer, delta);
    }
  }

  unsigned short need_to_send_ack = 0;

  int ip_header_length = iph->ihl * WORD_SIZE;
  int tcp_header_length = tcph->doff * WORD_SIZE;

  int payload_length =
      ntohs(iph->tot_len) - (ip_header_length + tcp_header_length);

  if (payload_length > 0) {
    unsigned char *payload = (unsigned char *)tcph + tcp_header_length;
    printk("mytcp: Data size: %d\n", payload_length);

    unsigned int copied =
        kfifo_in(&entry->input_buffer, payload, payload_length);
    entry->client_seq += copied;
    need_to_send_ack = 1;
  }

  int send_fin = 0;
  if (tcph->fin) {
    printk("mytcp: Client want to close connection\n");
    entry->client_seq += 1;
    need_to_send_ack = 1;
    entry->status = CLOSE_WAIT;
    send_fin = 1;
  }

  spin_unlock_bh(&entry->lock);
  put_entry(entry);

  if (need_to_send_ack == 1) {
    send_empty_package(skb->dev, iph->daddr, iph->saddr, tcph->dest,
                       tcph->source, 0, 0, need_to_send_ack);
  }

  if (send_fin == 1) {
    send_fin_package(skb->dev, iph->daddr, iph->saddr, tcph->dest,
                     tcph->source);
  }

  return NF_DROP;
}

static int mytcp_open(struct inode *inode, struct file *file) {
  struct connection_entry *entry;
  entry = container_of(inode->i_cdev, struct connection_entry, device);
  kref_get(&entry->refcount);
  file->private_data = entry;
  return 0;
}

static int mytcp_release(struct inode *inode, struct file *file) {
  struct connection_entry *entry = file->private_data;
  if (entry) {
    put_entry(entry);
  }
  return 0;
}

static ssize_t mytcp_read(struct file *file, char __user *buf, size_t count,
                          loff_t *ppos) {
  struct connection_entry *entry = file->private_data;

  spin_lock_bh(&entry->lock);

  unsigned int copied;
  if (kfifo_to_user(&entry->input_buffer, buf, count, &copied) < 0) {
    spin_unlock_bh(&entry->lock);
    return -EFAULT;
  }

  spin_unlock_bh(&entry->lock);

  return copied;
}

static ssize_t mytcp_write(struct file *file, const char __user *buf,
                           size_t count, loff_t *ppos) {
  struct connection_entry* entry = file->private_data;

  spin_lock_bh(&entry->lock);

  unsigned int copied;
  if (kfifo_from_user(&entry->output_buffer, buf, count, &copied)) {
    spin_unlock_bh(&entry->lock);
    return -EFAULT;
  }
  
  kref_get(&entry->refcount); // for sending package work
  if (!queue_work(mytcp_queue, &entry->send_data_work)) {
    put_entry(entry);
  }

  spin_unlock_bh(&entry->lock);
  
  return copied;
}

static struct nf_hook_ops nfho;

static int __init mytcp_init(void) {
  init_bucket_array();
  init_hash();

  mytcp_queue = alloc_ordered_workqueue("mytcp_queue", 0);
  if (!mytcp_queue) {
    printk("mytcp: Failed to create work queue\n");
    remove_bucket_array();
    return -1;
  }

  nfho.hook = mytcp_hook;
  nfho.hooknum = NF_INET_LOCAL_IN;
  nfho.pf = NFPROTO_IPV4;
  nfho.priority = NF_IP_PRI_FIRST;

  if (nf_register_net_hook(&init_net, &nfho) != 0) {
    printk("mytcp: Failed to register hook\n");
    destroy_workqueue(mytcp_queue);
    remove_bucket_array();
    return -1;
  }

  if (alloc_chrdev_region(&dev_num, 0, MAX_CONNECTION_COUNT, "mytcp_driver") <
      0) {
    printk("mytcp: Failed to allocate chardevice region\n");
    nf_unregister_net_hook(&init_net, &nfho);
    destroy_workqueue(mytcp_queue);
    remove_bucket_array();
    return -1;
  }

  mytcp_class = class_create(CLASS_NAME);
  if (IS_ERR(mytcp_class)) {
    printk("mytcp: Failed to create class\n");
    nf_unregister_net_hook(&init_net, &nfho);
    destroy_workqueue(mytcp_queue);
    remove_bucket_array();
    unregister_chrdev_region(dev_num, MAX_CONNECTION_COUNT);
    return -1;
  }

  printk("mytcp: Module init sucessfully\n");
  return 0;
}

static void __exit mytcp_exit(void) {
  nf_unregister_net_hook(&init_net, &nfho);

  destroy_workqueue(mytcp_queue);

  remove_bucket_array();

  class_destroy(mytcp_class);
  unregister_chrdev_region(dev_num, MAX_CONNECTION_COUNT);

  printk("mytcp: Module sucessfully removed\n");
}

module_init(mytcp_init);
module_exit(mytcp_exit);
MODULE_LICENSE("GPL");
