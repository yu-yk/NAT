#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <checksum.h>


/*
* Callback function installed to netfilter queue
*/
static int Callback(struct nfq_q_handle *qh, struct nfgenmsg *msg, struct nfq_data *pkt, void *data) {
  int i;
  struct nfqnl_msg_packet_hdr *header;
  struct nfqnl_msg_packet_hw *hwph;

  char *payload;
  int data_len = nfq_get_payload(pkt, &payload);
  struct iphdr *iph = (struct iphdr*) payload;

  if (iph->protocol == IPPROTO_TCP) {
    // TCP packets

  } else {
    // Others, can be ignored
  }

  // Print the payload;
  printf("\n[");
  unsigned char *pktData;
  int len = nfq_get_payload(pkt, (char**)&pktData);
  if (len > 0) {
    for (i=0; i<len; i++) {
      printf("%02x ", pktData[i]);
    }
  }
  printf("]\n");

  // for the first 20 packeks, a packet[id] is accept, if
  // accept[id-1] = 1.
  // All packets with id > 20, will be accepted

  // if (id <= 20) {
  //   if (accept[id-1]) {
  //     printf("ACCEPT\n");
  //     return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
  //   } else {
  //     printf("DROP\n");
  //     return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
  //   }
  // } else {
  //   printf("ACCEPT\n");
  //   return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
  // }

}

/*
* Main program
*/
int main(int argc, char **argv){
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  struct nfnl_handle *nh;
  int fd;
  int len;
  char buf[4096];
  char *public_ip;
  char *internal_ip;
  char *subnet_mask;

  // Open library handle
  if (!(h = nfq_open())) {
    fprintf(stderr, "Error: nfq_open()\n");
    exit(-1);
  }

  // Unbind existing nf_queue handler (if any)
  if (nfq_unbind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "Error: nfq_unbind_pf()\n");
    exit(1);
  }

  // Bind nfnetlink_queue as nf_queue handler of AF_INET
  if (nfq_bind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "Error: nfq_bind_pf()\n");
    exit(1);
  }

  // bind socket and install a callback on queue 0
  if (!(qh = nfq_create_queue(h,  0, &Callback, NULL))) {
    fprintf(stderr, "Error: nfq_create_queue()\n");
    exit(1);
  }

  // Setting packet copy mode
  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    fprintf(stderr, "Could not set packet copy mode\n");
    exit(1);
  }

  fd = nfq_fd(h);

  while ((len = recv(fd, buf, sizeof(buf), 0)) && len >= 0) {
    nfq_handle_packet(h, buf, len);

  }

  printf("unbinding from queue 0\n");
  nfq_destroy_queue(qh);

  nfq_close(h);

  return 0;

}
