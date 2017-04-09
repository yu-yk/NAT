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
  // nfq related variable
  struct nfqnl_msg_packet_hdr *nfq_header;
  struct nfqnl_msg_packet_hw *hwph;
  unsigned int nfq_id;

  nfq_header = nfq_get_msg_packet_hdr(pkt);
  if (nfq_header != NULL) {
    nfq_id = ntohl(nfq_header->packet_id);
  }


  char *payload;
  int data_len = nfq_get_payload(pkt, &payload);
  struct iphdr *iph = (struct iphdr*) payload;

  // check the protocol type, only accept TCP
  if (iph->protocol == IPPROTO_TCP) {
    // TCP packets
    // check in or outbound
    if (inbound) {
      // inbound
      // search dest port match nat table
      if (yes) {
        // modifies the ip and tcp header
        // recalculate checksum
        // accept
      } else {
        // no match port found, drop
        printf("DROP\n");
        return nfq_set_verdict(qh, nfq_id, NF_DROP, 0, NULL);
      }
    } else {
      // outbound
      // check is there entry in nat table
      if (yes) {
        // use the nat table information for further process
      } else {
        // no entry found
        // check is it a SYN packet
        if (yes) {
          // create a new entry
          // the source IP-port pair
          // the newly assigned port number (between 10000 and 12000) incremental
        } else {
          // not a SYN packet, drop
          printf("DROP\n");
          return nfq_set_verdict(qh, nfq_id, NF_DROP, 0, NULL);
        }
      }
      //do the translation and forward it
      // translation here
      return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, NULL);

    }

  } else {
    // Others protocol, drop
    printf("DROP\n");
    return nfq_set_verdict(qh, nfq_id, NF_DROP, 0, NULL);
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


  // Check the number of run-time argument
  if(argc != 4){
    fprintf(stderr, "Usage: %s <public ip> <internal ip> <subnet mask>\n", argv[0]);
    exit(1);
  }

  public_ip = argv[1];
  internal_ip = argv[2];
  subnet_mask = argv[3];

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
