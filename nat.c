#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <checksum.h>
#include "table.c"

//global variable
char *public_ip;
char *internal_ip;
char *subnet_mask;
unsigned int wan_port = 10000;

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
  unsigned int source_ip = ntohl(iph->saddr);
  unsigned int dest_ip = ntohl(iph->daddr);

  struct tcphdr *tcph = (struct tcphdr *)(((char*) iph) + iph->ihl << 2);
  unsigned int source_port = ntohs(tcph->source);
  unsigned int dest_port = ntohs(tcph->dest);
  //flag bit
  unsigned int SYN = ntohs(tcph->syn);
  unsigned int ACK = ntohs(tcph->ack);
  unsigned int FIN = ntohs(tcph->fin);
  unsigned int RST = ntohs(tcph->rst);


  // check the protocol type, only accept TCP
  if (iph->protocol == IPPROTO_TCP) {
    // TCP packets
    int inbound = 0;
    int mask_int = atoi(subnet_mask);
    unsigned int local_mask = 0xffffffff << (32-mask_int)
    unsigned int local_network = (ntohl(inet_aton(internal_ip) & local_mask);
    // create an dummy entry for stroing the nat data
    struct Entry *tempEntry = (struct Entry*) malloc(sizeof(struct Entry));
    // check in or outbound
    if ((source_ip & local_mask) == local_network) {
      inbound = 1;
    }

    if (inbound) {
      // inbound
      // search dest port match nat table
      tempEntry = find(dest_ip, dest_port);

      if (tempEntry != NULL) {
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
      tempEntry = find(source_ip, source_port);
      if (tempEntry != NULL) {
        //do nothing, translation step is at the last

      } else {
        // no entry found
        // check is it a SYN packet
        if (SYN) {
          // create a new entry
          // the source IP-port pair
          unsigned int wan_ip;
          inet_pton(AF_INET, "10.3.1.3", &wan_ip);
          struct IP_PORT *wan = (struct IP_PORT*) malloc(sizeof(struct IP_PORT));
          wan->ip = wan_ip;
          wan->port = wan_port;
          struct IP_PORT *lan = (struct IP_PORT*) malloc(sizeof(struct IP_PORT));
          lan->ip = source_ip;
          lan->port = source_port;

          insertFirst(wan, lan);
          // the newly assigned port number (between 10000 and 12000) incremental
          wan_port++;

        } else {
          // not a SYN packet, drop
          printf("DROP\n");
          return nfq_set_verdict(qh, nfq_id, NF_DROP, 0, NULL);
        }
      }
      // do the translation

      // forward it
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
