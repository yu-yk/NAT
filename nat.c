#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "checksum.h"
#include "table.h"

//global variable
char *public_ip;
char *internal_ip;
char *subnet_mask;
uint32_t local_network;
unsigned int local_mask;
unsigned int wan_ip;
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
  uint32_t source_ip = ntohl(iph->saddr);
  uint32_t dest_ip = ntohl(iph->daddr);

  struct tcphdr *tcph = (struct tcphdr *)(payload + (iph->ihl << 2));

  unsigned int source_port = ntohs(tcph->source);
  unsigned int dest_port = ntohs(tcph->dest);
  //flag bit
  unsigned int SYN = tcph->syn;
  unsigned int ACK = tcph->ack;
  unsigned int FIN = tcph->fin;
  unsigned int RST = tcph->rst;

  printf("SYN = %d\n\n\n\n", SYN);

  // check the protocol type, only accept TCP
  printf("check the protocol type, only accept TCP\n");
  if (iph->protocol == IPPROTO_TCP) {
    // TCP packets
    int inbound = 1;

    struct Entry *tempEntry = (struct Entry*) malloc(sizeof(struct Entry));
    // check in or outbound
    if ((source_ip & local_mask) == local_network) {
      inbound = 0;
    }

    if (inbound) {
      // inbound
      // search dest port match nat table
      printf("search dest port match nat table\n");
      tempEntry = (struct Entry*)find(dest_ip, dest_port);

      if (tempEntry != NULL) {
        // modifies the ip and tcp header
        printf("modifies the ip and tcp header\n");
        // do the translation
        iph->daddr = htonl(tempEntry->lan->ip);
        tcph->dest = htons(tempEntry->lan->port);

        // recalculate checksum
        printf("recalculate checksum\n");
        // reset checksum
        iph->check = 0;
        tcph->check = 0;

        // calculate new checksum
        tcph->check = tcp_checksum((unsigned char *) iph);
        iph->check = ip_checksum((unsigned char *) iph);

        printList();

        // accept
        return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, NULL);
      } else {
        // no match port found, drop
        printf("no match port found, drop\n");
        return nfq_set_verdict(qh, nfq_id, NF_DROP, 0, NULL);
      }

    } else {
      // outbound
      // check is there entry in nat table
      printf("check is there entry in nat table\n");
      tempEntry = (struct Entry*)find(source_ip, source_port);
      if (tempEntry != NULL) {
        // translation step is at the last
        printf("Entry found\n");

      } else {
        // no entry found
        printf("no entry found\n");
        // check is it a SYN packet
        if (SYN) {
          // create a new entry
          printf("create a new entry\n");
          // the source IP-port pair
          struct IP_PORT *wan = (struct IP_PORT*) malloc(sizeof(struct IP_PORT));
          wan->ip = wan_ip;
          wan->port = wan_port;
          struct IP_PORT *lan = (struct IP_PORT*) malloc(sizeof(struct IP_PORT));
          lan->ip = source_ip;
          lan->port = source_port;

          insertFirst(wan, lan);
          // the newly assigned port number (between 10000 and 12000) incremental
          printf("the newly assigned port number (between 10000 and 12000) incremental\n");
          wan_port++;

        } else {
          // not a SYN packet, drop
          printf("not a SYN packet, drop\n");
          return nfq_set_verdict(qh, nfq_id, NF_DROP, 0, NULL);
        }
      }
      // do the translation
      iph->saddr = htonl(wan_ip);
      tcph->source = htons(wan_port);

      // reset checksum
      iph->check = 0;
      tcph->check = 0;

      // calculate new checksum
      tcph->check = tcp_checksum((unsigned char *) iph);
      iph->check = ip_checksum((unsigned char *) iph);

      printList();

      // forward it
      return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, NULL);

    }
  } else {
    // Others protocol, drop
    printf("Others protocol, drop\n");
    return nfq_set_verdict(qh, nfq_id, NF_DROP, 0, NULL);
  }

}

/*
* Main program
*/
int main(int argc, char **argv) {
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  struct nfnl_handle *nh;
  int fd;
  int len;
  char buf[4096];

  // Check the number of run-time argument
  if(argc != 4){
    fprintf(stderr, "Usage: ./%s <public ip> <internal ip> <subnet mask>\n", argv[0]);
    exit(1);
  }

  public_ip = argv[1];
  internal_ip = argv[2];
  subnet_mask = argv[3];

  struct in_addr temp;
  int mask_int = atoi(subnet_mask);
  local_mask = (0xffffffff << (32-mask_int));
  inet_aton(internal_ip, &temp);
  local_network = ntohl(temp.s_addr) & local_mask;

  inet_aton(public_ip, &wan_ip);
  wan_ip = ntohl(wan_ip);

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

  printf("before while\n");
  while ((len = recv(fd, buf, sizeof(buf), 0)) && len >= 0) {
    printf("in while\n");
    nfq_handle_packet(h, buf, len);

  }

  printf("unbinding from queue 0\n");
  nfq_destroy_queue(qh);

  nfq_close(h);

  return 0;

}
