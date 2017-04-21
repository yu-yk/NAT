#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "checksum.h"
#include "table.h"

#define CONNECTION_STATE_NORMAL 0
#define CONNECTION_STATE_FIN_1_IN 1
#define CONNECTION_STATE_FIN_1_OUT 2
#define CONNECTION_STATE_FIN_2_IN 3
#define CONNECTION_STATE_FIN_2_OUT 4

int tcpfindport(void);

//global variable
char *public_ip;
char *internal_ip;
char *subnet_mask;
uint32_t local_network;
unsigned int local_mask;
unsigned int wan_ip;
unsigned int wan_port;
int port_used[2001] = {0};

int tcpfindport() {
  int i;
  for (i = 10000; i <= 12000; i++) {
    if (port_used[i-10000] == 0) {
      port_used[i-10000] = 1;
      return i;
    }
  }
  return -1;
}

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
  struct in_addr temp;

  struct tcphdr *tcph = (struct tcphdr *)(payload + (iph->ihl << 2));

  uint16_t source_port = ntohs(tcph->source);
  uint16_t dest_port = ntohs(tcph->dest);
  //flag bit
  unsigned int SYN = tcph->syn;
  unsigned int ACK = tcph->ack;
  unsigned int FIN = tcph->fin;
  unsigned int RST = tcph->rst;


  // check the protocol type, only accept TCP
  if (iph->protocol == IPPROTO_TCP) {
    printf("\n");
    printf("SYN = %d\n", SYN);
    printf("ACK = %d\n", ACK);
    printf("FIN = %d\n", FIN);
    printf("RST = %d\n", RST);
    // TCP packets
    int inbound = 1;

    struct Entry *tempEntry = (struct Entry*) malloc(sizeof(struct Entry));
    // check in or outbound
    if ((source_ip & local_mask) == local_network) {
      inbound = 0;
    }

    if (inbound) {
      printf("In bound packet\n");
      temp.s_addr = iph->saddr;
      printf("From %s:%d ", (char*)inet_ntoa(temp), source_port);
      temp.s_addr = iph->daddr;
      printf("to %s:%d\n", (char*)inet_ntoa(temp), dest_port);
      printf("search dest port match nat table\n");
      tempEntry = (struct Entry*)find(dest_ip, dest_port);

      if (tempEntry != NULL) {
        printf("entry found\n");

        printf("translate ip and tcp header\n");
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

        // if it is rst packet, delete the entry
        if (RST) {
          deleteEntry(dest_ip, dest_port);
          port_used[dest_port-10000] = 0;
        } else {
          // check four way hand shake state
          switch (tempEntry->four_way_state) {
            case CONNECTION_STATE_NORMAL:
              if (FIN) { tempEntry->four_way_state = CONNECTION_STATE_FIN_1_IN; }
              break;
            case CONNECTION_STATE_FIN_1_OUT:
              if (FIN) { tempEntry->four_way_state = CONNECTION_STATE_FIN_2_IN; }
              break;
            case CONNECTION_STATE_FIN_2_OUT:
              if (ACK) {
                deleteEntry(dest_ip, dest_port);
                port_used[dest_port-10000] = 0;
              }
              break;
            default:
              printf("four_way_state error\n");

          }
        }

        printList();

        // accept
        return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, data_len, payload);
      } else {
        // no match port found, drop
        printf("no match port found, drop\n");
        printList();
        return nfq_set_verdict(qh, nfq_id, NF_DROP, 0, NULL);
      }

    } else {
      printf("out bound packet\n");
      temp.s_addr = iph->saddr;
      printf("From %s:%d ", (char*)inet_ntoa(temp), source_port);
      temp.s_addr = iph->daddr;
      printf("to %s:%d\n", (char*)inet_ntoa(temp), dest_port);
      printf("check is there entry in nat table\n");
      tempEntry = (struct Entry*)find(source_ip, source_port);

      if (tempEntry != NULL) {
        // translation step is at the last
        printf("Entry found\n");
        // if it is rst packet, delete the entry
        wan_ip = tempEntry->wan->ip;
        wan_port = tempEntry->wan->port;
        if (RST) {
          port_used[tempEntry->wan->port-10000] = 0;
          deleteEntry(source_ip, source_port);
        } else {
          // check four way hand shake state
          switch (tempEntry->four_way_state) {
            case CONNECTION_STATE_NORMAL:
              if (FIN) { tempEntry->four_way_state = CONNECTION_STATE_FIN_1_OUT; }
              break;
            case CONNECTION_STATE_FIN_1_IN:
              if (FIN) { tempEntry->four_way_state = CONNECTION_STATE_FIN_2_OUT; }
              break;
            case CONNECTION_STATE_FIN_2_IN:
              if (ACK) {
                port_used[tempEntry->wan->port-10000] = 0;
                deleteEntry(source_ip, source_port);
              }
              break;
            default:
              printf("four_way_state error\n");
          }
        }

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
          wan_port = tcpfindport();
          if (wan_port == -1) {
            printf("no available port\n");
            exit(-1);
          }
          wan->port = wan_port;
          struct IP_PORT *lan = (struct IP_PORT*) malloc(sizeof(struct IP_PORT));
          lan->ip = source_ip;
          lan->port = source_port;

          printf("insert new entry\n");
          insertFirst(wan, lan);


        } else {
          // not a SYN packet, drop
          printf("not a SYN packet, drop\n");
          printList();
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
      return nfq_set_verdict(qh, nfq_id, NF_ACCEPT, data_len, payload);

    }
  } else {
    // Others protocol, drop
    printf("Others protocol, drop\n");
    printList();
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
    fprintf(stderr, "Usage: %s <public ip> <internal ip> <subnet mask>\n", argv[0]);
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


  while ((len = recv(fd, buf, sizeof(buf), 0)) && len >= 0) {
    printf("nfq_handle_packet\n");
    nfq_handle_packet(h, buf, len);

  }

  printf("unbinding from queue 0\n");
  nfq_destroy_queue(qh);

  nfq_close(h);

  return 0;

}
