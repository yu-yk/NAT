#ifndef __TABLE__

#define __TABLE__

struct IP_PORT {
  uint32_t ip;
  uint16_t port;
};
// struct Entry;
struct Entry {
  struct Entry *next; // use port number to be the key
  struct IP_PORT *wan;
  struct IP_PORT *lan;
  int four_way_state;
};
// struct Entry* hashArray[SIZE];
// struct Entry* dummyEntry;
// struct Entry* entry;

// int hashCode(int key);
struct Entry *search(int key);
void insert(int key, struct IP_PORT *wan, struct IP_PORT *lan);
struct Entry *deleteEntry(unsigned int ip, unsigned int port);
void display();

#endif
