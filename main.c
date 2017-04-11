#include <stdio.h>
#include <stdlib.h>
#include "table.c"


int main() {
   struct Entry* dummyEntry = (struct Entry*) malloc(sizeof(struct Entry));
   struct IP_PORT *wan = (struct IP_PORT*) malloc(sizeof(struct IP_PORT));
   wan->ip = 100;
   wan->port = 1000;
   struct IP_PORT *lan = (struct IP_PORT*) malloc(sizeof(struct IP_PORT));
   lan->ip = 200;
   lan->port = 2000;
   struct Entry* entry;


   insert(1, wan, lan);


   display();
  //  entry = search(1);
   //
  //  if(entry != NULL) {
  //     printf("Element found: %d\n", entry->data);
  //  } else {
  //     printf("Element not found\n");
  //  }
   //
  //  delete(entry);
  //  entry = search(37);
   //
  //  if(entry != NULL) {
  //     printf("Element found: %d\n", entry->data);
  //  } else {
  //     printf("Element not found\n");
  //  }
}
