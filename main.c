#include <stdio.h>
#include <stdlib.h>
#include "table.c"


int main() {
   struct Entry *dummy = (struct Entry*) malloc(sizeof(struct Entry));
   struct IP_PORT *wan = (struct IP_PORT*) malloc(sizeof(struct IP_PORT));
   wan->ip = 100;
   wan->port = 1000;
   struct IP_PORT *lan = (struct IP_PORT*) malloc(sizeof(struct IP_PORT));
   lan->ip = 200;
   lan->port = 2000;

   insertFirst(wan,lan);
   dummy = find(wan->ip, wan->port);

   printf("data found, wan ip: %d, wan port: %d\n", dummy->wan->ip, dummy->wan->port);

   //print list
  //  printList();
}
