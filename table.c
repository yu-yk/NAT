#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>


struct IP_PORT {
  unsigned int ip;
  unsigned int port;
};

struct Entry {
  struct Entry *next; // use port number to be the key
  struct IP_PORT *wan;
  struct IP_PORT *lan;
};

struct Entry *head = NULL;
struct Entry *current = NULL;

//insert link at the first location
void insertFirst(struct IP_PORT *wan, struct IP_PORT *lan) {
   //create a link
   struct Entry *entry = (struct Entry*) malloc(sizeof(struct Entry));

   entry->wan = wan;
   entry->lan = lan;

   //point it to old first node
   entry->next = head;

   //point first to new first node
   head = entry;
}

//delete first item
struct Entry* deleteFirst() {

   //save reference to first link
   struct Entry *tempLink = head;

   //mark next to first link as first
   head = head->next;

   //return the deleted link
   return tempLink;
}

//is list empty
bool isEmpty() {
   return head == NULL;
}

int length() {
   int length = 0;
   struct Entry *current;

   for(current = head; current != NULL; current = current->next) {
      length++;
   }

   return length;
}

//find a link with given key
struct Entry* find(unsigned int ip, unsigned int port) {

   //start from the first link
   struct Entry* current = head;

   //if list is empty
   if(head == NULL) {
      return NULL;
   }

   //navigate through list
   while((current->wan->ip!=ip || current->wan->port!=port) && (current->lan->ip!=ip || current->lan->port!=port)) {

      //if it is last node
      if(current->next == NULL) {
         return NULL;
      } else {
         //go to next link
         current = current->next;
      }
   }

   //if data found, return the current Link
   return current;
}

//delete a link with given key
struct Entry* delete(unsigned int ip, unsigned int port) {

   //start from the first link
   struct Entry* current = head;
   struct Entry* previous = NULL;

   //if list is empty
   if(head == NULL) {
      return NULL;
   }

   //navigate through list
   while((current->wan->ip!=ip || current->wan->port!=port) && (current->lan->ip!=ip || current->lan->port!=port)) {

      //if it is last node
      if(current->next == NULL) {
         return NULL;
      } else {
         //store reference to current link
         previous = current;
         //move to next link
         current = current->next;
      }
   }

   //found a match, update the link
   if(current == head) {
      //change first to point to next link
      head = head->next;
   } else {
      //bypass the current link
      previous->next = current->next;
   }

   return current;
}

//display the list
void printList() {
   struct Entry *ptr = head;
   printf("\n[ ");

   //start from the beginning
   while(ptr != NULL) {
      printf("(%d,%d) ",ptr->wan->ip,ptr->wan->port);
      printf("(%d,%d) ",ptr->lan->ip,ptr->lan->port);
      ptr = ptr->next;
   }

   printf(" ]");
}
