#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define SIZE 100

struct IP_PORT {
  unsigned int ip;
  unsigned int port;
};

struct Entry {
  int key; // use port number to be the key
  struct IP_PORT *wan;
  struct IP_PORT *lan;
};

struct Entry* hashArray[SIZE];
struct Entry* dummyEntry;
struct Entry* entry;

int hashCode(int key) {
  return key % SIZE;
}

struct Entry *search(int key) {
  //get the hash
  int hashIndex = hashCode(key);

  //move in array until an empty
  while(hashArray[hashIndex] != NULL) {

    if(hashArray[hashIndex]->key == key)
    return hashArray[hashIndex];

    //go to next cell
    ++hashIndex;

    //wrap around the table
    hashIndex %= SIZE;
  }

  return NULL;
}

void insert(int key, struct IP_PORT *wan, struct IP_PORT *lan) {

  struct Entry *entry = (struct Entry*) malloc(sizeof(struct Entry));
  entry->key = key;
  entry->wan = wan;
  entry->lan = lan;

  //get the hash
  int hashIndex = hashCode(key);

  //move in array until an empty or deleted cell
  while(hashArray[hashIndex] != NULL && hashArray[hashIndex]->key != -1) {
    //go to next cell
    ++hashIndex;

    //wrap around the table
    hashIndex %= SIZE;
  }

  hashArray[hashIndex] = entry;
}

struct Entry* delete(struct Entry* entry) {
  int key = entry->key;

  //get the hash
  int hashIndex = hashCode(key);

  //move in array until an empty
  while(hashArray[hashIndex] != NULL) {

    if(hashArray[hashIndex]->key == key) {
      struct Entry* temp = hashArray[hashIndex];

      //assign a dummy item at deleted position
      hashArray[hashIndex] = dummyEntry;
      return temp;
    }

    //go to next cell
    ++hashIndex;

    //wrap around the table
    hashIndex %= SIZE;
  }

  return NULL;
}

void display() {
  int i = 0;

  for(i = 0; i<SIZE; i++) {

    if(hashArray[i] != NULL) {
      printf(" (%d,%d,%d)",hashArray[i]->key,hashArray[i]->wan->ip, hashArray[i]->wan->port);
      printf(" (%d,%d,%d)",hashArray[i]->key,hashArray[i]->lan->ip, hashArray[i]->lan->port);
    } else {
      printf(" ~~ ");
    }
  }

  printf("\n");
}
