struct IP_PORT;
struct Entry;
// struct Entry* hashArray[SIZE];
// struct Entry* dummyEntry;
// struct Entry* entry;

// int hashCode(int key);
struct Entry *search(int key);
void insert(int key, struct IP_PORT *wan, struct IP_PORT *lan);
struct Entry* delete(struct Entry* entry);
void display();
