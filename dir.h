#ifndef DIR
#define DIR

#define ENTRY_SIZE 32   // 2 bytes for inode number, 16 bytes for name, 14 bytes reserved

struct directory {
    struct inode *in;
    unsigned int offset;
};

struct directory_entry {
    unsigned int inode_num;
    char name[16];
};

struct directory *directory_open(int inode_num);
int directory_get(struct directory *dir, struct directory_entry *ent);
void directory_close(struct directory *d);
void ls(void);
void mkfs(void);

#endif