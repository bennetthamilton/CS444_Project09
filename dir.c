#include "dir.h"
#include "block.h"
#include "inode.h"
#include "pack.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct directory *directory_open(int inode_num){
    // Use iget() to get the inode for this file
    struct inode *in = iget(inode_num);

    // If it fails, directory_open() should return NULL
    if (in == NULL) {
        return NULL;
    }

    // malloc() space for a new struct directory
    struct directory *dir = malloc(sizeof(struct directory));

    // Set the inode and offset fields of the struct directory
    dir->in = in;
    dir->offset = 0;

    // Return the pointer to the struct directory
    return dir;
}

int directory_get(struct directory *dir, struct directory_entry *ent){

    if (dir->offset >= dir->in->size) {
        return -1;
    }

    int block_index = dir->offset / BLOCK_SIZE;
    int block_offset = dir->offset % BLOCK_SIZE;

    unsigned char block[BLOCK_SIZE];
    int block_num = dir->in->block_ptr[block_index];
    bread(block_num, block);

    unsigned char *entry = block + block_offset;

    ent->inode_num = read_u16(entry);

    strncpy(ent->name, (char *)(entry + 2), 15);
    ent->name[15] = '\0';

    dir->offset += ENTRY_SIZE;

    return 0;
}

void directory_close(struct directory *d){
    iput(d->in);
    free(d);
}

void ls(void){
    struct directory *dir;
    struct directory_entry ent;

    dir = directory_open(0);

    while (directory_get(dir, &ent) != -1) {
        printf("%d %s\n", ent.inode_num, ent.name);
    }

    directory_close(dir);
}

void mkfs(void){
    // Get new inode with ialloc
    int root = 0;
    struct inode *in = ialloc();

    in->inode_num = root;

    // Call alloc to get a new data block
    int block_num = alloc();

    // Initialize the inode returned from ialloc
    // flags = 2, size = byte size of directory (64 bytes, 2 entries), block_ptr[0] needs to point to the block we got from alloc
    in->flags = 2;
    in->size = 2 * ENTRY_SIZE;
    in->block_ptr[0] = block_num;

    // Make unsigned char block[BLOCK_SIZE] that you can populate with new directory data
    unsigned char block[BLOCK_SIZE];
    memset(block, 0, BLOCK_SIZE);

    // Add the directory entries
    // First entry: inode number of the directory itself, name is "."
    int inode_num = in->inode_num;
    write_u16(block, inode_num);
    strcpy((char *)(block + 2), ".");
    
    // Second entry: inode number of the parent directory, name is ".."
    write_u16(block + ENTRY_SIZE, in->inode_num);
    strcpy((char *)(block + ENTRY_SIZE + 2), "..");

    // Write the block to the disk with bwrite
    bwrite(block_num, block);

    // call iput() to write the new direcory inode out to disk and free up the in-core inode
    iput(in);
}