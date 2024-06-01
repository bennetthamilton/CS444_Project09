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

// The namei() function does a variety of things:

// If the path is /, it returns the root directory's in-core inode.
// If the path is /foo, it returns foo's in-core inode.
// If the path is /foo/bar, it returns bar's in-core inode.
// If the path is invalid (i.e. a component isn't found), it returns NULL.
// For this first part, simply implement namei() so it just returns the in-core inode for the root directory, /. The other bits can wait until later.

// You'll want to use iget() with the root directory's inode number to get this information. (It's OK to #define ROOT_INODE_NUM 0 and use that.)

struct inode *namei(char *path){

    if (strcmp(path, "/") == 0) {
        return iget(ROOT_INODE);
    }

    return NULL;
}

int directory_make(char *path){
    // Check if it starts with /
    if (path[0] == '/'){
        return -1;
    }

    // Find directory path that will contain the new directory
    char *parent_path = strdup(path);

    // Find new directory name from the path
    char *new_dir_name = strrchr(path, '/');
    if (new_dir_name == NULL) {
        free(parent_path);
        return -1;
    }
    *new_dir_name = '\0';
    new_dir_name++;

    // Find the inode for the parent that will hold the new entry
    struct inode *parent_in = namei(parent_path);
    free(parent_path);
    if (parent_in == NULL) {
        return -1;
    }

    // Create a new inode for the new directory
    struct inode *in = ialloc();
    if (in == NULL) {
        iput(parent_path);
        return -1;
    }

    // Create a new data block for the new directory entries
    int block_num = alloc();
    if (block_num == -1) {
        iput(in);
        iput(parent_in);
        return -1;
    }

    // Initialize the new directory's inode with proper size, flags, and block_ptr[0]
    in->size = 2 * ENTRY_SIZE;
    in->flags = 2;
    in->block_ptr[0] = block_num;

    // Create a new block-sized array for the new directory data block and initialize it . and .. files
    unsigned char block[BLOCK_SIZE];
    memset(block, 0, BLOCK_SIZE);
    // . should contain the new directory's inode number
    write_u16(block, in->inode_num);
    strcpy((char *)(block + 2), ".");
    // .. should contain the parent directory's inode number
    write_u16(block + ENTRY_SIZE, parent_in->inode_num);
    strcpy((char *)(block + ENTRY_SIZE + 2), "..");

    // Write the new directory data block to disk
    bwrite(block_num, block);

    // From the parent directory inode, find the block that will contain the new directory entry 
    int parent_block_index = parent_in->size / BLOCK_SIZE;
    int parent_block_offset = parent_in->size % BLOCK_SIZE;

    // Read that block into memory unless you're creating a new one (bread), and add the new directory entry into it
    unsigned char parent_block[BLOCK_SIZE];
    if (parent_block_offset == 0) {
        parent_in->block_ptr[parent_block_index] = alloc();
        bwrite(parent_in->block_ptr[parent_block_index], parent_block);
    } else {
        bread(parent_in->block_ptr[parent_block_index], parent_block);
    }

    // Write the block back to disk (bwrite)
    bwrite(parent_in->block_ptr[parent_block_index], parent_block);

    // Update the parent directory's inode to reflect the new directory entry
    parent_in->size += ENTRY_SIZE;
    write_inode(parent_in);

    // Release the new directory's in-core inode (iput)
    iput(in);

    // Release the parent directory's in-core inode (iput)
    iput(parent_in);

}