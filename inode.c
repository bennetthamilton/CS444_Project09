#include "inode.h"
#include "free.h"
#include "block.h"
#include "pack.h"
#include <stdio.h>

static struct inode incore[MAX_SYSTEM_FILES] = {0};

struct inode *ialloc(void) {
    unsigned char block[BLOCK_SIZE];    // get block
    bread(INODE_BLOCK, block);          // read block
    
    int inode_num = find_free(block);
    if (inode_num == -1) {
        return NULL;
    }

    set_free(block, inode_num, 1);

    // Initialize inode: 
    // Set the size, owner ID, permissions, and flags to 0.
    struct inode *in = incore_find(inode_num);
    in->size = 0;
    in->owner_id = 0;
    in->permissions = 0;    

    // Set all the block pointers to 0
    for (int i = 0; i < INODE_PTR_COUNT; i++) {
        in->block_ptr[i] = 0;
    }
    // Set the inode_num field to the inode number
    in->inode_num = inode_num;

    // Save the inode to disk
    write_inode(in);

    // Return the inode ptr
    return in;
}

struct inode *iget(int inode_num){
    struct inode *in = incore_find(inode_num);
    if (in == NULL) {               // if inode not found in incore
        in = incore_find_free();    // find free inode in incore
        if (in == NULL) {           // if no free inode in incore
            return NULL;            // return NULL
        }
        in->inode_num = inode_num;  // set inode number
        in->ref_count = 1;          // set ref_count to 1
        read_inode(in, inode_num);  // read inode
    } else {                        // if inode found in incore
        in->ref_count++;            // increment ref_count
    }
    return in;                      // return inode
}

void iput(struct inode *in){
    in->ref_count--;            // decrement ref_count
    if (in->ref_count == 0) {   // if ref_count is 0
        write_inode(in);        // write inode to
    }
}

struct inode *incore_find_free(void) {
    // find free inode in incore
    for (int i = 0; i < MAX_SYSTEM_FILES; i++) {
        if (incore[i].ref_count == 0) { // if ref_count is 0, then it is free
            return &incore[i];
        }
    }
    return NULL; // return NULL if not found
}

struct inode *incore_find(unsigned int inode_num) {
    // find inode in incore by inode number
    for (int i = 0; i < MAX_SYSTEM_FILES; i++) {
        if ((incore[i].ref_count =! 0) && (incore[i].inode_num == inode_num)) {
            return &incore[i];
        }
    }
    return NULL; // return NULL if not found
}

void incore_free_all(void) {
    for (int i = 0; i < MAX_SYSTEM_FILES; i++) {
        incore[i].ref_count = 0;
    }
}

void read_inode(struct inode *in, int inode_num){
    unsigned char block[BLOCK_SIZE];
    int block_num = inode_num / INODES_PER_BLOCK + INODE_FIRST_BLOCK;
    int block_offset = inode_num % INODES_PER_BLOCK;
    int block_offset_bytes = block_offset * INODE_SIZE;
    
    // read block
    bread(block_num, block);
    // unpack into inode
    in->size = read_u32(block + block_offset_bytes);
    in->owner_id = read_u16(block + block_offset_bytes + 4);
    in->permissions = read_u8(block + block_offset_bytes + 6);
    in->flags = read_u8(block + block_offset_bytes + 7);
    in->link_count = read_u8(block + block_offset_bytes + 8);
    for (int i = 0; i < INODE_PTR_COUNT; i++) {
        in->block_ptr[i] = read_u16(block + block_offset_bytes + 9 + i * 2);
    }
}

void write_inode(struct inode *in){
    unsigned char block[BLOCK_SIZE];
    int inode_num = in->inode_num;
    int block_num = inode_num / INODES_PER_BLOCK + INODE_FIRST_BLOCK;
    int block_offset = inode_num % INODES_PER_BLOCK;
    int block_offset_bytes = block_offset * INODE_SIZE;

    bread(block_num, block);

    write_u32(block + block_offset_bytes, in->size);
    write_u16(block + block_offset_bytes + 4, in->owner_id);
    write_u8(block + block_offset_bytes + 6, in->permissions);
    write_u8(block + block_offset_bytes + 7, in->flags);
    write_u8(block + block_offset_bytes, in->link_count);
    for (int i = 0; i < INODE_PTR_COUNT; i++) {
        write_u16(block + block_offset_bytes + 9 + i * 2, in->block_ptr[i]);
    }

    bwrite(block_num, block);
}