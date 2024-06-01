#include "image.h"
#include "block.h"
#include "free.h"
#include <unistd.h>
#include <stdio.h>

int bwrite_error_flag = 0;

unsigned char *bread(int block_num, unsigned char *block){
    // Find the block offset using block number and size
    int offset = block_num * BLOCK_SIZE;
    // Seek to the block offset of the image file
    // ref: https://man7.org/linux/man-pages/man2/lseek.2.html
    lseek(image_fd, offset, SEEK_SET);
    // Read the block from the image file
    // ref: https://man7.org/linux/man-pages/man2/read.2.html
    read(image_fd, block, BLOCK_SIZE);
    return block;
}

void bwrite(int block_num, unsigned char *block){
    // Find the block offset using block number and size
    int offset = block_num * BLOCK_SIZE;
    // Seek to the block offset of the image file
    lseek(image_fd, offset, SEEK_SET);
    // Write the block to the image file
    // ref: https://man7.org/linux/man-pages/man2/write.2.html
    write(image_fd, block, BLOCK_SIZE);

    if (bwrite_error_flag == -1) {
        perror("bwrite failed");
    }
}

int alloc(void){
    unsigned char block[BLOCK_SIZE];
    bread(FREE_BLOCK, block);
    int free_block = find_free(block);
    if (free_block != -1) {
        set_free(block, free_block, 1);
        bwrite(FREE_BLOCK, block);
    }
    return free_block;
}