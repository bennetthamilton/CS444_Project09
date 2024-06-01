#include "image.h"
#include <fcntl.h>
#include <unistd.h>

int image_fd;

int image_open(char *filename, int truncate){
    // Open image file, or create if doesn't exist, truncate it to 0 if truncate true
    image_fd = open(filename, O_RDWR | O_CREAT | (truncate ? O_TRUNC : 0), 0600);
    return image_fd;
} 

int image_close(void){
    // Close image file
    return close(image_fd);
}