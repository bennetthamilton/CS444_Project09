## How To Run
First compile the program using `make` (or `make pristine` to clear previous files in the process).

Run: `./main`

## Files
    - `image.c`: Manages image file.
    - `block.c`: Read and write from a block.
    - `testfs.c`: Tests _block.c_ and _image.c_.
    - `free.c`: Frees bits.
    - `inode.c`: Allocates space for the inode.
    - `pack.c`: Reads and Writes unsigned numbers of different numbers of bits/bytes.
    - `dir.c`: Manages Directory.

## Functions

### Block.c
    - `bread`: Finds the block offset based on a block number and reads from the image file.
    - `bwrite`: Finds the block offset based on a block number and writes to the image file.
    - `alloc`: Allocates a block of data.
### image.c
    - `image_open`: Opens a image file given a file name.
    - `image_close`: Closes the file image.
### testfs.c
    - test_image_open: tests _image.c_ image_open function.
    - test_image_open: tests _image.c_ image_close function.
    - test_block_bread: tests bread.
    - test_block_bwrite: tests bwrite.
### free.c
    - set_free: Sets a bit to free (0).
    - find_free: Finds the first free fit.
### inode.c
    - ialloc: Allocates space for the inode block.
    - incore_find_free: Finds the first free in-core  inode in the incore array and returns a pointer to it.
    - incore_find: Finds an in-core inode recod in the incore aaray by the inode number.
    - incore_free_all:Sets the ref_count to all in-core nodes to 0.
### pack.c
    - read_u_32: Reads an unsigned 32-bit integer from a buffer.p
    - read_u16: Reads an unsigned 16-bit integer from a buffer.
    - read_u8:  Reads an unsigned 8-bit integer from a buffer.
    - write_u32: Writes an unsigned 32-bit integer to a buffer.
    - write_u16: Writes an unsigned 16-bit integer to a buffer.
    - write_u8: Writes an unsigned 8-bit integer to a buffer.

### dir.c
    - directory_open: Opens a directory for reading based on the inode number provided.
    - directory_get: Reads the next directory entry from the directory `dir` into `entry` and returns -1 if it fails.
    - directory_close: Closes directory.
    - ls: Lists contents in current directory.
    - mkfs: Initializes new filesystem.
    
