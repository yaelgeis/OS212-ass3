#include "kernel/types.h"
#include "kernel/stat.h"
#include "user.h"
#include "kernel/fs.h"


int main(int argc, char *argv[]){

    int PAGES = 18; 
    int PAGESIZE = 4096;

    printf("Allocating 18 pages\n");

    char *array = sbrk(PAGESIZE * PAGES);
    //put info
    for(int i = 0; i < PAGES; i++){
        array[i*PAGESIZE] = i;
    }
    print_metadata();
    printf("*Allocated 18 pages, 16 should be in physical memory and 2 should be in swap file*\n\n");

    //modifying
    for(int i=12; i < 16; i++)
        array[i*PAGESIZE] = i*4;

    printf("Modified 3 pages.\nNEW META DATA:");
    print_metadata();

    //get info
    for(int i=0; i< PAGES; i++){
        if (((i > 11 && i < 16) && (array[i*PAGESIZE] != i*4)) ||
            ((i < 12 || i > 15) && (array[i*PAGESIZE] != i))){
            printf("ERROR in page %d\n", i+1);
            exit(-1);
        }
        
    }
    #ifdef SCFIFO
    print_metadata();
    #endif
    printf("\nTest Passed.\n");
    exit(0);
}