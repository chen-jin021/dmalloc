#define DMALLOC_DISABLE 1
#include "dmalloc.hh"
#include <cassert>
#include <cstring>
#include <math.h>
#include <unordered_map>

// define global variable to hold
struct dmalloc_stats state = {
    0,0,0,0,0,0,(uintptr_t) UINT64_MAX, (uintptr_t) WINT_MIN,
};

// define a struct for storing metadata of each block
struct metadata {
    size_t size;
    int free; // if it's 0x07654321
    char* file;
    long line;
};

// global data to store valid and freed pointer
std::unordered_map<uintptr_t, struct metadata> map;
// global data to store boundary detection
const char* secret = "secret";
size_t padding = 480; // 500 bytes of padding on both sides of memory block


/**
 * dmalloc(sz,file,line)
 *      malloc() wrapper. Dynamically allocate the requested amount `sz` of memory and 
 *      return a pointer to it 
 * 
 * @arg size_t sz : the amount of memory requested 
 * @arg const char *file : a string containing the filename from which dmalloc was called 
 * @arg long line : the line number from which dmalloc was called 
 * 
 * @return a pointer to the heap where the memory was reserved
 */
void* dmalloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // Your code here.
    // validate check
    // printf("%ld is the max and the input is: %ld\n", sizeof(size_t), sz);
    if(sz > pow(2, 32) - 1){
        state.nfail++;
        state.fail_size += sz;
        return NULL; // failed dmalloc
    }
    // pointer to where the metadata is at
    void* meta_ptr = base_malloc(sz + sizeof(struct metadata) + sizeof(secret) + 2 * padding);

    // check if valid
    if(meta_ptr == NULL){
        state.nfail++;
        state.fail_size += sz;
        return NULL; // failed dmalloc
    }

    struct metadata cur_meta = {sz, 0x07654321, (char*) file, (long) line};
    // assign the metadata
    struct metadata* meta = (struct metadata*) ((char*)meta_ptr + padding);
    *meta = cur_meta;
    void* payload_ptr = (char*) meta + sizeof(struct metadata);
    
    // add meta_ptr to the set
    map.insert({(uintptr_t)meta, cur_meta});
    // put the secret at the end of memory block
    char* secret_ptr = (char*)((char*)payload_ptr + sz);
    strcpy(secret_ptr, secret);
    
    // assign the payload
    // update the statistics
    state.nactive++; // active allocation + 1
    state.active_size += sz;
    state.ntotal++;
    state.total_size += sz;

    // check heap_min and heap_max
    if(state.heap_min > (uintptr_t)payload_ptr){
        state.heap_min = (uintptr_t)payload_ptr;
    }
    if(state.heap_max < (uintptr_t)((char*)payload_ptr + sz)){
        state.heap_max = (uintptr_t)payload_ptr+sz;
    }
    return payload_ptr;
}

/**
 * dfree(ptr, file, line)
 *      free() wrapper. Release the block of heap memory pointed to by `ptr`. This should 
 *      be a pointer that was previously allocated on the heap. If `ptr` is a nullptr do nothing. 
 * 
 * @arg void *ptr : a pointer to the heap 
 * @arg const char *file : a string containing the filename from which dfree was called 
 * @arg long line : the line number from which dfree was called 
 */
void dfree(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // Your code here.
    if(ptr == NULL){
        return;
    }
    // check valid ptr
    if((uintptr_t)ptr < state.heap_min || (uintptr_t)ptr > state.heap_max){
        fprintf(stderr, "MEMORY BUG: test %s.cc:%ld: invalid free of pointer %p, not in heap\n",file, line, ptr);
        abort();
    }
    struct metadata* meta_ptr = (struct metadata*) ((char*)ptr - sizeof(struct metadata));
    // check if allocated
    if(map.find((uintptr_t) meta_ptr) == map.end()){
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);
        // loop through the map to find the correct region
        uintptr_t target = (uintptr_t) meta_ptr;
        for (auto ele : map){
            uintptr_t meta_addr = ele.first;
            struct metadata data = ele.second;
            if(meta_addr > target){
                continue;
            }
            if(meta_addr + sizeof(struct metadata) + data.size > target){
                uintptr_t payload_ptr = (uintptr_t) ptr;
                uintptr_t map_ptr = meta_addr + sizeof(struct metadata);

                uintptr_t gap = payload_ptr - map_ptr;
                fprintf(stderr, "%s:%ld: %p is %ld bytes inside a %ld byte region allocated here\n", file, data.line, ptr, gap, data.size);
            }
        }
        abort();
    }
    struct metadata block_info = map[(uintptr_t) meta_ptr];
    // double free
    if(block_info.free == 0 ||meta_ptr->free != 0x07654321){
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n", file, line, ptr);
        abort();
    }

    // check for overwritten mem block
    char* secret_ptr = (char*)((char*)ptr + meta_ptr->size);
    if(strcmp(secret_ptr, "secret") != 0) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n", file, line, ptr);
        abort();
    }
    // update the statistics
    state.nactive--;
    state.active_size -= meta_ptr->size;
    // update the metadata
    meta_ptr->free = 0x0;
    meta_ptr->size = 0;
    // reset secret
    *secret_ptr = 0x0;
    // change the map free to 0
    map[(uintptr_t)meta_ptr].free = 0;
    map[(uintptr_t)meta_ptr].size = 0;
    base_free((void*) meta_ptr);
}

/**
 * dcalloc(nmemb, sz, file, line)
 *      calloc() wrapper. Dynamically allocate enough memory to store an array of `nmemb` 
 *      number of elements with wach element being `sz` bytes. The memory should be initialized 
 *      to zero  
 * 
 * @arg size_t nmemb : the number of items that space is requested for
 * @arg size_t sz : the size in bytes of the items that space is requested for
 * @arg const char *file : a string containing the filename from which dcalloc was called 
 * @arg long line : the line number from which dcalloc was called 
 * 
 * @return a pointer to the heap where the memory was reserved
 */
void* dcalloc(size_t nmemb, size_t sz, const char* file, long line) {
    // check valid
    if(nmemb > pow(2, 31) - 1 /sz){
        state.nfail++;
        state.fail_size += sz;
        return NULL; // failed dmalloc
    }

    void* ptr = dmalloc(nmemb * sz, file, line);
    if (ptr) {
        memset(ptr, 0, nmemb * sz);
    }
    return ptr;
}

/**
 * get_statistics(stats)
 *      fill a dmalloc_stats pointer with the current memory statistics  
 * 
 * @arg dmalloc_stats *stats : a pointer to the the dmalloc_stats struct we want to fill
 */
void get_statistics(dmalloc_stats* stats) {
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(dmalloc_stats));
    // Your code here.
    stats->nactive = state.nactive;
    stats->active_size = state.active_size;
    stats->ntotal = state.ntotal;
    stats->total_size = state.total_size;
    stats->nfail = state.nfail;
    stats->fail_size = state.fail_size;
    stats->heap_min = state.heap_min;
    stats->heap_max = state.heap_max;
}

/**
 * print_statistics()
 *      print the current memory statistics to stdout       
 */
void print_statistics() {
    dmalloc_stats stats;
    get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}

/**  
 * print_leak_report()
 *      Print a report of all currently-active allocated blocks of dynamic
 *      memory.
 */
void print_leak_report() {
    // // Your code here.
    for (auto ele : map) {
        // printf("meta_pointer is: %ld\n",ele.first);
        struct metadata meta_data = ele.second;
        // cout << ele.first << "   " << ele.second << endl;
        // printf("%lx and the file name %s\n", ele.first, ele.second.file);
        // printf("meta_pointer file name is: %s\n",ele.first->file);
        if (meta_data.size != 0 && meta_data.free != 0x0) { // allocated but not freed
            fprintf(stdout, "LEAK CHECK: %s:%ld: allocated object %p with size %zu\n",
                    meta_data.file, (long) meta_data.line, (void*)((char*)ele.first + sizeof(struct metadata)), meta_data.size);
        }
    }
}

/**
 * extra credit
 * drealloc(ptr, sz, file, line)
 * Reallocate the dynamic memory pointed to by `ptr` to hold at least
 * `sz` bytes, returning a pointer to the new block. If `ptr` is
 * `nullptr`, behaves like `dmalloc(sz, file, line)`. If `sz` is 0,
 * behaves like `dfree(ptr, file, line)`. The allocation request
 * was at location `file`:`line`.
*/
void* drealloc(void* ptr, size_t sz, const char* file, long line){
    if(ptr == NULL){
        return dmalloc(sz, file, line);
    }
    if(sz == 0){
        dfree(ptr, file, line);
        return NULL;
    }

    // check valid ptr
    if ((uintptr_t)ptr < state.heap_min || (uintptr_t)ptr > state.heap_max) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid realloc of pointer %p, not in heap\n", file, line, ptr);
        abort();
    }
    // check if there is an allocated ptr
    struct metadata* meta_ptr = (struct metadata*)((char*)ptr - sizeof(struct metadata));
    if (map.find((uintptr_t)meta_ptr) == map.end()) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid pointer %p, not allocated\n", file, line, ptr);
        abort();
    }
    struct metadata block_info = map[(uintptr_t)meta_ptr];
    // if current block already fits
    if (sz <= block_info.size ) {
        block_info.size = sz; // re-allocate the size
        return ptr;
    }
    // otherwise
    void* new_ptr = dmalloc(sz, file, line);
    if (new_ptr == NULL) {
        return NULL;
    }
    memcpy(new_ptr, ptr, block_info.size);
    dfree(ptr, file, line);
    return new_ptr;
}