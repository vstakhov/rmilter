#ifndef RADIX_H
#define RADIX_H

#include <sys/types.h>

#define RADIX_NO_VALUE   (unsigned char)-1

typedef struct radix_node_s  radix_node_t;

struct radix_node_s {
    radix_node_t *right;
    radix_node_t *left;
    radix_node_t *parent;
    unsigned char value;
};


typedef struct {
    radix_node_t  *root;
    char              *start;
    size_t             size;
} radix_tree_t;


radix_tree_t *radix_tree_create();
int radix32tree_insert(radix_tree_t *tree,
    uint32_t key, uint32_t mask, unsigned char value);
int radix32tree_delete(radix_tree_t *tree,
    uint32_t key, uint32_t mask);
unsigned char radix32tree_find(radix_tree_t *tree, uint32_t key);


#endif
