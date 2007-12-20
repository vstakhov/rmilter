#ifndef RADIX_H
#define RADIX_H

#include <sys/types.h>

#define RADIX_NO_VALUE   (uintptr_t) -1

typedef struct radix_node_s  radix_node_t;

struct radix_node_s {
    radix_node_t *right;
    radix_node_t *left;
    radix_node_t *parent;
    uintptr_t value;
};


typedef struct {
    radix_node_t  *root;
    radix_node_t  *free;
    char              *start;
    size_t             size;
} radix_tree_t;


radix_tree_t *radix_tree_create();
int radix32tree_insert(radix_tree_t *tree,
    uint32_t key, uint32_t mask, uintptr_t value);
int radix32tree_delete(radix_tree_t *tree,
    uint32_t key, uint32_t mask);
uintptr_t radix32tree_find(radix_tree_t *tree, uint32_t key);


#endif
