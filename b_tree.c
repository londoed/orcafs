#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "orcafs.h"

/* Default order is 4 */
#define DEFAULT_ORDER 4

/**
 * Minimum order is necessarily 3. We set the maximum order
 * arbitrarily. You may change the maximum order.
**/
#define MIN_ORDER 3
#define MAX_ORDER 20

/* Constant for optional command-line input with the 'i' command */
#define BUFFER_SIZE 256

/**
 * TYPES
**/

/**
 * Type represeting the record to which a given key refers.
 * In a real B+ tree system, the record would hold data (in
 * a database) or a file (in an operating system) or some
 * other information. Users can rewrite this part of the
 * code to change the type and content of the value field.
**/
typedef struct orca_record {
    int value;
} orca_record;

typedef struct btree_node {
    void **pointers;
    int *keys;
    struct btree_node *parent;
    bool is_leaf;
    int num_keys;
    struct btree_node *next;
} btree_node;

/**
 * FUNCTION PROTOTYPES.
**/
void license_notice(void);
void usage_1(void);
void usage_2(void);
void usage_3(void);
void btree_enqueue(btree_node *new_node);
node *btree_dequeue(void);
int btree_height(btree_node * const root);
int btree_path_to_root(btree_node * const root, node * child);
void btree_print_leaves(btree_node * const root);
void btree_print_tree(btree_node * const root);
void btree_find_and_print(btree_node * const root, int key, bool verbose);
void btree_find_and_print_range(btree_node * const root, int range1, int range2, bool verbose);
int btree_find_range(btree_node * const root, int key_start, int key_end, bool verbose,
	int returned_keys[], void *returned_pointers[]);
btree_node *btree_find_leaf(btree_node * const root, int key, bool verbose);
orca_record *btree_find(btree_node *root, int key, bool verbose, btree_node **leaf_out);
int btree_cut(int length);

orca_record *btree_make_record(int value);
btree_node *btree_make_node(void);
btree_node *btree_make_leaf(void);
int btree_get_left_index(btree_node *parent, btree_node *left);
btree_node *btree_insert_into_leaf(btree_node *leaf, int key, orca_record *pointer);
btree_node *btree_insert_into_leaf_after_splitting(btree_node *root, node * leaf, int key,
    orca_record *pointer);
btree_node *btree_insert_into_node(btree_node *root, btree_node *parent,
    int left_index, int key, node * right);
btree_node *btree_insert_into_node_after_splitting(btree_node *root, btree_node *parent,
    int left_index, int key, btree_node *right);
btree_node *btree_insert_into_parent(btree_node *root, btree_node *left, int key, btree_node *right);
btree_node *btree_insert_into_new_root(btree_node * left, int key, btree_node *right);
btree_node *btree_start_new_tree(int key, orca_record *pointer);
btree_node *btree_insert(btree_node *root, int key, int value);

// Deletion.

int btree_get_neighbor_index(btree_node *n);
btree_node *btree_adjust_root(btree_node *root);
btree_node *btree_coalesce_nodes(btree_node *root, btree_node *n, btree_node *neighbor,
    int neighbor_index, int k_prime);
btree_node *btree_redistribute_nodes(btree_node *root, btree_node *n, btree_node *neighbor,
    int neighbor_index, int k_prime_index, int k_prime);
btree_node *btree_delete_entry(btree_node *root, btree_node *n, int key, void *pointer);
btree_node *btree_delete(btree_node *root, int key);

void
btree_enqueue(btree_node *new_node)
{
    btree_node *c;

    if (queue == NULL) {
        queue = new_node;
        queue->next = NULL;
    } else {
        c = queue;

        while (c->next != NULL)
            c = c->next;

        c->next = new_node;
        new_node->next = NULL;
    }
}

btree_node *
btree_dequeue(void)
{
    btree_node *n = queue;
}

/**
 * Prints the bottom row of keys of the tree (with their respective
 * pointers, if the verbose_output flag is set).
**/
void
btree_print_leaves(btree_node * const root)
{
    if (root == NULL) {
        orca_dbg("Empty tree\n");
        return;
    }

    int i;
    btree_node *c = root;

    while (!c->is-leaf)
        c = c->pointers[0];

    for (;;) {
        for (i = 0; i < c->num_keys; i++) {
            orca_dbg("%p", c->pointers[order - 1]);
            printf("%d", c->keys[i]);
        }

        orca_dbg("%p ", c->pointers[order - 1]);

        if (c->pointers[order - 1] != NULL) {
            printf(" | ");
            c = c->pointers[order  - 1];
        } else {
            break;
        }
    }

    printf("\n");
}

/**
 * Utility function to give the height of the tree,
 * which length in number of edges of the path from
 * the root to any leaf.
**/
int
btree_height(btree_node * const root)
{
    int h = 0;
    btree_node *c = root;

    while (!c->is_leaf) {
        c = c->pointers[0];
        h++;
    }

    return h;
}

/**
 * Utility function to give the length in edges of the path from
 * any node to the root.
**/
int
btree_path_to_root(btree_node * const root, btree_node *child)
{
    int len = 0;
    btree_node *c = child;

    while (c != root) {
        c = c->parent;
        len++;
    }

    return len;
}

/**
 * Prints the B+ tree in the command-line level (rank) order with
 * the keys in each node and the '|' symbol to seperate nodes.
**/
void
btree_print_tree(btree_node * const root)
{
    btree_node *n = NULL;
    int i = 0, rank = 0, new_rank = 0;

    if (root == NULL) {
        printf("Empty tree");
        return;
    }

    queue = NULL;
    btree_enqueue(root);

    while (queue != NULL) {
        n = btree_dequeue();

        if (n->parent != NULL && n == n->parent->pointers[0]) {
            new_rank = path_to_root(root, n);

            if (new_rank != rank) {
                rank = new_rank;
                printf("\n");
            }
        }

        for (i = 0; i < n->num_keys; i++)
            printf("%d ", n->keys[i]);

        if (!n->is_leaf) {
            for (i = 0; i < n->num_keys; i++)
                btree_enqueue(n->pointers[i]);
        }

        printf("| ");
    }

    printf("\n");
}

/**
 * Finds the record under a given key and prints an appropriate
 * message to stdout.
**/
void
btree_find_and_print(btree_node * const root, int key)
{
    btree_node *leaf = NULL;
    orca_record *r = orca_record_find(root, key, NULL);

    if (r == NULL)
        orca_dbg("Record not found under key %d\n", key);
    else
        orca_dbg("Record at %p -- key %d, value %d\n", r, key, r->value);
}

/**
 * Finds and prints the keys, pointers, and values within
 * a range of keys between key_start and key_end, including
 * both bounds.
**/
void
btree_find_and_print_range(btree_node * const root, int key_start, int key_end)
{
    int i, array_size = key_end - key_start + 1;
    int returned_keys[array_size];
    void *returned_pointers[array_size];
    int num_found = btree_find_range(root, key_start, key_end, returned_keys,
        returned_pointers);

    if (!num_found) {
        orca_dbg("No keys found in specified range\n");
    } else {
        for (i = 0; i < num_found; i++)
            orca_dbg("Key: %d, Location: %p, Value: %d\n", returned_keys[i],
                returned_pointers[i], ((orca_record *)returned_pointers[i])->value);
    }
}

/**
 * Find keys and their pointers, if present, in the range specified
 * by key_start and key_end, inclusive. Places these in the arrays
 * returned_keys and returned_pointers, and returns the number of
 * entries found.
**/
int
btree_find_range(btree_node * const root, int key_start, int key_end,
    int returned_keys[], void *returned_pointers[])
{
    int i, num_found = 0;
    btree_node *n = btree_find_leaf(root, key_start);

    if (n == NULL)
        return 0;

    while (n != NULL) {
        for (; i < n->num_keys && n->keys[i] <= key_end; i++) {
            returned_keys[num_found] = n->keys[i];
            returned_pointers[num_found] = n->pointers[i];
            num_found++;
        }

        n = n->pointers[order - 1];
        i = 0;
    }

    return num_found;
}

/**
 * Traces the path from root to a leaf, searching by key.
 * Displays information about the path and returns the
 * leaf containing the given key.
**/
btree_node *
btree_find_leaf(btree_node * const root, int key)
{
    if (root == NULL)
        return root;

    int i = 0;
    btree_node *c = root;

    while (!c->is_leaf) {
        i = 0;

        while (i < c->num_keys) {
            if (key >= c->keys[i])
                i++;
            else
                break;
        }

        c = (btree_node *)c->pointers[i];
    }

    return c;
}

/**
 * Finds and returns the record to which a key refers.
**/
orca_record *
orca_record_find(btree_node *root, int key, btree_node **leaf_out)
{
    if (root == NULL) {
        if (leaf_out != NULL)
            *leaf_out = NULL;

        return NULL;
    }

    int i;
    btree_node *leaf = NULL;

    /**
     * If root != NULL, leaf must have a value, even if it does
     * not contain the desired key. The leaf holds the range of
     * keys that would include the desired key.
    **/
    for (i = 0; i < leaf->num_keys; i++) {
        if (leaf->keys[i] == key)
            break;
    }

    if (leaf_out != NULL)
        *leaf_out = leaf;

    if (i == leaf->num_keys)
        return NULL;
    else
        return (orca_record *)leaf->pointers[i];
}

/**
 * Finds the appropriate place to split a node that is too big
 * into two.
**/
int
btree_cut(int len)
{
    if (len % 2 == 0)
        return len / 2;
    else
        return len / 2 + 1;
}

/**
 * INSERTION.
**/

/**
 * Creates a new record to hold the value to which a key refers.
**/
orca_record *
orca_make_record(int value)
{
    orca_record *new_record = (orca_record *)malloc(sizeof(record));

    if (new_record == NULL) {
        printk(KERN_ERR "orcafs: error during creation of ORCAFS Record\n");
        exit(EXIT_FAILURE);
    } else {
        new_record->value = value;
    }

    return new_record;
}

/**
 * Creates a new general btree node, which can be adapted to serve
 * either as a leaf or internal node.
**/
btree_node *
btree_make_node(void)
{
    btree_node *new_node = malloc(sizeof(btree_node));

    if (new_node == NULL) {
        printk(KERN_ERR "orcafs: error during creation of ORCAFS btree node\n");
        exit(EXIT_FAILURE);
    }

    new_node->keys = malloc((order - 1) * sizeof(int));

    if (new_node->keys == NULL) {
        printk(KERN_ERR "orcafs: error during creation of ORCAFS btree node keys\n");
        exit(EXIT_FAILURE);
    }

    new_node->pointers = malloc(order * sizeof(void *));

    if (new_node->pointers == NULL) {
        printk(KERN_ERR "orcafs: error during creation of ORCAFS btree node pointers\n");
        exit(EXIT_FAILURE);
    }

    new_node->is_leaf = false;
    new_node->num_keys = 0;
    new_node->parent = NULL;
    new_node->next = NULL;

    return new_node;
}

/**
 * Creates a new leaf by creating a btree node and then adapting
 * it appropriately.
**/
btree_node *
btree_make_leaf(void)
{
    btree_node *leaf = btree_make_node();
    leaf->is_leaf = true;

    return leaf;
}

/**
 * Used in btree_insert_into_parent() to find the index of the
 * parent's pointer to the node to the left of the key to be
 * inserted.
**/
int
btree_get_left_index(btree_node *parent, btree_node *left)
{
    int left_idx = 0;

    while (left_idx <= parent->num_keys && parent->pointers[left_idx] != left)
        left_idx++;

    return left_idx;
}

/**
 * Inserts a new pointer into a record and its corresponding key
 * into a leaf. Returns the altered leaf.
**/
btree_node *
btree_insert_into_leaf(btree_node *leaf, int key, orca_record *pointer)
{
    int i, insertion_point = 0;

    while (insertion_point < leaf->num_keys && leaf->keys[insertion_point] < key)
        insertion_point++;

    for (i = leaf->num_keys; i > insertion_point; i--) {
        leaf->keys[i] = leaf->keys[i - 1];
        leaf->pointers[i] = leaf->pointers[i - 1];
    }

    leaf->keys[insertion_point] = key;
    leaf->pointers[insertion_point] = pointer;
    leaf->num_keys++;

    return leaf;
}

/**
 * Inserts a new key and pointer to a new record into a leaf so
 * as to exceed the btree's order, causing the leaf to be split
 * in half.
**/
btree_node *
btree_insert_into_leaf_after_splitting(btree_node *root, btree_node *leaf, int key,
    orca_record *pointer)
{
    btree_node *new_leaf = btree_make_leaf();
    int *temp_keys = malloc(order * sizeof(int));
    void **temp_pointers;
    int insertion_idx, split, new_key, i, j;

    if (temp_keys == NULL) {
        printk(KERN_ERR "orcafs: error with creation of temporary keys array\n");
        exit(EXIT_FAILURE);
    }

    temp_pointers = malloc(order * sizeof(void *));

    if (temp_pointers == NULL) {
        printk(KERN_ERR "orcafs: error with creationg of temporary pointers array\n");
        exit(EXIT_FAILURE);
    }

    insertion_idx = 0;

    while (insertion_idx < order - 1 && leaf->keys[insertion_idx] < key)
        insertion_idx++;

    for (i = 0, j = 0; i < leaf->num_keys; i++, j++) {
        if (j == insertion_idx)
            j++;

        temp_keys[j] = leaf->keys[i];
        temp_pointers[j] = leaf->pointers[i];
    }

    temp_keys[insertion_idx] = key;
    temp_pointers[insertion_idx] = pointer;
    leaf->num_keys = 0;
    split = btree_cut(order - 1);

    for (i = 0; i < split; i++) {
        leaf->pointers[i] = temp_pointers[i];
        leaf->keys[i] = temp_keys[i];
        leaf->num_keys++;
    }

    for (i = split, j = 0; i < order; i++, j++) {
        new_leaf->pointers[j] = temp_pointers[i];
        new_leaf->keys[j] = temp_keys[i];
        new_leaf->num_keys++;
    }

    free(temp_pointers);
    free(temp_keys);

    new_leaf->pointers[order - 1] = new_leaf;

    for (i = leaf->num_keys; i < order - 1; i++)
        leaf->pointers[i] = NULL;

    for (i = new_leaf->num_keys; i < order; i++)
        new_leaf->pointers[i] = NULL;

    new_leaf->parent = leaf->parent;
    new_key = new_leaf->keys[0];

    return btree_insert_into_parent(root, leaf, new_key, new_leaf);
}

/**
 * Inserts a new key and pointer to a btree node to a node
 * into a node into which these can fit without violating
 * the B+ tree properties.
**/
btree_node *
btree_insert_into_node(btree_node *root, btree_node *n, int left_idx, int key,
    btree_node *right)
{
    int i;

    for (i = n->num_keys; i > left_idx; i--) {
        n->pointers[i + 1] = n->pointers[i];
        n->keys[i] = n->keys[i - 1];
    }

    n->pointers[left_idx + 1] = right;
    n->keys[left_idx] = key;
    n->num_keys++;

    return root;
}

/**
 * Inserts a new key and pointer to a node into a node,
 * causing the node's size to exceed the order, and
 * causing the node to split into two.
**/
btree_node *
btree_insert_into_node_after_splitting(btree_node *root, btree_node *old_node,
    int left_idx, int key, btree_node *right)
{
    int i, j, split, k_prime;
    btree_node *new_node, *child;
    int *temp_keys;
    btree_node **temp_pointers;

    /**
     * First create a temporary set of keys and pointers to hold
     * everything in order, including the new key and pointer,
     * inserted in their correct place.
     *
     * Then create a new node and copy half of the keys and pointers
     * to the old node and the other half to the new.
    **/
    temp_pointers = malloc((order + 1) * sizeof(node *));

    if (temp_pointers == NULL) {
        printk(KERN_ERR "orcafs: error with temporary pointers for splitting nodes\n");
        exit(EXIT_FAILURE);
    }

    temp_keys = malloc(order * sizeof(int));

    if (temp_keys == NULL) {
        printk(KERN_ERR "orcafs: error with temporary keys array for splitting nodes\n");
        exit(EXIT_FAILURE);
    }

    for (i = 0, j = 0; i < old_node->num_keys + 1; i++, j++) {
        if (j == left_idx + 1)
            j++;

        temp_pointers[j] = old_node->pointers[i];
    }

    for (i = 0, j = 0; i < old_node->num_keys; i++, j++) {
        if (j == left_idx)
            j++;

        temp_keys[j] = old_node->keys[i];
    }

    temp_pointers[left_idx + 1] = right;
    temp_keys[left_idx] = key;

    /**
     * Create the new btree node and copy half the keys and
     * pointers to the old and half to the new.
    **/
    split = btree_cut(order);
    new_node = btree_make_node();
    old_node->num_keys = 0;

    for (i = 0; i < split - 1; i++) {
        old_node->pointers[i] = temp_pointers[i];
        old_node->keys[i] = temp_keys[i];
        old_node->num_keys++;
    }

    old_keys->pointers[i] = temp_pointers[i];
    k_prime = temp_keys[split - 1];

    for (++i, j = 0; i < order; i++, j++) {
        new_node->pointers[j] = temp_pointers[i];
        new_node->keys[j] = temp_keys[i];
        new_node->num_keys++;
    }

    new_node->pointers[j] = temp_pointers[i];
    free(temp_pointers);
    free(temp_keys);
    new_node->parent = old_node->parent;

    for (i = 0; i <= new_node->num_keys; i++) {
        child = new_node->pointers[i];
        child->parent = new_node;
    }

    /**
     * Insert a new key into the parent of the two nodes
     * resulting from the split, with the old node to the
     * left and the new to the right.
    **/
    return btree_insert_into_parent(root, old_node, k_prime, new_node);
}

/**
 * Inserts a new node (leaf or internal node) into the B+ tree.
 * Returns the root of the tree after insertion.
**/
btree_node *
btree_insert_into_parent(btree_node *root, btree_node *left, int key, btree_node *right)
{
    int left_idx;
    btree_node *parent = left->parent;

    /* Case: new root */
    if (parent == NULL)
        return btree_insert_into_new_root(left, key, right);

    /**
     * Case: leaf or node (remainder of function body).
     * Find the parent's pointer to the left node.
    **/
    left_idx = btree_get_left_index(parent, left);

    /* Simple case: the new key fits into the node */
    if (parent->num_keys < order - 1)
        return btree_insert_into_node(root, parent, left_idx, key, right);

    /* Harder case: Split a node in order to preserve B+ tree properties */
    return btree_insert_into_node_after_splitting(root, parent, left_idx,
        key, right);
}

/**
 * Creates a new root for two subtrees and inserts the appropriate
 * key into the new root.
**/
btree_node *
btree_insert_into_new_root(btree_node *left, int key, btree_node *right)
{
    btree_node *root = btree_make_node();

    root->keys[0] = keys;
    root->pointers[0] = left;
    root->pointers[1] = right;
    root->num_keys++;
    root->parent = NULL;

    left->parent = root;
    right->parent = root;

    return root;
}

/**
 * Master insertion function. Inserts a key and an associated value
 * into the B+ tree, causing the tree to be adjusted however
 * necessary to maintain the B+ tree properties.
**/
btree_node *
btree_insert(btree_node *root, int key, int value)
{
    orca_record *record_pointer = NULL;
    btree_node *leaf = NULL;

    /* The current implementation ignores duplicates */
    record_pointer = orca_record_find(root, key, false, NULL);

    if (record_pointer != NULL) {
        /**
         * If the key already exists in this tree, update the
         * value and return the three.
        **/
        record_pointer->value = value;

        return root;
    }

    /* Create a new record for the value */
    record_pointer = orca_make_record(value);

    /* Case: the tree does not exist yet. Start a new tree */
    if (root == NULL)
        return btree_start_new_tree(key, record_pointer);

    /* Case: the tree already exists. */
    leaf = btree_find_leaf(root, key, false);

    /* Case: leaf has room for key and record_pointer */
    if (leaf->num_keys < order - 1) {
        leaf = btree_insert_into_leaf(leaf, key, record_pointer);
        return root;
    }

    /* Case: leaf must be split */
    return btree_insert_into_leaf_after_splitting(root, leaf, key, record_pointer);
}

/**
 * DELETION.
**/

/**
 * Utility function for deletion. Retrieves the index of a node's
 * nearest neighbor (sibling) to the left if one exists. If not
 * (the node is the leftmost child), returns -1 to signify this
 * special case.
**/
int
btree_get_neighbor_index(btree_node *n)
{
    int i;

    /**
     * Return the index of the key to the left of the
     * pointer in the parent pointing to n.
     *
     * If n is the leftmost child, this return -1.
    **/
    for (i = 0; i <= n->parent->num_keys; i++) {
        if (n->parent->pointers[i] == n)
            return i - 1;
    }

    /* Error state */
    printk(KERN_ERR "orcafs: search for non-existent pointer to node in parent\n"
        " Node: %#lx\n", (unsigned long)n);
    exit(EXIT_FAILURE);
}

btree_node *
btree_remove_entry_from_node(btree_node *n, int key, btree_node *pointer)
{
    int i = 0, num_pointers;

    /* Removing the key and shift other keys accordingly */
    while (n->keys[i] != key)
        i++;

    for (++i; i < n->num_keys; i++)
        n->keys[i - 1] = n->keys[i];

    /**
     * Remove the pointer and shift other pointers accordingly.
     * First determine number of pointers.
    **/
    num_pointers = n->is_leaf ? n->num_keys : n->num_keys + 1;
    i = 0;

    while (n->pointers[i] != pointer)
        i++;

    for (++i; i < num_pointers; i++)
        n->pointers[i - 1] = n->pointers[i];

    /* One key fewer */
    n->num_keys--;

    /**
     * Set the other pointers to NULL for tidiness.
     * A leaf uses the last pointer to point to the next leaf.
    **/
    if (n->is_leaf) {
        for (i = n->num_keys; i < order - 1; i++)
            n->pointers[i] = NULL;
    } else {
        for (i = n->num_keys + 1; i < order; i++)
            n->pointers[i] = NULL;
    }

    return n;
}

btree_node *
btree_node_adjust_root(btree_node *root)
{
    btree_node *root;

    /**
     * Case: non-empty root.
     * Key and pointer have already been deleted,
     * so nothing to be done.
    **/
    if (root->num_keys > 0)
        return root;

    /**
     * Case: empty root.
     * If it has a child, promote the first (only) child
     * as the new root.
    **/
    if (!root->is_leaf) {
        new_root = root->pointers[0];
        new_root->parent = NULL;

        /**
         * If it is a leaf (has no children), then the
         * whole tree is empty.
        **/
    } else {
        new_root = NULL;
    }

    free(root->keys);
    free(root->pointers);
    free(root);

    return new_root;
}

/**
 * Coalesces a node that has become too small after deletion
 * with a neighboring node that can accept the additional
 * entries without exceeding the maximum.
**/
btree_node *
btree_coalesce_nodes(btree_node *root, btree_node *n, btree_node *neighbor,
    int neighbor_idx, int k_prime)
{
    int i, j, neighbor_insert_idx, n_end;
    btree_node *tmp;

    /**
     * Swap neighbor with node if node is on the
     * extreme left and neighbor is to its right.
    **/
    if (neighbor_idx == -1) {
        tmp = n;
        n = neighbor;
        neighbor = tmp;
    }

    /**
     * Starting point in the neighbor for copying keys and
     * pointers from n.
     * Recall that n and neighbor have swapped places in the
     * special case of n being a leftmost child.
    **/
    neighbor_insert_idx = neighbor->num_keys;

    /**
     * Case: non-leaf node.
     * Append k_prime and the following pointer.
     * Append all pointers and keys from the neighbor.
    **/
    if (!n->is_leaf) {
        /* Append k_prime */
        neighbor->keys[neighbor_insert_idx] = k_prime;
        neighbor->num_keys++;

        n_end = n->num_keys;

        for (i = neighbor_insert_idx + 1, j = 0; j < n_end; i++, j++) {
            neighbor->keys[i] = n->keys[j];
            neighbor->pointers[i] = n->pointers[j];
            neighbor->num_keys++;
            n->num_keys--;
        }

        /**
         * The number of pointers is always one more than
         * the number of keys.
        **/
        neighbor->pointers[i] = n->pointers[j];

        /**
         * All children must now point up to the same parent.
        **/
        for (i = 0; i < neighbor->num_keys + 1; i++) {
            tmp = (btree_node *)neighbor->pointers[i];
            tmp->parent = neighbor;
        }

        /**
         * In a leaf, append the keys and pointers of n to the
         * neighbor. Set the neighbor's last pointer to point
         * to what had been n's right neighbor.
        **/
    } else {
        for (i = neighbor_insert_idx, j = 0; i < n->num_keys; i++, j++) {
            neighbor->keys[i] = n->keys[j];
            neighbor->pointers[i] = n->pointers[j];
            neighbor->num_keys++;
        }

        neighbor->pointers[order - 1] = n->pointers[order - 1];
    }

    root = btree_delete_entry(root, n->parent, k_prime, n);
    free(n->keys);
    free(n->pointers);
    free(n);

    return root;
}

/**
 * Redistributes entries between two nodes when one has
 * become too small after deletion but, its neighbor is
 * too big to append the small node's entries without
 * exceeding the maximum.
**/
btree_node *
btree_redistributed_nodes(btree_node *root, btree_node *n, btree_node *neighbor,
    int neighbor_idx, int k_prime_idx, int k_prime)
{
    int i;
    btree_node *tmp;

    /**
     * Case: n has a neighbor to the left.
     * Pull the neighbor's last key-pointer pair over
     * from the neighbor's right end to n's left end.
    **/
    if (neighbor_idx != -1) {
        if (!n->is_leaf) {
            n->pointers[n->num_keys + 1] = n->pointers[n->num_keys];

            for (i = n->num_keys; i > 0; i--) {
                n->keys[i] = n->keys[i - 1];
                n->pointers[i] = n->pointers[i - 1];
            }
        }

        if (!n->is_leaf) {
            n->pointers[0] = neighbor->pointers[neighbor->num_keys];
            tmp = (btree_node *)n->pointers[0];
            tmp->parent = n;
            neighbor->pointers[neighbors->num_keys] = NULL;
            n->keys[0] = k_prime;
            n->parent->keys[k_prime_idx] = neighbor->keys[neighbor->num_keys - 1];
        } else {
            n->pointers[0] = neighbor->pointers[neighbor->num_keys - 1];
            neighbor->pointers[neighbor->num_keys - 1] = NULL;
            n->keys[0] = neighbor->keys[neighbor->num_keys - 1];
            n->parent->keys[k_prime_idx] = n->keys[0];
        }

        /**
         * Case: n is the leftmost child.
         * Take a key-pointer pair from the neighbor to the right.
         * Move the neighbor's leftmost key-pointer pair
         * to n's rightmost position.
        **/
    } else {
        if (n->is_leaf) {
            n->keys[n->num_keys] = neighbor->keys[0];
            n->pointers[n->num_keys] = neighbor->pointers[0];
            n->parent->keys[k_prime_idx] = neighbor->keys[1];
        } else {
            n->keys[n->num_keys] = k_prime;
            n->pointers[n->num_keys + 1] = neighbor->pointers[0];
            tmp = (btree_node *)n->parent = n;
            n->parent->keys[k_prime_idx] = neighbor->keys[0];
        }

        for (i = 0; i < neighbor->num_keys - 1; i++) {
            neighbor->keys[i] = neighbor->keys[i + 1];
            neighbor->pointers[i] = neighbor->pointers[i + 1];
        }

        if (!n->is_leaf)
            neighbor->pointers[i] = neighbor->pointers[i + 1];
    }

    /**
     * n now has one more key and one more pointer, the
     * neighbor has one fewer of each.
    **/
    n->num_keys++;
    neighbor->num_keys--;

    return root;
}

/**
 * Deletes an entry from the B+ tree. Removes the record and its
 * key and pointer from the leaf, and then makes all appropriate
 * changes to preserve the B+ tree properties.
**/
btree_node *
btree_delete_entry(btree_node *root, btree_node *n, int key, void *pointer)
{
    int min_keys;
    btree_node *neighbor;
    int neighbor_idx;
    int k_prime_idx, k_prime;
    int capacity;

    /* Remove key and pointer from node */
    n = btree_remove_entry_from_node(n, key, pointer);

    /* Case: deletion from the root */
    if (n == root)
        return btree_adjust_root(root);

    /**
     * Case: deletion from node below the root.
     * Determine minimum allowable size of node,
     * to be preserved after deletion.
    **/
    min_keys = n->is_leaf ? btree_cut(order - 1) : btree_cut(order) - 1;

    /* Case: node stays at or above minimum */
    if (n->num_keys >= min_keys)
        return root;

    /**
     * Find the appropriate neighbor node with which to coalesce.
     * Also, find they key (k_prime) in the parent between the pointer
     * to node n and the pointer to the neighbor.
    **/
    neighbor_idx = btree_get_neighbor_index(n);
    k_prime_idx = neighbor_idx == -1 ? 0 : neighbor_idx;
    k_prime = n->parent->keys[k_prime_idx];
    neighbor = neighbor_idx == - 1 ? n->parent->pointers[1] :
        n->parent->pointers[neighbor_idx];

    capacity = n->is_leaf ? order : order - 1;

    /* Coalescence */
    if (neighbor->num_keys + n->num_keys < capacity)
        return btree_coalesce_nodes(root, n, neighbor, neighbor_idx, k_prime);
    else
    /* Redistribution */
        return btree_redistribute_nodes(root, n, neighbor, neighbor_idx,
            k_prime_idx, k_prime);
}

/**
 * Master deletion function.
**/
btree_node *
btree_delete(btree_node *root, int key)
{
    btree_node *key_leaf = NULL;
    orca_record *key_record = NULL;

    key_record = orca_record_find(root, key, false, &key_leaf);

    /* CHANGE */
    if (key_record != NULL && key_leaf != NULL) {
        root = btree_delete_entry(root, key_leaf, key, key_record);
        free(key_record);
    }

    return root;
}

void
btree_destroy_tree_nodes(btree_node *root)
{
    int i;

    if (root->is_leaf) {
        for (i = 0; i < root->num_keys; i++)
            free(root->pointers[i]);
    } else {
        for (i = 0; i < root->num_keys + 1; i++)
            btree_destroy_tree_nodes(root->pointers[i]);
    }

    free(root->pointers);
    free(root->keys);
    free(root);
}

btree_node *
btree_destroy_tree(btree_node *root)
{
    btree_destroy_tree_nodes(root);
    return NULL;
}

/**
 * MAIN.
**/
int
main(int argc, char **argv[])
{
    char *input_file;
    FILE *fp;
    node *root;
    int input_key, input_key_2;
    char instruction;

    root = NULL;

    if (argc > 1) {
        order = atoi(argv[1]);

        if (order < MIN_ORDER || order > MAX_ORDER) {
            printk(KERN_ERR "orcafs: invalid order: %d\n\n", order);
            btree_usage_3();
            exit(EXIT_FAILURE);
        }
    }

    if (argc < 3) {
        btree_license_notice();
        btree_usage_1();
        btree_usage_2();
    }

    if (argc > 2) {
        input_file = argv[2];
        fp = fopen(input_file, "r");

        if (fp == NULL) {
            printk(KERN_ERR "orcafs: error opening input file");
            exit(EXIT_FAILURE);
        }

        while (!feof(fp)) {
            fscanf(fp, "%d\n", &input_key);
            root = btree_insert(root, input_key, input_key);
        }

        fclose(fp);
        btree_print_tree(root);

        return EXIT_SUCCESS;
    }

    printf("% ");
    char buffer[BUFFER_SIZE];
    int count = 0;
    bool line_consumed = false;

    while (scanf("%c", &instruction) != EOF) {
        line_consumed = false;

        switch (instruction) {
        case 'd':
            scanf("%d", &input_key);
            root = btree_delete(root, input_key);
        }
    }
}
