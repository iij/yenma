/*
 * radtree -- generic radix tree for binary strings.
 *
 * Copyright (c) 2010, NLnet Labs.  See LICENSE for license.
 */
#ifndef RADTREE_H
#define RADTREE_H

#ifdef __cplusplus
extern "C" {
#endif

struct radnode;

/** length of the binary string */
typedef uint16_t radstrlen_t;

/**
 * The radix tree
 *
 * The elements are stored based on binary strings(0-255) of a given length.
 * They are sorted, a prefix is sorted before its suffixes.
 * If you want to know the key string, you should store it yourself, the
 * tree stores it in the parts necessary for lookup.
 * For binary strings for domain names see the radname routines.
 */
struct radtree {
	/** root node in tree */
	struct radnode* root;
	/** count of number of elements */
	size_t count;
};

/**
 * A radix tree lookup node.
 * The array is malloced separately from the radnode.
 */
struct radnode {
	/** data element associated with the binary string up to this node */
	void* elem;
	/** parent node (NULL for the root) */
	struct radnode* parent;
	/** index in the parent lookup array */
	uint8_t pidx;
	/** offset of the lookup array, add to [i] for lookups */
	uint8_t offset;
	/** length of the lookup array */
	uint16_t len;
	/** capacity of the lookup array (can be larger than length) */
	uint16_t capacity;
	/** the lookup array by [byte-offset] */
	struct radsel* array; 
};

/**
 * radix select edge in array
 */
struct radsel {
	/** additional string after the selection-byte for this edge. */
	uint8_t* str;
	/** length of the additional string for this edge */
	radstrlen_t len;
	/** node that deals with byte+str */
	struct radnode* node;
};

/**
 * Create new radix tree
 * @return new tree or NULL on alloc failure.
 */
struct radtree* radix_tree_create(void);

/**
 * Init new radix tree.
 * @param rt: radix tree to be initialized.
 */
void radix_tree_init(struct radtree* rt);

/**
 * Delete intermediate nodes from radix tree
 * @param rt: radix tree to be initialized.
 */
void radix_tree_clear(struct radtree* rt);

/**
 * Delete radix tree.
 * @param rt: radix tree to be deleted.
 */
void radix_tree_delete(struct radtree* rt);


/**
 * Insert element into radix tree.
 * @param rt: the radix tree.
 * @param key: key string.
 * @param len: length of key.
 * @param elem: pointer to element data.
 * @return NULL on failure - out of memory.
 * 	NULL on failure - duplicate entry.
 * 	On success the new radix node for this element.
 */
struct radnode* radix_insert(struct radtree* rt, uint8_t* k, radstrlen_t len,
	void* elem);

/**
 * Delete element from radix tree.
 * @param rt: the radix tree.
 * @param n: radix node for that element.
 * 	if NULL, nothing is deleted.
 */
void radix_delete(struct radtree* rt, struct radnode* n);

/**
 * Find radix element in tree.
 * @param rt: the radix tree.
 * @param key: key string.
 * @param len: length of key.
 * @return the radix node or NULL if not found.
 */
struct radnode* radix_search(const struct radtree* rt, const uint8_t* k, radstrlen_t len);

/**
 * Find radix element in tree, and if not found, find the closest smaller or
 * equal element in the tree.
 * @param rt: the radix tree.
 * @param key: key string.
 * @param len: length of key.
 * @param result: returns the radix node or closest match (NULL if key is
 * 	smaller than the smallest key in the tree).
 * @return true if exact match, false if no match.
 */
int radix_find_less_equal(const struct radtree* rt, const uint8_t* k, radstrlen_t len,
	struct radnode** result);

/**
 * Return the first (smallest) element in the tree.
 * @param rt: the radix tree.
 * @return: first node or NULL if none.
 */
struct radnode* radix_first(struct radtree* rt);

/**
 * Return the last (largest) element in the tree.
 * @param rt: the radix tree.
 * @return: last node or NULL if none.
 */
struct radnode* radix_last(struct radtree* rt);

/**
 * Return the next element.
 * @param n: the element to go from.
 * @return: next node or NULL if none.
 */
struct radnode* radix_next(struct radnode* n);

/**
 * Return the previous element.
 * @param n: the element to go from.
 * @return: prev node or NULL if none.
 */
struct radnode* radix_prev(struct radnode* n);

/*
 * Perform a walk through all elements of the tree.
 * node: variable of type struct radnode*.
 * tree: pointer to the tree.
 *	for(node=radix_first(tree); node; node=radix_next(node))
*/

/** number of bytes in common in strings */
radstrlen_t bstr_common_ext(uint8_t* x, radstrlen_t xlen, uint8_t* y,
	radstrlen_t ylen);
/** true if one is prefix of the other */
int bstr_is_prefix_ext(uint8_t* p, radstrlen_t plen, uint8_t* x,
	radstrlen_t xlen);

#ifdef __cplusplus
}
#endif

#endif /* RADTREE_H */
