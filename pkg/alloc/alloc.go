// package alloc is the id allocator that circulates the
// next id as the id allocator.
//
// When the allocation space is large, the next id behind
// the current id is very likely to be unused in most cases,
// which involves only a single operation while allocating.
//
// The upper limit of this allocator is O(N), where N is the
// current number of elements in use.
package alloc

// Alloc allocates the ID by circularly seeking for the
// next available identity.
//
// Please notice that since the index 0 has been reserved
// for invalid index, it will be returned whenever the
// allocation has failed.
func Alloc(
	id, upperLimit uint64, occupied func(uint64) bool,
) uint64 {
	if upperLimit == 0 {
		upperLimit = ^uint64(0)
	}

	// Fast path: attempt to return the value next to this
	// value as the identity.
	//
	// The fast path is asserted to happen in most cases,
	// since it is nearly impossible to use up all
	// identities as long as the limit is great enough.
	newID := id + 1
	if newID != 0 && !occupied(id) {
		return newID
	}

	// Slow path: attempt to seek for the last
	// available identities.
	for newID := id + 2; newID <= upperLimit; newID++ {
		if !occupied(newID) {
			return newID
		}
	}
	for newID := uint64(1); newID < id; newID++ {
		if !occupied(newID) {
			return newID
		}
	}
	return 0
}
