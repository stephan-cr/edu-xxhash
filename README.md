# Educational XXhash

Educational implementation of XXHash. It implements
[`Hasher`](https://doc.rust-lang.org/std/hash/trait.Hasher.html),
which allows to hash in a streaming fashion.

## Test vectors

Test vectors are generated with [xxhsum](https://github.com/Cyan4973/xxHash):

For XXHash 32 `echo -n <test-data> | xxhsum -H0 --binary -` and for XXHash 64
`echo -n <test-data> | xxhsum -H1 --binary -`.

## Resources

- https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md
