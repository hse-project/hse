/*
 */
#ifndef MURMUR3_H
#define MURMUR3_H

extern uint32_t
murmur3_32(const void *data, size_t nbytes);
extern void
murmur3_128(const void *data, size_t nbytes, void *retbuf);

#endif /* MURMUR3_H */
