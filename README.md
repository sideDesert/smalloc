# Smalloc: A really bad malloc implementation

## Introduction
Smalloc is a simple memory allocator designed for educational purposes. It uses a simple vector to manage free blocks of memory. The allocator is not thread-safe and should not be used in production code EVER. It uses mmap, as opposed to sbrk, and pages of mmap are also tracked via the custor simple vector.

## Why?
I wanted to learn C and this seemed like a good way to do it.

## Why a vector?
I genuinely didn't know any better. In hindsight a linked list , or hashmap would have been probably better, but I wanted things to be simple to understand the concept, rather than the implementation (though you can argue that doing it with a custom mmap vector is much of a footgun than a linked list...).

## Approach
There are two worlds
1. The theoretical heap world
2. The practical physical page memory world

Offset everywhere in this codebase are part of the theoretical heap world which start at offset 0. Imagine that the heap start from 0 and we keep going and going. Of course this is not practical as mmap - only gives us memory in fixed size pages. So we need to track the pages as well as the offsets for these pages.

We also have two lists - block_list (All blocks) and free_list (All free blocks).
These lists are just vectors of pointers to the memory (user memory) and indices (of the free blocks in the block_list) respectively.

Memory is laid out like so in a page. We need to align the memory otherwise we get OS sanitation errors...annoying IK.
|[Header][userdata]|

We use a really simple implementation of a dynamic array (which internally uses mmap) to keep track of the pages. Not the most efficient, but it works.

This implementation is not thread-safe. It obviously should not be used in production code, unless you are feeling a little bit insane. This throws a random memory sanitation error - which I am not sure why happens. So like YAY!!
This implementation also is a fragmentation monster. It is not optimized for fragmentation and WILL lead to memory fragmentation issues. (I just felt a little bit lazy writing that part)

This is just an exercise in learning C and understanding memory management ok? Don't expect a production grade project. I don't know even know how I am supposed to link projects.
