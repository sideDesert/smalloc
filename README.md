# Smalloc: A really bad malloc implementation

## Introduction
Smalloc is a simple memory allocator designed for educational purposes. It uses a simple vector to manage free blocks of memory. The allocator is not thread-safe and should not be used in production code EVER. It uses mmap, as opposed to sbrk, and pages of mmap are also tracked via the custor simple vector.

## Why?
I wanted to learn C and this seemed like a good way to do it.

## Why a vector?
I genuinely didn't know any better. In hindsight a linked list , or hashmap would have been probably better, but I wanted things to be simple to understand the concept, rather than the implementation (though you can argue that doing it with a custom mmap vector is much of a footgun than a linked list...).
