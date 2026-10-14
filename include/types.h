#ifndef TYPES_H
#define TYPES_H

typedef void               U0;
typedef signed char        I8;
typedef unsigned char      U8;
typedef signed short       I16;
typedef unsigned short     U16;
typedef signed int         I32;
typedef unsigned int       U32;
typedef signed long long   I64;
typedef unsigned long long U64;

typedef signed char        int8_t;
typedef unsigned char      uint8_t;
typedef signed short       int16_t;
typedef unsigned short     uint16_t;
typedef signed int         int32_t;
typedef unsigned int       uint32_t;
typedef signed long long   int64_t;
typedef unsigned long long uint64_t;

typedef unsigned long long size_t;
typedef signed long long   intptr_t;
typedef unsigned long long uintptr_t;
typedef signed long long   ptrdiff_t;

typedef I64 Bool;
#define TRUE  1
#define FALSE 0
#define NULL  ((void*)0)

#endif // TYPES_H
