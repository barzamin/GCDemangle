//
// These two functions are imported by cplus-dem.c
//

// #define WIN32_LEAN_AND_MEAN
// #include "windows.h"
// #include "malloc.h"

#include <stdlib.h>

void* xmalloc(size_t size)
{
	void* result = malloc(size);

	return result;
//	return HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, size);
}

void* xrealloc(void* ptr, size_t size)
{
	void* result = realloc(ptr, size);

	return result;
//	return HeapReAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, ptr, size);
}
