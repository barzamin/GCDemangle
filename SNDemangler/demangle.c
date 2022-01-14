// DEMAN.cpp : Defines the entry point for the DLL application.
//

#include "sn_demangle.h"
#include <stdlib.h>

#define SOEXPORT __attribute__ ((visibility ("default")))

SOEXPORT char * demangle (const char * mangled, int options) {
	return cplus_demangle(mangled, options);
}

SOEXPORT void demangle_free (void* ptr) {
	free(ptr);
}
