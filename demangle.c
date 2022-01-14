#include <stdio.h>
#include <stdlib.h>

extern char * demangle (const char * mangled, int options);
extern void demangle_free (void* ptr);

#define DEMANGLE_OPT_PARAMS    1
#define DEMANGLE_OPT_ANSI      2
#define DEMANGLE_OPT_JAVA      4
#define DEMANGLE_OPT_AUTO      8
#define DEMANGLE_OPT_GNU      16
#define DEMANGLE_OPT_LUCID    32
#define DEMANGLE_OPT_ARM      64
#define DEMANGLE_OPT_HP      128
#define DEMANGLE_OPT_EDG     256

int main(int argc, char* argv[]) {
	int opts = DEMANGLE_OPT_PARAMS
	| DEMANGLE_OPT_ANSI
	| DEMANGLE_OPT_AUTO
	| DEMANGLE_OPT_GNU
	| DEMANGLE_OPT_LUCID
	| DEMANGLE_OPT_ARM
	| DEMANGLE_OPT_HP
	| DEMANGLE_OPT_EDG;

	if (argc != 2) {
		fprintf(stderr, "usage: demangle <symbol>\n");
		return EXIT_FAILURE;
	}

	char* demangled = demangle(argv[1], opts);
	if (demangled)
		puts(demangled);
	else {
		fprintf(stderr, "demangler error: can't demangle symbol\n");
		return EXIT_FAILURE;
	}
	demangle_free(demangled);

	return EXIT_SUCCESS;
}