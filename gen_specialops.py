import re
x = """
  {"nw",	  " new",	DEMANGLE_OPT_ANSI},	/* new (1.92,	 ansi) */
  {"dl",	  " delete",	DEMANGLE_OPT_ANSI},	/* new (1.92,	 ansi) */
  {"new",	  " new",	0},		/* old (1.91,	 and 1.x) */
  {"delete",	  " delete",	0},		/* old (1.91,	 and 1.x) */
  {"vn",	  " new []",	DEMANGLE_OPT_ANSI},	/* GNU, pending ansi */
  {"vd",	  " delete []",	DEMANGLE_OPT_ANSI},	/* GNU, pending ansi */
  {"as",	  "=",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"ne",	  "!=",		DEMANGLE_OPT_ANSI},	/* old, ansi */
  {"eq",	  "==",		DEMANGLE_OPT_ANSI},	/* old,	ansi */
  {"ge",	  ">=",		DEMANGLE_OPT_ANSI},	/* old,	ansi */
  {"gt",	  ">",		DEMANGLE_OPT_ANSI},	/* old,	ansi */
  {"le",	  "<=",		DEMANGLE_OPT_ANSI},	/* old,	ansi */
  {"lt",	  "<",		DEMANGLE_OPT_ANSI},	/* old,	ansi */
  {"plus",	  "+",		0},		/* old */
  {"pl",	  "+",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"apl",	  "+=",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"minus",	  "-",		0},		/* old */
  {"mi",	  "-",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"ami",	  "-=",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"mult",	  "*",		0},		/* old */
  {"ml",	  "*",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"amu",	  "*=",		DEMANGLE_OPT_ANSI},	/* ansi (ARM/Lucid) */
  {"aml",	  "*=",		DEMANGLE_OPT_ANSI},	/* ansi (GNU/g++) */
  {"convert",	  "+",		0},		/* old (unary +) */
  {"negate",	  "-",		0},		/* old (unary -) */
  {"trunc_mod",	  "%",		0},		/* old */
  {"md",	  "%",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"amd",	  "%=",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"trunc_div",	  "/",		0},		/* old */
  {"dv",	  "/",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"adv",	  "/=",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"truth_andif", "&&",		0},		/* old */
  {"aa",	  "&&",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"truth_orif",  "||",		0},		/* old */
  {"oo",	  "||",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"truth_not",	  "!",		0},		/* old */
  {"nt",	  "!",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"postincrement","++",	0},		/* old */
  {"pp",	  "++",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"postdecrement","--",	0},		/* old */
  {"mm",	  "--",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"bit_ior",	  "|",		0},		/* old */
  {"or",	  "|",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"aor",	  "|=",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"bit_xor",	  "^",		0},		/* old */
  {"er",	  "^",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"aer",	  "^=",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"bit_and",	  "&",		0},		/* old */
  {"ad",	  "&",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"aad",	  "&=",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"bit_not",	  "~",		0},		/* old */
  {"co",	  "~",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"call",	  "()",		0},		/* old */
  {"cl",	  "()",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"alshift",	  "<<",		0},		/* old */
  {"ls",	  "<<",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"als",	  "<<=",	DEMANGLE_OPT_ANSI},	/* ansi */
  {"arshift",	  ">>",		0},		/* old */
  {"rs",	  ">>",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"ars",	  ">>=",	DEMANGLE_OPT_ANSI},	/* ansi */
  {"component",	  "->",		0},		/* old */
  {"pt",	  "->",		DEMANGLE_OPT_ANSI},	/* ansi; Lucid C++ form */
  {"rf",	  "->",		DEMANGLE_OPT_ANSI},	/* ansi; ARM/GNU form */
  {"indirect",	  "*",		0},		/* old */
  {"method_call",  "->()",	0},		/* old */
  {"addr",	  "&",		0},		/* old (unary &) */
  {"array",	  "[]",		0},		/* old */
  {"vc",	  "[]",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"compound",	  ", ",		0},		/* old */
  {"cm",	  ", ",		DEMANGLE_OPT_ANSI},	/* ansi */
  {"cond",	  "?:",		0},		/* old */
  {"cn",	  "?:",		DEMANGLE_OPT_ANSI},	/* pseudo-ansi */
  {"max",	  ">?",		0},		/* old */
  {"mx",	  ">?",		DEMANGLE_OPT_ANSI},	/* pseudo-ansi */
  {"min",	  "<?",		0},		/* old */
  {"mn",	  "<?",		DEMANGLE_OPT_ANSI},	/* pseudo-ansi */
  {"nop",	  "",		0},		/* old (for operator=) */
  {"rm",	  "->*",	DEMANGLE_OPT_ANSI},	/* ansi */
  {"sz",          "sizeof ",    DEMANGLE_OPT_ANSI}      /* pseudo-ansi */
"""
PATT = re.compile(r'\{"(\w+)",\s*"(.+)",\s*(\w+)\}\,?\s*\/\*(.*)\*\/')
for l in x.strip().split('\n'):
    # print(l)
    if m := PATT.match(l.strip()):
        opcode, op, opts, cmt = m.groups()

        print(f'map.put("{opcode}", "operator {op.strip()}"); // {opts}, {cmt.strip()}')
    # else:
    #     print(f'=======> {l}')