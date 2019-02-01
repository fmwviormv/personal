%{
#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define STRSIZE 63

struct yystype {
	char		 str[STRSIZE + 1];
};
#define YYSTYPE struct yystype

#define yyerror warnx

static int	 yylex(void);
%}

%token TSTRING

%%

grammar:	/* empty */
		| grammar '\n'
		| grammar rule '\n'
		| error '\n'
		;

rule:		TSTRING {
			printf("%s\n", $1.str);
		} ;

%%

static int
yylex(void)
{
	int		 c;
	size_t		 len;

	while ((c = getchar()) == ' ' || c == '\t')
		/* nothing */;

	switch (c) {
	case EOF:
		return 0;
	case '"':
		len = 0;
		while ((c = getchar()) != '"') {
			if (len + 1 >= sizeof(yylval.str))
				err(1, "big string");
			yylval.str[len++] = c;
		}
		yylval.str[len] = 0;
		return TSTRING;
	case '#':
		while ((c = getchar()) != '\n')
			if (c == EOF)
				return 0;
		return c;
	default:
		return c;
	}
}

int
main(void)
{
	yyparse();
	return 0;
}
