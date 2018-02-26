#ifndef LMG_KCOMPILER_H
#define LMG_KCOMPILER_H

// linux/compiler.h
# define likely(x)	__builtin_expect(!!(x), 1)
# define unlikely(x)	__builtin_expect(!!(x), 0)
//*****************************************************************************************************//

//// asm-generic/bug.h

#define BUG() do {} while (1)

#define WARN_ON(condition) ({						\
	int __ret_warn_on = !!(condition);				\
	unlikely(__ret_warn_on);					\
})

#define WARN_ON_ONCE(condition) WARN_ON(condition)
//*****************************************************************************************************//


#endif
