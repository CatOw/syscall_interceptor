#ifndef SYSCALL_DEFS_H
#define SYSCALL_DEFS_H

#include <string>

std::string get_syscall_name_by_NR(long NR);
int get_args_amount_by_NR(long NR);
bool is_arg_string_address(long nr, std::string::size_type arg_pos);

#endif // SYSCALL_DEFS_H
