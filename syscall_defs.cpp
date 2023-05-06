#include <map>
#include <stdexcept>
#include <string>

using std::invalid_argument;
using std::map;
using std::pair;
using std::string;
using std::to_string;

// A map containing information about different system calls.
// The keys are the system call numbers (NR) and the values are pairs of
// strings representing the name of the system call and a string of 0s and 1s.
// The second string is a representation of whether each argument is an address to a string.
// A 0 indicates that the argument is not an address to a string, and a 1 indicates that it is.
const map<long, pair<string, string>> k_syscalls = {
    {0, {"read", "010"}},
    {1, {"write", "010"}},
    {2, {"open", "100"}},
    {3, {"close", "0"}},
};

string get_syscall_name_by_NR(long nr) {
    auto it = k_syscalls.find(nr);
    if (it == k_syscalls.end()) {
        throw invalid_argument(to_string(nr));
    }
    return it->second.first;
}

int get_args_amount_by_NR(long nr) {
    auto it = k_syscalls.find(nr);
    if (it == k_syscalls.end()) {
        throw invalid_argument(to_string(nr));
    }
    return it->second.second.length();
}

bool is_arg_string_address(long nr, std::string::size_type arg_pos) {
    auto it = k_syscalls.find(nr);
    if (it == k_syscalls.end()) {
        throw std::invalid_argument(to_string(nr));
    }
    const string& arg_mask = it->second.second;
    if (arg_pos >= arg_mask.length()) {
        throw std::invalid_argument("invalid argument position");
    }
    return arg_mask[arg_pos] == '1';
}
