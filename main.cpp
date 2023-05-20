#include <fstream>
#include <iostream>
#include <sstream>
#include <cstring>
#include <map>
#include <limits>
#include <string>
#include <iomanip>
#include <cerrno>
#include <string>

#include <limits.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>

#include "syscall_defs.h"

using std::cout;
using std::cin;
using std::cerr;
using std::endl;

pid_t pid;


std::string strlen_long(long num) {
    std::ostringstream oss;
    std::string str;
    size_t len = std::to_string(num).length();
    
    // Convert length to a 4-character string
    oss << std::setw(4) << std::setfill('0') << len;
    str = oss.str();
    
    return str;
}

std::string strlen_string(const std::string& str) {
    // Get the size of the string
    size_t size = str.size();
    
    // Convert the size to a 4-character string with leading zeros
    std::ostringstream oss;
    oss << std::setw(4) << std::setfill('0') << size;
    
    return oss.str();
}

std::string get_raw_string(const std::string& input) {
    std::string raw_string;
    for (char c : input) {
        switch (c) {
            case '\n':
                raw_string += "\\n";
                break;
            case '\r':
                raw_string += "\\r";
                break;
            case '\t':
                raw_string += "\\t";
                break;
            default:
                raw_string += c;
                break;
        }
    }
    return raw_string;
}

void flush_stdin() {
    cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

// Define a function to read a string from memory
std::string read_string_from_memory(unsigned long address) {
    std::string str;
    char buffer[sizeof(long)];
    int bytesRead = 0;

    while (true) {
        // Read a word of memory from the traced process
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, address + bytesRead, nullptr);
        if (word == -1 && errno) {
            perror("ptrace peekdata");
            break;
        }

        // Copy bytes from the word into the buffer
        memcpy(buffer, &word, sizeof(long));

        // Process each byte in the buffer
        for (size_t i = 0; i < sizeof(long); ++i) {
            if (buffer[i] == '\0') {
                return str;
            }
            str.push_back(buffer[i]);
        }

        bytesRead += sizeof(long);
    }
    return str;
}

void* inject_string(char str[]) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace(PTRACE_GETREGS)");
        exit(EXIT_FAILURE);
    }

    const size_t STACK_SIZE = PATH_MAX + 128;
    void *stack = malloc(STACK_SIZE);

    // Make sure we're writing to a safe part of the stack
    unsigned long long addr = regs.rsp - STACK_SIZE;

    // Align to a 16-byte boundary
    addr &= ~0xFULL;

    size_t len = strlen(str) + 1;

    // Write string to stack
    for (size_t i = 0; i < len; i += sizeof(unsigned long long)) {
        unsigned long long word = 0;
        memcpy(&word, &str[i], sizeof(word));
        ptrace(PTRACE_POKEDATA, pid, addr + i, (void*)word);
    }

    free(stack);
    return (void*)addr;
}

class SyscallHandler {
private:
    struct user_regs_struct regs;
    long args[6];
    long syscall_NR;
    int num_args;

public:
    SyscallHandler() {
        get_current_regs();
        update_args();
        syscall_NR = get_NR();

        num_args = get_args_amount_by_NR(syscall_NR);
    }

    void get_current_regs() {
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            perror("ptrace getregs");
        }
    }

    long get_NR() {
        return regs.orig_rax;
    }

    long get_ret() {
        get_current_regs();
        return regs.rax;
    }

    void set_ret(long value) {
        get_current_regs();
        regs.rax = value;
        set_regs();
    }

    const long* get_args() const { return args; }

    void set_arg(int arg_pos, long value) {
        get_current_regs();
        switch(arg_pos) {
            case 0:
                regs.rdi = value;
                break;
            case 1:
                regs.rsi = value;
                break;
            case 2:
                regs.rdx = value;
                break;
            case 3:
                regs.r10 = value;
                break;
            case 4:
                regs.r8 = value;
                break;
            case 5:
                regs.r9 = value;
                break;
        }
        update_args();
        set_regs();
    }

    void modify_args() {
        for (int i = 0; i < num_args; i++) {
            cout << "SETARG" << i << endl;
            long new_arg_value;
            if (is_arg_string_address(syscall_NR, i)) {
                std::string str;
                flush_stdin();
                std::getline(std::cin, str);
                new_arg_value = reinterpret_cast<long>(inject_string(const_cast<char*>(str.c_str())));
            } else {
                cin >> new_arg_value;
            }
            set_arg(i, new_arg_value);
        }
    }

    void modify_ret() {
        cout << "SETRET" << endl;
        long new_ret;
        cin >> new_ret;
        set_ret(new_ret);
    }

    void output_syscall_name(char type) {
        std::string syscall_name = get_syscall_name_by_NR(syscall_NR);
        cout << type << num_args << syscall_name << endl;
    }

    void output_args() {
        const long* args = get_args();
        for (int i = 0; i < num_args; i++) {
            if (is_arg_string_address(syscall_NR, i)) {
                std::string str_ver = read_string_from_memory(args[i]);
                str_ver = get_raw_string(str_ver);
                cout << "ARG" << i << "1" << strlen_string(str_ver) << str_ver << endl;
            } else {
                cout << "ARG" << i << "0" << strlen_long(args[i]) << args[i] << endl;
            }
        }
    }

    void output_ret() {
        cout << "RET" << get_ret() << endl;
    }

    bool output_skip_prompt() {
        cout << "SKIP" << endl;
        int response;
        cin >> response;
        return response == 0;
    }

private:
    void get_regs() {
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            perror("ptrace getregs");
        }
    }

    void set_regs() {
        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
            perror("ptrace setregs");
        }
    }

    void update_args() {
        args[0] = static_cast<long>(regs.rdi);
        args[1] = static_cast<long>(regs.rsi);
        args[2] = static_cast<long>(regs.rdx);
        args[3] = static_cast<long>(regs.r10);
        args[4] = static_cast<long>(regs.r8);
        args[5] = static_cast<long>(regs.r9);
    }
};

void intercept_syscalls() {
    while (true) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
            perror("ptrace syscall");
            break;
        }

        if (waitpid(pid, 0, 0) == -1) {
            perror("waitpid");
            break;
        }

        try {
            SyscallHandler handler;

            handler.output_syscall_name('E');
        
            handler.output_args();

            if (handler.output_skip_prompt()) {
                handler.modify_args();
            }

            if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
                perror("ptrace syscall");
                break;
            }

            if (waitpid(pid, 0, 0) == -1) {
                perror("waitpid");
                break;
            }

            handler.output_syscall_name('R');

            handler.output_ret();
            
            if (!handler.output_skip_prompt()) {
                continue;
            }

            handler.modify_ret();
        } catch (std::invalid_argument& e) {
            continue;
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        cout << "Usage: " << argv[0] << " [-p PID] | [-e EXECUTABLE]" << endl;
        return 1;
    }

    pid = -1;

    if (strcmp(argv[1], "-p") == 0) {
        pid = atoi(argv[2]);
    } else if (strcmp(argv[1], "-e") == 0) {
        pid = fork();
        if (pid == 0) {
            execvp(argv[2], argv + 2);
            perror("execvp");
            exit(1);
        } else if (pid == -1) {
            perror("fork");
            return 1;
        }
    } else {
        cout << "Usage: " << argv[0] << " [-p PID] | [-e EXECUTABLE]" << endl;
        return 1;
    }

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        perror("ptrace attach");
        return 1;
    }

    if (waitpid(pid, 0, 0) == -1) {
        perror("waitpid");
        return 1;
    }

    intercept_syscalls();
}
