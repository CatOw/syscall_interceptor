# compiler
CXX=g++

# compiler flags
CXXFLAGS=-Wall -Wextra -std=c++17

# source files
SRCS=main.cpp syscall_defs.cpp

# object files
OBJS=$(SRCS:.cpp=.o)

# target executable
TARGET=interceptor

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET)

main.o: main.cpp syscall_defs.h
	$(CXX) $(CXXFLAGS) -c main.cpp -o main.o

syscall_defs.o: syscall_defs.cpp syscall_defs.h
	$(CXX) $(CXXFLAGS) -c syscall_defs.cpp -o syscall_defs.o

clean:
	rm -f $(OBJS) $(TARGET)
