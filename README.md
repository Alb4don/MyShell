
- I created this learning project for college, to get hands-on with system calls like fork, execvp, and wait and it's cross-platform. At its core, MyShell is designed for simplicity and extensibility. It handles basic command execution by parsing user input, forking child processes, and managing their lifecycles. Input parsing, process creation, and execution are all separate functions, making it easy to build on without a complete overhaul.

![MyShell](https://github.com/user-attachments/assets/48eeed7c-d079-4d0c-a22c-0046fed5f46d)


# Prerequisites

- A C compiler (GCC or MinGW for Windows).
- On Windows, ensure MinGW is set up with pthread support for threading.
- No external libraries it's pure C with standard headers.
