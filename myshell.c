#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <sys/wait.h>
#include <termios.h>
#endif

#define MAX_INPUT_SIZE 1024
#define MAX_ARGS 64
#define MAX_HISTORY 100
#define MAX_PATH_LEN 256
#define MAX_HOSTNAME 256
#define MAX_USERNAME 64
#define HISTORY_FILE ".myshell_history"

typedef struct HistoryNode {
    char *command;
    struct HistoryNode *next;
    struct HistoryNode *prev;
} HistoryNode;

HistoryNode *history_head = NULL;
HistoryNode *history_tail = NULL;
int history_count = 0;
HistoryNode *current_history = NULL;
pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;

void add_to_history(char *cmd) {
    if (!cmd || !*cmd) return;
    if (history_tail && strcmp(history_tail->command, cmd) == 0) return;
    char *new_cmd = strdup(cmd);
    if (!new_cmd) return;
    HistoryNode *node = malloc(sizeof(HistoryNode));
    if (!node) {
        free(new_cmd);
        return;
    }
    node->command = new_cmd;
    node->next = NULL;
    node->prev = history_tail;
    if (history_tail) {
        history_tail->next = node;
    } else {
        history_head = node;
    }
    history_tail = node;
    if (history_count == MAX_HISTORY) {
        HistoryNode *temp = history_head;
        history_head = history_head->next;
        history_head->prev = NULL;
        free(temp->command);
        free(temp);
    } else {
        history_count++;
    }
    current_history = NULL;
}

void save_history() {
    FILE *file = fopen(HISTORY_FILE, "w");
    if (!file) return;
    HistoryNode *current = history_head;
    while (current) {
        fprintf(file, "%s\n", current->command);
        current = current->next;
    }
    fclose(file);
}

void load_history() {
    FILE *file = fopen(HISTORY_FILE, "r");
    if (!file) return;
    char line[MAX_INPUT_SIZE];
    while (fgets(line, MAX_INPUT_SIZE, file)) {
        line[strcspn(line, "\n")] = '\0';
        if (*line) add_to_history(line);
    }
    fclose(file);
}

void free_history() {
    HistoryNode *current = history_head;
    while (current) {
        HistoryNode *temp = current;
        current = current->next;
        free(temp->command);
        free(temp);
    }
    history_head = history_tail = NULL;
    history_count = 0;
}

void parse_input(char *input, char **args, char **infile, char **outfile, int *append) {
    *infile = *outfile = NULL;
    *append = 0;
    if (!input || strlen(input) >= MAX_INPUT_SIZE - 1) return;
    int arg_count = 0;
    char *token = strtok(input, " ");
    while (token && arg_count < MAX_ARGS - 1) {
        if (strcmp(token, "<") == 0) {
            token = strtok(NULL, " ");
            if (token) *infile = token;
        } else if (strcmp(token, ">") == 0) {
            token = strtok(NULL, " ");
            if (token) {
                *outfile = token;
                *append = 0;
            }
        } else if (strcmp(token, ">>") == 0) {
            token = strtok(NULL, " ");
            if (token) {
                *outfile = token;
                *append = 1;
            }
        } else {
            args[arg_count++] = token;
        }
        token = strtok(NULL, " ");
    }
    args[arg_count] = NULL;
}

void print_colored(const char *text, const char *color) {
    pthread_mutex_lock(&output_mutex);
    printf("%s%s\033[0m", color, text);
    fflush(stdout);
    pthread_mutex_unlock(&output_mutex);
}

void display_banner() {
    print_colored("====================================\n", "\033[1;34m");
    print_colored(" MyShell - A Lightweight Shell\n", "\033[1;36m");
    print_colored("====================================\n", "\033[1;34m");
}

void display_help() {
    print_colored("MyShell Commands:\n", "\033[1;33m");
    print_colored("  cd [dir]        Change directory\n", "\033[1;32m");
    print_colored("  history         Show command history\n", "\033[1;32m");
    print_colored("  exit            Exit the shell\n", "\033[1;32m");
    print_colored("  cmd < file      Input redirection\n", "\033[1;32m");
    print_colored("  cmd > file      Output redirection (overwrite)\n", "\033[1;32m");
    print_colored("  cmd >> file     Output redirection (append)\n", "\033[1;32m");
}

typedef struct {
    char **args;
    char *infile;
    char *outfile;
    int append;
    int *status;
} JobData;

JobData *job_data_new(char **a, char *in, char *out, int app, int *st) {
    JobData *jd = malloc(sizeof(JobData));
    if (!jd) return NULL;
    jd->args = malloc(MAX_ARGS * sizeof(char *));
    if (!jd->args) {
        free(jd);
        return NULL;
    }
    int i = 0;
    for (; a[i] && i < MAX_ARGS - 1; i++) {
        jd->args[i] = strdup(a[i]);
    }
    jd->args[i] = NULL;
    jd->infile = in ? strdup(in) : NULL;
    jd->outfile = out ? strdup(out) : NULL;
    jd->append = app;
    jd->status = st;
    return jd;
}

void job_data_free(JobData *jd) {
    if (!jd) return;
    for (int i = 0; jd->args[i]; i++) {
        free(jd->args[i]);
    }
    free(jd->args);
    free(jd->infile);
    free(jd->outfile);
    free(jd);
}

void *execute_command(void *data) {
    JobData *jd = data;
    char **args = jd->args;
    char *infile = jd->infile;
    char *outfile = jd->outfile;
    int append = jd->append;
    int *status = jd->status;

    if (!args || !args[0]) {
        *status = 0;
        job_data_free(jd);
        return NULL;
    }

#ifdef _WIN32
    char cmdline[MAX_INPUT_SIZE * 2];
    int offset = 0;
    for (int i = 0; args[i]; i++) {
        int needs_quotes = strchr(args[i], ' ') != NULL;
        if (i > 0) cmdline[offset++] = ' ';
        if (needs_quotes) cmdline[offset++] = '"';
        offset += snprintf(cmdline + offset, sizeof(cmdline) - offset, "%s", args[i]);
        if (needs_quotes) cmdline[offset++] = '"';
        if (offset >= sizeof(cmdline) - 1) {
            char err[256];
            snprintf(err, sizeof(err), "Command line too long.\n");
            print_colored(err, "\033[1;31m");
            *status = 1;
            job_data_free(jd);
            return NULL;
        }
    }
    cmdline[offset] = '\0';

    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    HANDLE hIn = INVALID_HANDLE_VALUE, hOut = INVALID_HANDLE_VALUE;

    if (infile) {
        hIn = CreateFile(infile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hIn == INVALID_HANDLE_VALUE) {
            char err[256];
            snprintf(err, sizeof(err), "Failed to open input file (%lu).\n", GetLastError());
            print_colored(err, "\033[1;31m");
            *status = 1;
            job_data_free(jd);
            return NULL;
        }
    }
    if (outfile) {
        hOut = CreateFile(outfile, GENERIC_WRITE, 0, NULL, append ? OPEN_ALWAYS : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOut == INVALID_HANDLE_VALUE) {
            char err[256];
            snprintf(err, sizeof(err), "Failed to open output file (%lu).\n", GetLastError());
            print_colored(err, "\033[1;31m");
            if (hIn != INVALID_HANDLE_VALUE) CloseHandle(hIn);
            *status = 1;
            job_data_free(jd);
            return NULL;
        }
        if (append) SetFilePointer(hOut, 0, NULL, FILE_END);
    }

    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput = hIn != INVALID_HANDLE_VALUE ? hIn : GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = hOut != INVALID_HANDLE_VALUE ? hOut : GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = hOut != INVALID_HANDLE_VALUE ? hOut : GetStdHandle(STD_ERROR_HANDLE);

    if (!CreateProcess(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        char err[256];
        snprintf(err, sizeof(err), "CreateProcess failed (%lu).\n", GetLastError());
        print_colored(err, "\033[1;31m");
        if (hIn != INVALID_HANDLE_VALUE) CloseHandle(hIn);
        if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
        *status = 1;
        job_data_free(jd);
        return NULL;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    *status = exit_code;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (hIn != INVALID_HANDLE_VALUE) CloseHandle(hIn);
    if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
#else
    int fd_in = -1, fd_out = -1;
    if (infile) {
        fd_in = open(infile, O_RDONLY);
        if (fd_in == -1) {
            char err[256];
            snprintf(err, sizeof(err), "open %s: %s\n", infile, strerror(errno));
            print_colored(err, "\033[1;31m");
            *status = 1;
            job_data_free(jd);
            return NULL;
        }
    }
    if (outfile) {
        fd_out = open(outfile, O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC), 0644);
        if (fd_out == -1) {
            char err[256];
            snprintf(err, sizeof(err), "open %s: %s\n", outfile, strerror(errno));
            print_colored(err, "\033[1;31m");
            if (fd_in != -1) close(fd_in);
            *status = 1;
            job_data_free(jd);
            return NULL;
        }
    }

    pid_t pid = fork();
    if (pid == -1) {
        char err[256];
        snprintf(err, sizeof(err), "fork: %s\n", strerror(errno));
        print_colored(err, "\033[1;31m");
        if (fd_in != -1) close(fd_in);
        if (fd_out != -1) close(fd_out);
        *status = 1;
        job_data_free(jd);
        return NULL;
    } else if (pid == 0) {
        if (fd_in != -1) {
            if (dup2(fd_in, STDIN_FILENO) == -1) exit(EXIT_FAILURE);
            close(fd_in);
        }
        if (fd_out != -1) {
            if (dup2(fd_out, STDOUT_FILENO) == -1 || dup2(fd_out, STDERR_FILENO) == -1) exit(EXIT_FAILURE);
            close(fd_out);
        }
        execvp(args[0], args);
        char err[256];
        snprintf(err, sizeof(err), "execvp %s: %s\n", args[0], strerror(errno));
        print_colored(err, "\033[1;31m");
        exit(EXIT_FAILURE);
    } else {
        int wstatus;
        waitpid(pid, &wstatus, 0);
        if (fd_in != -1) close(fd_in);
        if (fd_out != -1) close(fd_out);
        *status = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : 1;
    }
#endif
    job_data_free(jd);
    return NULL;
}

void get_prompt(char *prompt, size_t size) {
    char username[MAX_USERNAME], hostname[MAX_HOSTNAME], cwd[MAX_PATH_LEN], display_path[MAX_PATH_LEN];
#ifdef _WIN32
    DWORD uname_size = MAX_USERNAME;
    GetUserName(username, &uname_size);
    if (!username[0]) strcpy(username, getenv("USERNAME") ? getenv("USERNAME") : "user");
    DWORD hsize = MAX_HOSTNAME;
    GetComputerName(hostname, &hsize);
#else
    strcpy(username, getenv("USER") ? getenv("USER") : "user");
    gethostname(hostname, MAX_HOSTNAME);
#endif
    hostname[MAX_HOSTNAME - 1] = '\0';
    getcwd(cwd, MAX_PATH_LEN);
    cwd[MAX_PATH_LEN - 1] = '\0';
    char *home = getenv("HOME");
    if (home && strstr(cwd, home) == cwd) {
        snprintf(display_path, MAX_PATH_LEN, "~%s", cwd + strlen(home));
    } else {
        strncpy(display_path, cwd, MAX_PATH_LEN);
    }
    snprintf(prompt, size, "%s@%s:%s$ ", username, hostname, display_path);
}

int main() {
#ifdef _WIN32
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(console, &mode);
    SetConsoleMode(console, mode | 0x0004);
#else
    struct termios term, term_old;
    tcgetattr(STDIN_FILENO, &term_old);
    term = term_old;
    term.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
#endif

    load_history();
    display_banner();

    char input[MAX_INPUT_SIZE];
    char *args[MAX_ARGS];
    char *infile, *outfile;
    int append, status = 0;

    while (1) {
        char prompt[512];
        get_prompt(prompt, sizeof(prompt));
        print_colored(prompt, status == 0 ? "\033[1;32m" : "\033[1;31m");
        fflush(stdout);

        int pos = 0, c;
        while (1) {
#ifdef _WIN32
            INPUT_RECORD ir;
            DWORD read;
            ReadConsoleInput(GetStdHandle(STD_INPUT_HANDLE), &ir, 1, &read);
            if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
                c = ir.Event.KeyEvent.uChar.AsciiChar;
                if (c == 0) {
                    if (ir.Event.KeyEvent.wVirtualKeyCode == VK_UP && history_head && history_count > 0) {
                        if (!current_history) current_history = history_tail;
                        else if (current_history->prev) current_history = current_history->prev;
                        strncpy(input, current_history->command, MAX_INPUT_SIZE - 1);
                        pos = strlen(input);
                        printf("\r\033[K%s%s", prompt, input);
                    } else if (ir.Event.KeyEvent.wVirtualKeyCode == VK_DOWN && current_history) {
                        if (current_history->next) {
                            current_history = current_history->next;
                            strncpy(input, current_history->command, MAX_INPUT_SIZE - 1);
                        } else {
                            current_history = NULL;
                            input[0] = '\0';
                        }
                        pos = strlen(input);
                        printf("\r\033[K%s%s", prompt, input);
                    }
                    continue;
                }
#else
            c = getchar();
            if (c == '\033') {
                getchar();
                c = getchar();
                if (c == 'A' && history_head && history_count > 0) {
                    if (!current_history) current_history = history_tail;
                    else if (current_history->prev) current_history = current_history->prev;
                    strncpy(input, current_history->command, MAX_INPUT_SIZE - 1);
                    pos = strlen(input);
                    printf("\r\033[K%s%s", prompt, input);
                    continue;
                } else if (c == 'B' && current_history) {
                    if (current_history->next) {
                        current_history = current_history->next;
                        strncpy(input, current_history->command, MAX_INPUT_SIZE - 1);
                    } else {
                        current_history = NULL;
                        input[0] = '\0';
                    }
                    pos = strlen(input);
                    printf("\r\033[K%s%s", prompt, input);
                    continue;
                }
#endif
            } else if (c == '\r' || c == '\n') {
                input[pos] = '\0';
                printf("\n");
                break;
            } else if (c == 127 || c == '\b') {
                if (pos > 0) {
                    input[--pos] = '\0';
                    printf("\r\033[K%s%s", prompt, input);
                }
            } else if (pos < MAX_INPUT_SIZE - 1 && c >= 32 && c <= 126) {
                input[pos++] = c;
                input[pos] = '\0';
                printf("\r\033[K%s%s", prompt, input);
            }
        }

        if (pos == 0) continue;
        char *cmd = strdup(input);
        if (!cmd) {
            print_colored("Memory allocation failed.\n", "\033[1;31m");
            continue;
        }
        add_to_history(cmd);
        parse_input(input, args, &infile, &outfile, &append);

        if (!args[0]) {
            free(cmd);
            continue;
        }

        if (strcmp(args[0], "exit") == 0) {
            free(cmd);
            break;
        } else if (strcmp(args[0], "cd") == 0) {
            char *dir = args[1] ? args[1] : getenv("HOME");
            if (!dir) dir = "";
#ifdef _WIN32
            if (SetCurrentDirectory(dir) == 0) {
                char err[256];
                snprintf(err, sizeof(err), "cd failed (%lu).\n", GetLastError());
                print_colored(err, "\033[1;31m");
            }
#else
            if (chdir(dir) == -1) {
                char err[256];
                snprintf(err, sizeof(err), "cd: %s\n", strerror(errno));
                print_colored(err, "\033[1;31m");
            }
#endif
            status = 0;
        } else if (strcmp(args[0], "history") == 0) {
            HistoryNode *current = history_head;
            int i = 1;
            while (current) {
                char line[256];
                snprintf(line, sizeof(line), "%d %s\n", i++, current->command);
                print_colored(line, "\033[1;33m");
                current = current->next;
            }
            status = 0;
        } else if (strcmp(args[0], "help") == 0) {
            display_help();
            status = 0;
        } else {
            JobData *jd = job_data_new(args, infile, outfile, append, &status);
            if (jd) {
                pthread_t thread;
                pthread_create(&thread, NULL, execute_command, jd);
                pthread_detach(thread);
                usleep(10000);
            }
        }
        free(cmd);
    }

    save_history();
    free_history();
    pthread_mutex_destroy(&output_mutex);
#ifdef _WIN32
    SetConsoleMode(console, mode);
#else
    tcsetattr(STDIN_FILENO, TCSANOW, &term_old);
#endif
    return status;
}
