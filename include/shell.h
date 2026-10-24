#ifndef SHELL_H
#define SHELL_H

#include "types.h"

U0 shell_init(U0);
U0 shell_update(U0);
U0 shell_process_char(char c);
U0 shell_execute_command(const char* cmd_line);

// Secret input mode (vault passphrases): while active, terminals must not
// echo typed characters, and the next submitted line is consumed by the
// pending secret operation instead of being executed as a command.
Bool        shell_secret_prompt_active(U0);
const char* shell_secret_prompt_label(U0);

// Product commands: run() returns TRUE when it handled the line; help()
// prints the product's section of `help`. Up to 12 extensions.
// Optional: capture() takes the next submitted line while the extension has
// a hidden prompt pending (returns TRUE if it did); prompt() returns that
// prompt's label, or NULL when none is pending (input is then echoed).
typedef struct {
    Bool        (*run)(const char* cmd);
    U0          (*help)(U0);
    Bool        (*capture)(const char* line);
    const char* (*prompt)(U0);
} ShellExtension;
U0   shell_register(const ShellExtension* ext);
Bool shell_is_prefix(const char* prefix, const char* str);
U64  shell_parse_uint(const char* p);

// System Power Management
U0 sys_poweroff(U0);
U0 sys_reboot(U0);

#endif // SHELL_H

