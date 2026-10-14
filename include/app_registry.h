#ifndef APP_REGISTRY_H
#define APP_REGISTRY_H

#include "types.h"

#define MAX_DYNAMIC_APPS 8

typedef struct {
    char name[32];
    char bundle_path[64];
    char exec_entry[32];
    Bool is_active;
} DynamicApp;

U0          app_registry_init(U0);
Bool        app_registry_register(const char* name, const char* bundle_path, const char* exec_entry);
U32         app_registry_get_count(U0);
DynamicApp* app_registry_get(U32 index);
U0          app_registry_launch(U32 index);
Bool        app_registry_remove(const char* name);
U0          app_registry_rescan(U0);

U0 app_registry_register_shell(U0);   // `pkg` console command

#endif // APP_REGISTRY_H
