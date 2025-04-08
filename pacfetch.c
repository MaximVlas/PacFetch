#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>
#include <pwd.h>
#include <ctype.h>

#define MAX_CMD_LEN 1024
#define MAX_PATH_LEN 512
#define LOG_DIR ".pacfetch"
#define LOG_FILE "install_log.txt"
#define DB_FILE "packages.db"
#define CONFIG_FILE "config.ini"
#define MAX_LINE_LEN 256
#define MAX_MANAGERS 10

// Function prototypes


typedef struct {
    char name[32];          // e.g., "pacman", "yay"
    char type[32];          // "official" or "aur"
    char install_flags[64]; // e.g., "-S --needed"
    char remove_flags[64];  // e.g., "-R"
    char upgrade_flags[64]; // e.g., "-Syu"
    int use_sudo;           // 1 or 0
} PackageManagerConfig;

typedef struct {
    PackageManagerConfig managers[MAX_MANAGERS];
    int manager_count;
    char system_upgrade_manager[32]; // Manager for system-wide upgrades
} PackfetchConfig;

typedef struct {
    char version[64];
    long long size;  // in bytes
    int dependency_count;
    char source[16];  // "official" or "AUR"
} PackageDetails;

int get_package_details(const char *package_name, PackageDetails *details);
char* get_command_string(int argc, char *argv[]);
void init_pacfetch(void);
void log_installation(const char *package_name, const char *install_dir, const char *command_used, const char *manager);
void install_package(int argc, char *argv[], PackfetchConfig *config, const char *specified_manager);
void remove_package(int argc, char *argv[], PackfetchConfig *config, const char *specified_manager);
void upgrade_packages(int argc, char *argv[], PackfetchConfig *config, const char *specified_manager);

void query_package(int argc, char *argv[]);
void log_removal(const char *package_name, const char *command_used, const char *manager);
void log_upgrade(const char *package_name, const char *command_used, const char *manager);
int check_if_installed(const char *package_name);
int validate_package_name(const char *package_name);
char* sanitize_input(const char *input);
void export_package_list(const char *filename);
void help(void);
char* get_current_dir(void);
char* get_log_dir(void);
void create_dir_if_not_exists(const char *path);
void log_system_upgrade(const char *command_used);
void load_config(PackfetchConfig *config);
int execute_package_manager(const char *package_manager, const char *action, const char *flags, const char *package, int use_sudo);
void backup_packages(const char *filename);
void import_packages(const char *filename);
void clean_orphans(void);
void search_packages(int argc, char *argv[]);
long long estimate_package_size(const char *package_name);
void check_consistency(void);

// Structure to hold log events
struct Event {
    char package_name[64];
    time_t timestamp;
    char operation[16];
};


// Comparator for sorting events
int compare_events(const void *a, const void *b) {
    struct Event *e1 = (struct Event *)a;
    struct Event *e2 = (struct Event *)b;
    int cmp = strcmp(e1->package_name, e2->package_name);
    if (cmp != 0) return cmp;
    return (e1->timestamp > e2->timestamp) - (e1->timestamp < e2->timestamp);
}

// Parse timestamp string to time_t
time_t parse_timestamp(const char *timestamp_str) {
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    if (sscanf(timestamp_str, "%d-%d-%d %d:%d:%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
        return -1;
    }
    tm.tm_year -= 1900; // Years since 1900
    tm.tm_mon -= 1;     // Months are 0-based
    tm.tm_isdst = -1;   // Unknown DST
    return mktime(&tm);
}

// Format duration for display
void print_duration(time_t seconds) {
    int days = seconds / 86400;
    seconds %= 86400;
    int hours = seconds / 3600;
    seconds %= 3600;
    int minutes = seconds / 60;
    seconds %= 60;
    printf("%d days, %d hours, %d minutes, %d seconds", days, hours, minutes, (int)seconds);
}

// Calculate and display usage durations
void calculate_duration(void) {
    char *log_dir_path = get_log_dir();
    if (log_dir_path == NULL) {
        printf("Error: Failed to get log directory\n");
        return;
    }
    char log_path[MAX_PATH_LEN];
    snprintf(log_path, MAX_PATH_LEN, "%s/%s", log_dir_path, LOG_FILE);

    FILE *log = fopen(log_path, "r");
    if (log == NULL) {
        printf("Error: Failed to open log file %s\n", log_path);
        free(log_dir_path);
        return;
    }

    #define MAX_EVENTS 10000
    struct Event events[MAX_EVENTS];
    int event_count = 0;
    char line[MAX_CMD_LEN];

    while (fgets(line, MAX_CMD_LEN, log) != NULL) {
        char timestamp_str[64], operation[16], package_name[64];
        if (sscanf(line, "%63[^,],%15[^,],%63[^,]", timestamp_str, operation, package_name) == 3) {
            if (strcmp(operation, "installed") == 0 || strcmp(operation, "removed") == 0) {
                time_t timestamp = parse_timestamp(timestamp_str);
                if (timestamp != -1) {
                    strncpy(events[event_count].package_name, package_name, 63);
                    events[event_count].package_name[63] = '\0';
                    events[event_count].timestamp = timestamp;
                    strncpy(events[event_count].operation, operation, 15);
                    events[event_count].operation[15] = '\0';
                    event_count++;
                    if (event_count >= MAX_EVENTS) {
                        printf("Warning: Too many events, truncating.\n");
                        break;
                    }
                }
            }
        }
    }
    fclose(log);
    free(log_dir_path);

    if (event_count == 0) {
        printf("No installation or removal events found.\n");
        return;
    }

    qsort(events, event_count, sizeof(struct Event), compare_events);

    char current_package[64] = "";
    time_t last_install_time = -1;
    time_t total_duration = 0;
    time_t now = time(NULL);

    for (int i = 0; i < event_count; i++) {
        struct Event *event = &events[i];
        if (strcmp(event->package_name, current_package) != 0) {
            if (strlen(current_package) > 0) {
                if (last_install_time != -1) {
                    total_duration += now - last_install_time;
                }
                printf("%s: ", current_package);
                print_duration(total_duration);
                printf("\n");
            }
            strcpy(current_package, event->package_name);
            last_install_time = -1;
            total_duration = 0;
        }
        if (strcmp(event->operation, "installed") == 0) {
            if (last_install_time != -1) {
                printf("Warning: Multiple installs without remove for %s\n", event->package_name);
            }
            last_install_time = event->timestamp;
        } else if (strcmp(event->operation, "removed") == 0) {
            if (last_install_time == -1) {
                printf("Warning: Remove without install for %s\n", event->package_name);
            } else {
                total_duration += event->timestamp - last_install_time;
                last_install_time = -1;
            }
        }
    }
    // Handle the last package
    if (strlen(current_package) > 0) {
        if (last_install_time != -1) {
            total_duration += now - last_install_time;
        }
        printf("%s: ", current_package);
        print_duration(total_duration);
        printf("\n");
    }
}

void check_consistency(void) {
    char *log_dir_path = get_log_dir();
    if (!log_dir_path) {
        printf("Error: Failed to get log directory\n");
        return;
    }

    char db_path[MAX_PATH_LEN];
    snprintf(db_path, MAX_PATH_LEN, "%s/%s", log_dir_path, DB_FILE);

    FILE *db = fopen(db_path, "r");
    if (!db) {
        printf("No tracked packages to check.\n");
        free(log_dir_path);
        return;
    }

    printf("Checking consistency between tracked and installed packages...\n");

    char line[MAX_CMD_LEN];
    int discrepancies = 0;

    while (fgets(line, MAX_CMD_LEN, db)) {
        char *pkg_name = strtok(line, ",");
        if (pkg_name) {
            char cmd[MAX_CMD_LEN];
            snprintf(cmd, MAX_CMD_LEN, "pacman -Q %s >/dev/null 2>&1", pkg_name);
            if (system(cmd) != 0) {
                printf("Discrepancy: %s is tracked but not installed.\n", pkg_name);
                discrepancies++;
            }
        }
    }
    fclose(db);

    FILE *installed = popen("pacman -Qeq", "r");
    if (!installed) {
        printf("Error: Failed to query installed packages\n");
        free(log_dir_path);
        return;
    }

    char pkg[MAX_CMD_LEN];
    while (fgets(pkg, MAX_CMD_LEN, installed)) {
        pkg[strcspn(pkg, "\n")] = 0;
        if (!check_if_installed(pkg)) {
            printf("Discrepancy: %s is installed but not tracked.\n", pkg);
            discrepancies++;
        }
    }
    pclose(installed);

    if (discrepancies == 0) {
        printf("No discrepancies found.\n");
    } else {
        printf("Found %d discrepancies.\n", discrepancies);
    }

    free(log_dir_path);
}

void vulnerability_scan(void) {
    if (system("command -v arch-audit >/dev/null 2>&1") != 0) {
        printf("Error: arch-audit is not installed. Please install it via 'pacman -S arch-audit'.\n");
        return;
    }
    printf("Running vulnerability scan with arch-audit...\n");
    int ret = system("arch-audit");
    if (ret != 0) {
        printf("Warning: arch-audit returned non-zero exit code.\n");
    }
}


int main(int argc, char *argv[]) {
    init_pacfetch();
    PackfetchConfig config;
    load_config(&config);

    if (argc < 2) {
        help();
        return 1;
    }

    char *specified_manager = NULL;
    int i = 1;
    while (i < argc) {
        if (strncmp(argv[i], "--manager=", 10) == 0) {
            specified_manager = argv[i] + 10;
            for (int j = i; j < argc - 1; j++) {
                argv[j] = argv[j + 1];
            }
            argc--;
        } else {
            i++;
        }
    }

    if (strcmp(argv[1], "-S") == 0 || strcmp(argv[1], "--sync") == 0) {
        install_package(argc, argv, &config, specified_manager);
    } else if (strcmp(argv[1], "-R") == 0 || strcmp(argv[1], "--remove") == 0) {
        remove_package(argc, argv, &config, specified_manager);
    } else if (strcmp(argv[1], "-U") == 0 || strcmp(argv[1], "--upgrade") == 0) {
        upgrade_packages(argc, argv, &config, specified_manager);
    } else if (strcmp(argv[1], "-B") == 0 || strcmp(argv[1], "--backup") == 0) {
        if (argc < 3) {
            printf("Error: No filename specified for backup\n");
            return 1;
        }
        backup_packages(argv[2]);
    } else if (strcmp(argv[1], "-I") == 0 || strcmp(argv[1], "--import") == 0) {
        if (argc < 3) {
            printf("Error: No filename specified for import\n");
            return 1;
        }
        import_packages(argv[2]);
    } else if (strcmp(argv[1], "-C") == 0 || strcmp(argv[1], "--clean-orphans") == 0) {
        clean_orphans();
    } else if (strcmp(argv[1], "-Ss") == 0) {
        search_packages(argc, argv);
    } else if (strcmp(argv[1], "-Q") == 0 || strcmp(argv[1], "--query") == 0) {
        query_package(argc, argv);
    } else if (strcmp(argv[1], "-D") == 0 || strcmp(argv[1], "--duration") == 0) {
        calculate_duration();
    } else if (strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--vuln-scan") == 0) {
        vulnerability_scan();
    } else if (strcmp(argv[1], "-E") == 0 || strcmp(argv[1], "--export") == 0) {
        if (argc < 3) {
            printf("Error: No filename specified for export\n");
            return 1;
        }
        export_package_list(argv[2]);
    } else if (strcmp(argv[1], "--check") == 0) {
        check_consistency();
    } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        help();
    } else {
        printf("Unknown command: %s\n", argv[1]);
        help();
        return 1;
    }

    return 0;
}

void init_pacfetch(void) {
    char *log_dir_path = get_log_dir();
    create_dir_if_not_exists(log_dir_path);
    free(log_dir_path);
}

#if 0
void init_default_config(PackfetchConfig *config) {
    strcpy(config->default_package_manager, "pacman");
    config->use_sudo = 1;
    strcpy(config->install_flags, "-S --needed");
    strcpy(config->remove_flags, "-R");
    strcpy(config->upgrade_flags, "-Syu");
}
#endif

void install_package(int argc, char *argv[], PackfetchConfig *config, const char *specified_manager) {
    if (argc < 3) {
        printf("Error: No package specified\n");
        return;
    }
    char *package_name = argv[2];
    if (!validate_package_name(package_name)) {
        printf("Error: Invalid package name '%s'\n", package_name);
        return;
    }
    if (check_if_installed(package_name)) {
        printf("Package %s already tracked. Use -U to upgrade.\n", package_name);
        return;
    }

    char *manager_to_use = NULL;
    if (specified_manager) {
        for (int i = 0; i < config->manager_count; i++) {
            if (strcmp(config->managers[i].name, specified_manager) == 0) {
                manager_to_use = config->managers[i].name;
                break;
            }
        }
        if (!manager_to_use) {
            printf("Error: Manager '%s' not configured\n", specified_manager);
            return;
        }
    }

    int result = -1;
    if (manager_to_use) {
        for (int i = 0; i < config->manager_count; i++) {
            if (strcmp(config->managers[i].name, manager_to_use) == 0) {
                result = execute_package_manager(manager_to_use, "install",
                                                 config->managers[i].install_flags,
                                                 package_name, config->managers[i].use_sudo);
                break;
            }
        }
    } else {
        for (int i = 0; i < config->manager_count; i++) {
            if (strcmp(config->managers[i].type, "official") == 0) {
                result = execute_package_manager(config->managers[i].name, "install",
                                                 config->managers[i].install_flags,
                                                 package_name, config->managers[i].use_sudo);
                if (result == 0) {
                    manager_to_use = config->managers[i].name;
                    break;
                }
            }
        }
        if (result != 0) {
            for (int i = 0; i < config->manager_count; i++) {
                if (strcmp(config->managers[i].type, "aur") == 0) {
                    result = execute_package_manager(config->managers[i].name, "install",
                                                     config->managers[i].install_flags,
                                                     package_name, config->managers[i].use_sudo);
                    if (result == 0) {
                        manager_to_use = config->managers[i].name;
                        break;
                    }
                }
            }
        }
    }

    if (result != 0) {
        printf("Failed to install %s with any manager\n", package_name);
        return;
    }

    char *current_dir = get_current_dir();
    char *command_str = get_command_string(argc, argv);
    log_installation(package_name, current_dir, command_str, manager_to_use);
    if (current_dir) free(current_dir);
    if (command_str) free(command_str);
    printf("Installed %s with %s\n", package_name, manager_to_use);
}

char* get_installation_manager(const char *package_name) {
    char *log_dir_path = get_log_dir();
    if (!log_dir_path) return NULL;
    char db_path[MAX_PATH_LEN];
    snprintf(db_path, MAX_PATH_LEN, "%s/%s", log_dir_path, DB_FILE);
    FILE *db = fopen(db_path, "r");
    if (!db) {
        free(log_dir_path);
        return NULL;
    }
    char line[MAX_CMD_LEN];
    while (fgets(line, MAX_CMD_LEN, db)) {
        char *fields[10];
        int field_count = 0;
        char *token = strtok(line, ",");
        while (token && field_count < 10) {
            fields[field_count++] = token;
            token = strtok(NULL, ",");
        }
        if (field_count >= 4 && strcmp(fields[0], package_name) == 0) {
            char *manager = fields[3];
            char *result = strdup(manager);
            fclose(db);
            free(log_dir_path);
            return result;
        }
    }
    fclose(db);
    free(log_dir_path);
    return NULL;
}

void clean_orphans(void) {
    printf("Checking for orphaned packages...\n");
    FILE *fp = popen("pacman -Qdtq", "r");
    if (fp == NULL) return;

    // Reserve space for "sudo pacman -Rns " (17 bytes) and some buffer (e.g., 100 bytes total)
    char orphans[MAX_CMD_LEN - 100];
    orphans[0] = '\0';  // Initialize as empty string

    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        // Remove newline from line
        line[strcspn(line, "\n")] = '\0';

        // Check if adding the next package name exceeds the buffer
        if (strlen(orphans) + strlen(line) + 1 < sizeof(orphans)) {
            if (orphans[0] != '\0') strcat(orphans, " ");  // Add space between package names
            strcat(orphans, line);
        } else {
            printf("Warning: Too many orphaned packages, cannot remove all at once.\n");
            break;
        }
    }
    pclose(fp);

    if (strlen(orphans) > 0) {
        printf("Orphaned packages found: %s\n", orphans);
        printf("Remove them? (y/n): ");
        char response;
        scanf(" %c", &response);
        if (response == 'y' || response == 'Y') {
            char cmd[MAX_CMD_LEN];
            snprintf(cmd, MAX_CMD_LEN, "sudo pacman -Rns %s", orphans);
            system(cmd);
        }
    } else {
        printf("No orphaned packages found.\n");
    }
}

void backup_packages(const char *filename) {
    export_package_list(filename);  // Reuse existing function
}

void import_packages(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Error: Could not open backup file %s\n", filename);
        return;
    }
    char line[MAX_CMD_LEN];
    PackfetchConfig config;
    load_config(&config);
    
    // Find the system upgrade manager's config
    PackageManagerConfig *mgr = NULL;
    for (int i = 0; i < config.manager_count; i++) {
        if (strcmp(config.managers[i].name, config.system_upgrade_manager) == 0) {
            mgr = &config.managers[i];
            break;
        }
    }
    if (mgr == NULL) {
        printf("Error: System upgrade manager '%s' not found\n", config.system_upgrade_manager);
        fclose(file);
        return;
    }
    
    while (fgets(line, MAX_CMD_LEN, file) != NULL) {
        if (line[0] == '#') continue;  // Skip comments
        char *pkg_name = strtok(line, ",");
        if (pkg_name && !check_if_installed(pkg_name)) {
            execute_package_manager(mgr->name, "install", mgr->install_flags, pkg_name, mgr->use_sudo);
        }
    }
    fclose(file);
}

void export_package_list(const char *filename) {
    char *log_dir_path = get_log_dir();
    if (log_dir_path == NULL) {
        printf("Error: Failed to get log directory\n");
        return;
    }
    
    char db_path[MAX_PATH_LEN];
    snprintf(db_path, MAX_PATH_LEN, "%s/%s", log_dir_path, DB_FILE);
    
    FILE *db = fopen(db_path, "r");
    if (db == NULL) {
        printf("Error: No package database found at %s\n", db_path);
        free(log_dir_path);
        return;
    }
    
    FILE *export_file = fopen(filename, "w");
    if (export_file == NULL) {
        printf("Error: Could not create export file %s\n", filename);
        fclose(db);
        free(log_dir_path);
        return;
    }
    
    printf("Exporting package list to %s...\n", filename);
    fprintf(export_file, "# PacFetch package list exported on %s\n", __DATE__);
    fprintf(export_file, "# Format: package_name,install_date,install_directory\n");
    
    char line[MAX_CMD_LEN];
    while (fgets(line, MAX_CMD_LEN, db) != NULL) {
        fputs(line, export_file);
    }
    
    fclose(db);
    fclose(export_file);
    free(log_dir_path);
    
    printf("Export completed successfully to %s\n", filename);
}

int execute_package_manager(const char *package_manager, const char *action, const char *flags, const char *package, int use_sudo) {
    if (!validate_package_name(package)) {
        printf("Error: Invalid package name\n");
        return -1;
    }
    
    char *sanitized_package = sanitize_input(package);
    if (sanitized_package == NULL) {
        printf("Error: Failed to sanitize package name\n");
        return -1;
    }
    
    char cmd[MAX_CMD_LEN];
    
    printf("Performing %s action on package %s using %s...\n", 
           action, sanitized_package, package_manager);
    
    if (use_sudo) {
        snprintf(cmd, MAX_CMD_LEN, "sudo %s %s %s", package_manager, flags, sanitized_package);
    } else {
        snprintf(cmd, MAX_CMD_LEN, "%s %s %s", package_manager, flags, sanitized_package);
    }
    
    printf("Executing: %s\n", cmd);
    int result = system(cmd);
    
    free(sanitized_package);
    return result;
}

void load_config(PackfetchConfig *config) {
    config->manager_count = 0;
    strcpy(config->system_upgrade_manager, "");

    char *log_dir_path = get_log_dir();
    char config_path[MAX_PATH_LEN];
    snprintf(config_path, MAX_PATH_LEN, "%s/%s", log_dir_path, CONFIG_FILE);

    FILE *cfg = fopen(config_path, "r");
    if (cfg == NULL) {
        // Set default configuration
        if (config->manager_count < MAX_MANAGERS) {
            strcpy(config->managers[0].name, "pacman");
            strcpy(config->managers[0].type, "official");
            strcpy(config->managers[0].install_flags, "-S --needed");
            strcpy(config->managers[0].remove_flags, "-R");
            strcpy(config->managers[0].upgrade_flags, "-Syu");
            config->managers[0].use_sudo = 1;
            config->manager_count++;
        }
        if (config->manager_count < MAX_MANAGERS) {
            strcpy(config->managers[1].name, "yay");
            strcpy(config->managers[1].type, "aur");
            strcpy(config->managers[1].install_flags, "-S --needed");
            strcpy(config->managers[1].remove_flags, "-R");
            strcpy(config->managers[1].upgrade_flags, "-Syu");
            config->managers[1].use_sudo = 0;
            config->manager_count++;
        }
        strcpy(config->system_upgrade_manager, "yay");
        free(log_dir_path);
        return;
    }

    char line[MAX_LINE_LEN];
    char current_section[32] = "";
    while (fgets(line, MAX_LINE_LEN, cfg) != NULL) {
        line[strcspn(line, "\n")] = 0;
        if (line[0] == '[') {
            sscanf(line, "[%31[^]]", current_section);
        } else if (strlen(line) > 0 && line[0] != '#') {
            char key[32], value[64];
            if (sscanf(line, "%31[^=]=%63s", key, value) == 2) {
                if (strcmp(current_section, "package_managers") == 0) {
                    if (config->manager_count < MAX_MANAGERS) {
                        strcpy(config->managers[config->manager_count].name, key);
                        strcpy(config->managers[config->manager_count].type, value);
                        config->manager_count++;
                    }
                } else if (strcmp(current_section, "default") == 0) {
                    if (strcmp(key, "system_upgrade_manager") == 0) {
                        strcpy(config->system_upgrade_manager, value);
                    }
                } else {
                    for (int i = 0; i < config->manager_count; i++) {
                        if (strcmp(config->managers[i].name, current_section) == 0) {
                            if (strcmp(key, "install_flags") == 0) {
                                strcpy(config->managers[i].install_flags, value);
                            } else if (strcmp(key, "remove_flags") == 0) {
                                strcpy(config->managers[i].remove_flags, value);
                            } else if (strcmp(key, "upgrade_flags") == 0) {
                                strcpy(config->managers[i].upgrade_flags, value);
                            } else if (strcmp(key, "use_sudo") == 0) {
                                config->managers[i].use_sudo = atoi(value);
                            }
                        }
                    }
                }
            }
        }
    }
    fclose(cfg);
    free(log_dir_path);
}


int validate_package_name(const char *package_name) {
    if (package_name == NULL || strlen(package_name) == 0) {
        return 0;
    }
    
    // Check for valid package name characters
    // Allow alphanumeric, hyphens, underscores, and periods (common in package names)
    for (size_t i = 0; i < strlen(package_name); i++) {
        char c = package_name[i];
        if (!((c >= 'a' && c <= 'z') || 
              (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || 
              c == '-' || c == '_' || c == '.')) {
            return 0;
        }
    }
    
    return 1;
}

char* sanitize_input(const char *input) {
    if (input == NULL) {
        return NULL;
    }
    
    char *sanitized = malloc(strlen(input) + 1);
    if (sanitized == NULL) {
        return NULL;
    }
    
    size_t j = 0;
    for (size_t i = 0; i < strlen(input); i++) {
        char c = input[i];
        if ((c >= 'a' && c <= 'z') || 
            (c >= 'A' && c <= 'Z') || 
            (c >= '0' && c <= '9') || 
            c == '-' || c == '_' || c == '.') {
            sanitized[j++] = c;
        }
    }
    sanitized[j] = '\0';
    
    return sanitized;
}

void remove_package(int argc, char *argv[], PackfetchConfig *config, const char *specified_manager) {
    if (argc < 3) {
        printf("Error: No package specified\n");
        return;
    }
    char *package_name = argv[2];
    if (!validate_package_name(package_name)) {
        printf("Error: Invalid package name '%s'\n", package_name);
        return;
    }

    char *manager_to_use = NULL;
    if (specified_manager) {
        manager_to_use = (char *)specified_manager;
    } else {
        manager_to_use = get_installation_manager(package_name);
        if (!manager_to_use) {
            for (int i = 0; i < config->manager_count; i++) {
                if (strcmp(config->managers[i].type, "official") == 0) {
                    manager_to_use = config->managers[i].name;
                    break;
                }
            }
        }
    }

    if (!manager_to_use) {
        printf("Error: No suitable manager found\n");
        return;
    }

    PackageManagerConfig *mgr_config = NULL;
    for (int i = 0; i < config->manager_count; i++) {
        if (strcmp(config->managers[i].name, manager_to_use) == 0) {
            mgr_config = &config->managers[i];
            break;
        }
    }
    if (!mgr_config) {
        printf("Error: Manager '%s' not configured\n", manager_to_use);
        free(manager_to_use);
        return;
    }

    int result = execute_package_manager(manager_to_use, "remove",
                                         mgr_config->remove_flags, package_name,
                                         mgr_config->use_sudo);
    if (result == 0) {
        char *command_str = get_command_string(argc, argv);
        log_removal(package_name, command_str, manager_to_use);
        if (command_str) free(command_str);
        printf("Removed %s with %s\n", package_name, manager_to_use);
    } else {
        printf("Failed to remove %s\n", package_name);
    }
    if (!specified_manager && manager_to_use) free(manager_to_use);
}

void query_package(int argc, char *argv[]) {
    if (argc < 3) {
        // List all tracked packages
        char *log_dir_path = get_log_dir();
        if (log_dir_path == NULL) {
            printf("Error: Failed to get log directory\n");
            return;
        }
        
        char db_path[MAX_PATH_LEN];
        snprintf(db_path, MAX_PATH_LEN, "%s/%s", log_dir_path, DB_FILE);
        
        FILE *db = fopen(db_path, "r");
        if (db == NULL) {
            printf("No tracked packages found.\n");
            free(log_dir_path);
            return;
        }
        
        printf("Packages tracked by PacFetch:\n");
        printf("%-20s %-20s %-40s\n", "Package", "Install Date", "Directory");
        printf("%-20s %-20s %-40s\n", "-------", "------------", "---------");
        
        char line[MAX_CMD_LEN];
        while (fgets(line, MAX_CMD_LEN, db) != NULL) {
            char line_copy[MAX_CMD_LEN];
            strcpy(line_copy, line);
            
            char *pkg_name = strtok(line_copy, ",");
            char *install_date = strtok(NULL, ",");
            char *install_dir = strtok(NULL, "\n");
            
            if (pkg_name != NULL && install_date != NULL && install_dir != NULL) {
                printf("%-20s %-20s %-40s\n", pkg_name, install_date, install_dir);
            }
        }
        
        fclose(db);
        free(log_dir_path);
    } else {
        char *package_name = argv[2];
        
        // Check if it's tracked and show details if yes
        if (check_if_installed(package_name)) {
            printf("Package %s is tracked by PacFetch.\n", package_name);
            char *log_dir_path = get_log_dir();
            if (log_dir_path != NULL) {
                char db_path[MAX_PATH_LEN];
                snprintf(db_path, MAX_PATH_LEN, "%s/%s", log_dir_path, DB_FILE);
                FILE *db = fopen(db_path, "r");
                if (db != NULL) {
                    char line[MAX_CMD_LEN];
                    while (fgets(line, MAX_CMD_LEN, db) != NULL) {
                        char line_copy[MAX_CMD_LEN];
                        strcpy(line_copy, line);
                        char *pkg_name = strtok(line_copy, ",");
                        if (pkg_name != NULL && strcmp(pkg_name, package_name) == 0) {
                            char *install_date = strtok(NULL, ",");
                            char *install_dir = strtok(NULL, "\n");
                            if (install_date != NULL && install_dir != NULL) {
                                printf("  Installed on: %s\n", install_date);
                                printf("  Install directory: %s\n", install_dir);
                            }
                            break;
                        }
                    }
                    fclose(db);
                }
                free(log_dir_path);
            }
        } else {
            printf("Package %s is not tracked by PacFetch.\n", package_name);
        }
        
        // Show history from log file
        printf("\nHistory for package %s:\n", package_name);
        char *log_dir_path = get_log_dir();
        if (log_dir_path != NULL) {
            char log_path[MAX_PATH_LEN];
            snprintf(log_path, MAX_PATH_LEN, "%s/%s", log_dir_path, LOG_FILE);
            FILE *log = fopen(log_path, "r");
            if (log != NULL) {
                char line[MAX_CMD_LEN];
                int found = 0;
                while (fgets(line, MAX_CMD_LEN, log) != NULL) {
                    char *fields[10];
                    int field_count = 0;
                    char *token = strtok(line, ",");
                    while (token != NULL && field_count < 10) {
                        fields[field_count++] = token;
                        token = strtok(NULL, ",");
                    }
                    if (field_count >= 3 && strcmp(fields[2], package_name) == 0) {
                        found = 1;
                        // Trim trailing newline from last field
                        if (field_count > 0) {
                            char *last_field = fields[field_count - 1];
                            size_t len = strlen(last_field);
                            if (len > 0 && last_field[len - 1] == '\n') {
                                last_field[len - 1] = '\0';
                            }
                        }
                        if (strcmp(fields[1], "installed") == 0 && field_count >= 9) {
                            printf("%s: Installed version %s from %s, size %s bytes, %s dependencies, command: %s, user: %s\n",
                                   fields[0], fields[3], fields[4], fields[5], fields[6], fields[7], fields[8]);
                        } else if (strcmp(fields[1], "removed") == 0 && field_count >= 5) {
                            printf("%s: Removed, command: %s, user: %s\n",
                                   fields[0], fields[3], fields[4]);
                        } else if (strcmp(fields[1], "upgraded") == 0 && field_count >= 9) {
                            printf("%s: Upgraded to version %s from %s, size %s bytes, %s dependencies, command: %s, user: %s\n",
                                   fields[0], fields[3], fields[4], fields[5], fields[6], fields[7], fields[8]);
                        }
                    }
                }
                if (!found) {
                    printf("No history found for %s in the log.\n", package_name);
                }
                fclose(log);
            } else {
                printf("Error: Failed to open log file %s\n", log_path);
            }
            free(log_dir_path);
        } else {
            printf("Error: Failed to get log directory\n");
        }
        
        // Check if it's installed according to pacman
        char query_cmd[MAX_CMD_LEN];
        snprintf(query_cmd, MAX_CMD_LEN, "pacman -Q %s >/dev/null 2>&1", package_name);
        if (system(query_cmd) == 0) {
            printf("\nCurrent package details from pacman:\n");
            snprintf(query_cmd, MAX_CMD_LEN, "pacman -Qi %s", package_name);
            system(query_cmd);
        } else {
            printf("\nPackage is not currently installed according to pacman.\n");
        }
    }
}

long long estimate_package_size(const char *package_name) {
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, MAX_CMD_LEN, "pacman -Si %s", package_name);
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    long long total_size = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "Download Size   :") || strstr(line, "Installed Size  :")) {
            float size;
            char unit[8];
            sscanf(line, "%*s %*s : %f %s", &size, unit);
            if (strcmp(unit, "KiB") == 0) total_size += (long long)(size * 1024);
            else if (strcmp(unit, "MiB") == 0) total_size += (long long)(size * 1024 * 1024);
            else if (strcmp(unit, "GiB") == 0) total_size += (long long)(size * 1024 * 1024 * 1024);
        }
    }
    pclose(fp);
    return total_size;
}


int get_package_details(const char *package_name, PackageDetails *details) {
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, MAX_CMD_LEN, "pacman -Qi %s", package_name);
    
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        return -1;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "Version         :") != NULL) {
            sscanf(line, "Version         : %s", details->version);
        } else if (strstr(line, "Installed Size  :") != NULL) {
            char size_str[32];
            char unit[8];
            sscanf(line, "Installed Size  : %s %s", size_str, unit);
            float size;
            sscanf(size_str, "%f", &size);
            if (strcmp(unit, "KiB") == 0) {
                details->size = (long long)(size * 1024);
            } else if (strcmp(unit, "MiB") == 0) {
                details->size = (long long)(size * 1024 * 1024);
            } else if (strcmp(unit, "GiB") == 0) {
                details->size = (long long)(size * 1024 * 1024 * 1024);
            } else {
                details->size = 0;  // Unknown unit
            }
        } else if (strstr(line, "Depends On      :") != NULL) {
            char *deps = strstr(line, ":") + 1;
            if (deps != NULL) {
                int count = 0;
                char *token = strtok(deps, " ");
                while (token != NULL) {
                    if (token[0] != '\0' && strcmp(token, "None") != 0) count++;
                    token = strtok(NULL, " ");
                }
                details->dependency_count = count;
            }
        }
    }
    pclose(fp);
    
    // Determine source: official if pacman -Si succeeds, AUR otherwise
    snprintf(cmd, MAX_CMD_LEN, "pacman -Si %s >/dev/null 2>&1", package_name);
    if (system(cmd) == 0) {
        strcpy(details->source, "official");
    } else {
        strcpy(details->source, "AUR");
    }
    
    return 0;
}

char* get_command_string(int argc, char *argv[]) {
    char *cmd = malloc(MAX_CMD_LEN);
    if (cmd == NULL) return NULL;
    cmd[0] = '\0';
    for (int i = 0; i < argc; i++) {
        if (i > 0) strcat(cmd, " ");
        strcat(cmd, argv[i]);
    }
    return cmd;
}

void log_installation(const char *package_name, const char *install_dir, const char *command_used, const char *manager) {
    char *log_dir_path = get_log_dir();
    char log_path[MAX_PATH_LEN];
    char db_path[MAX_PATH_LEN];
    snprintf(log_path, MAX_PATH_LEN, "%s/%s", log_dir_path, LOG_FILE);
    snprintf(db_path, MAX_PATH_LEN, "%s/%s", log_dir_path, DB_FILE);

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

    PackageDetails details;
    get_package_details(package_name, &details);
    char *user = getlogin() ? getlogin() : "unknown";

    FILE *log = fopen(log_path, "a");
    if (log) {
        fprintf(log, "%s,installed,%s,%s,%s,%lld,%d,%s,%s\n",
                time_str, package_name, details.version, details.source, details.size,
                details.dependency_count, command_used, user);
        fclose(log);
    }

    FILE *db = fopen(db_path, "a+");
    if (db) {
        fseek(db, 0, SEEK_SET);
        char line[MAX_CMD_LEN];
        int exists = 0;
        while (fgets(line, MAX_CMD_LEN, db)) {
            char *pkg_name = strtok(line, ",");
            if (pkg_name && strcmp(pkg_name, package_name) == 0) {
                exists = 1;
                break;
            }
        }
        if (!exists) {
            fprintf(db, "%s,%s,%s,%s,%s,%s\n", package_name, time_str, install_dir, manager, details.version, details.source);
        } else {
            fclose(db);
            char temp_db_path[MAX_PATH_LEN];
            snprintf(temp_db_path, MAX_PATH_LEN, "%s/%s.tmp", log_dir_path, DB_FILE);
            FILE *db_read = fopen(db_path, "r");
            FILE *temp_db = fopen(temp_db_path, "w");
            if (db_read && temp_db) {
                while (fgets(line, MAX_CMD_LEN, db_read)) {
                    char line_copy[MAX_CMD_LEN];
                    strcpy(line_copy, line);
                    char *pkg_name = strtok(line_copy, ",");
                    if (pkg_name && strcmp(pkg_name, package_name) == 0) {
                        fprintf(temp_db, "%s,%s,%s,%s,%s,%s\n", package_name, time_str, install_dir, manager, details.version, details.source);
                    } else {
                        fputs(line, temp_db);
                    }
                }
                fclose(db_read);
                fclose(temp_db);
                remove(db_path);
                rename(temp_db_path, db_path);
            }
        }
        if (!exists) fclose(db);
    }
    free(log_dir_path);
}

void log_removal(const char *package_name, const char *command_used, const char *manager) {
    char *log_dir_path = get_log_dir();
    if (log_dir_path == NULL) {
        printf("Error: Failed to get log directory\n");
        return;
    }

    char log_path[MAX_PATH_LEN];
    char db_path[MAX_PATH_LEN];
    char temp_db_path[MAX_PATH_LEN];
    snprintf(log_path, MAX_PATH_LEN, "%s/%s", log_dir_path, LOG_FILE);
    snprintf(db_path, MAX_PATH_LEN, "%s/%s", log_dir_path, DB_FILE);
    snprintf(temp_db_path, MAX_PATH_LEN, "%s/%s.tmp", log_dir_path, DB_FILE);

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

    char *user = getlogin();
    if (user == NULL) {
        user = "unknown";
    }

    FILE *log = fopen(log_path, "a");
    if (log != NULL) {
        fprintf(log, "%s,removed,%s,%s,%s,%s\n", time_str, package_name, command_used, user, manager);
        fclose(log);
    } else {
        printf("Warning: Failed to write to log file %s\n", log_path);
    }

    FILE *db = fopen(db_path, "r");
    FILE *temp_db = fopen(temp_db_path, "w");

    if (db != NULL && temp_db != NULL) {
        char line[MAX_CMD_LEN];
        char line_copy[MAX_CMD_LEN];

        while (fgets(line, MAX_CMD_LEN, db) != NULL) {
            strcpy(line_copy, line);
            char *pkg_name = strtok(line_copy, ",");
            if (pkg_name != NULL && strcmp(pkg_name, package_name) != 0) {
                fputs(line, temp_db);
            }
        }
        fclose(db);
        fclose(temp_db);
        remove(db_path);
        rename(temp_db_path, db_path);
    }

    free(log_dir_path);
}


// Fix for the upgrade_packages function to address the unused variable warning
// void upgrade_packages(int argc, char *argv[], PackfetchConfig *config, const char *specified_manager) {
//     char *log_dir_path = get_log_dir();
//     if (!log_dir_path) {
//         printf("Error: Failed to get log directory\n");
//         return;
//     }

//     if (argc >= 3) {
//         char *package_name = argv[2];
//         if (!validate_package_name(package_name)) {
//             printf("Error: Invalid package name '%s'\n", package_name);
//             free(log_dir_path);
//             return;
//         }
    
//         char *manager_to_use = NULL;
//         int manager_allocated = 0;
//         if (specified_manager) {
//             manager_to_use = (char *)specified_manager;
//         } else {
//             manager_to_use = get_installation_manager(package_name);
//             if (manager_to_use) {
//                 manager_allocated = 1;
//             } else {
//                 for (int i = 0; i < config->manager_count; i++) {
//                     if (strcmp(config->managers[i].type, "official") == 0) {
//                         manager_to_use = config->managers[i].name;
//                         break;
//                     }
//                 }
//             }
//         }
//         if (manager_to_use) {
//             int manager_found = 0;
//             for (int i = 0; i < config->manager_count; i++) {
//                 if (strcmp(config->managers[i].name, manager_to_use) == 0) {
//                     mgr_config = &config->managers[i];
//                     manager_found = 1;
//                     break;
//                 }
//             }
//             if (!manager_found) {
//                 printf("Warning: Manager '%s' invalid, using default\n", manager_to_use);
//                 if (manager_allocated) free(manager_to_use);
//                 manager_to_use = NULL;
//             }
//         }
//         if (!manager_to_use) {
//             for (int i = 0; i < config->manager_count; i++) {
//                 if (strcmp(config->managers[i].type, "official") == 0) {
//                     manager_to_use = config->managers[i].name;
//                     mgr_config = &config->managers[i];
//                     break;
//                 }
//             }
//         }
//         PackageManagerConfig *mgr_config = NULL;
//         if (manager_to_use) {
//             for (int i = 0; i < config->manager_count; i++) {
//                 if (strcmp(config->managers[i].name, manager_to_use) == 0) {
//                     mgr_config = &config->managers[i];
//                     break;
//                 }
//             }
//         }
//         if (!mgr_config) {
//             printf("Error: Manager '%s' not configured\n", manager_to_use);
//             if (manager_allocated) free(manager_to_use);
//             free(log_dir_path);
//             return;
//         }
    
//         int result = execute_package_manager(manager_to_use, "upgrade",
//                                              mgr_config->install_flags, package_name,
//                                              mgr_config->use_sudo);
//         if (result == 0) {
//             char *command_str = get_command_string(argc, argv);
//             log_upgrade(package_name, command_str, manager_to_use);
//             if (command_str) free(command_str);
//             printf("Upgraded %s with %s\n", package_name, manager_to_use);
//         } else {
//             printf("Failed to upgrade %s\n", package_name);
//         }
//         if (manager_allocated) free(manager_to_use);
//     } else {
//         char *manager_to_use = config->system_upgrade_manager[0] ? config->system_upgrade_manager : NULL;
//         if (!manager_to_use) {
//             for (int i = 0; i < config->manager_count; i++) {
//                 if (strcmp(config->managers[i].type, "aur") == 0) {
//                     manager_to_use = config->managers[i].name;
//                     break;
//                 }
//             }
//             if (!manager_to_use) {
//                 for (int i = 0; i < config->manager_count; i++) {
//                     if (strcmp(config->managers[i].type, "official") == 0) {
//                         manager_to_use = config->managers[i].name;
//                         break;
//                     }
//                 }
//             }
//         }

//         PackageManagerConfig *mgr_config = NULL;
//         for (int i = 0; i < config->manager_count; i++) {
//             if (strcmp(config->managers[i].name, manager_to_use) == 0) {
//                 mgr_config = &config->managers[i];
//                 break;
//             }
//         }
//         if (!mgr_config) {
//             printf("Error: No suitable manager for system upgrade\n");
//             free(log_dir_path);
//             return;
//         }

//         char cmd[MAX_CMD_LEN];
//         snprintf(cmd, MAX_CMD_LEN, "%s%s %s", mgr_config->use_sudo ? "sudo " : "",
//                  manager_to_use, mgr_config->upgrade_flags);
//         system(cmd);
//         char *command_str = get_command_string(argc, argv);
//         log_system_upgrade(command_str ? command_str : "unknown command");
//         if (command_str) free(command_str);
//         printf("System upgrade completed with %s\n", manager_to_use);
//     }
//     free(log_dir_path);
// }

void upgrade_packages(int argc, char *argv[], PackfetchConfig *config, const char *specified_manager) {
    char *log_dir_path = get_log_dir();
    if (!log_dir_path) {
        printf("Error: Failed to get log directory\n");
        return;
    }

    // Declare variables at the function scope
    char *manager_to_use = NULL;
    int manager_allocated = 0;
    PackageManagerConfig *mgr_config = NULL;

    if (argc >= 3) {
        char *package_name = argv[2];
        if (!validate_package_name(package_name)) {
            printf("Error: Invalid package name '%s'\n", package_name);
            free(log_dir_path);
            return;
        }

        // Determine the package manager to use
        if (specified_manager) {
            manager_to_use = (char *)specified_manager;
        } else {
            manager_to_use = get_installation_manager(package_name);
            if (manager_to_use) {
                manager_allocated = 1;
            }
        }

        // Validate manager_to_use and set mgr_config
        if (manager_to_use) {
            for (int i = 0; i < config->manager_count; i++) {
                if (strcmp(config->managers[i].name, manager_to_use) == 0) {
                    mgr_config = &config->managers[i];
                    break;
                }
            }
            if (!mgr_config) {
                printf("Warning: Manager '%s' invalid, using default\n", manager_to_use);
                if (manager_allocated) free(manager_to_use);
                manager_to_use = NULL;
                manager_allocated = 0;
            }
        }

        // Fallback to the first official manager if necessary
        if (!manager_to_use) {
            for (int i = 0; i < config->manager_count; i++) {
                if (strcmp(config->managers[i].type, "official") == 0) {
                    manager_to_use = config->managers[i].name;
                    mgr_config = &config->managers[i];
                    break;
                }
            }
        }

        // Check if a valid manager configuration was found
        if (!mgr_config) {
            printf("Error: No suitable manager found\n");
            if (manager_allocated) free(manager_to_use);
            free(log_dir_path);
            return;
        }

        // Execute the package manager
        int result = execute_package_manager(manager_to_use, "upgrade",
                                             mgr_config->install_flags, package_name,
                                             mgr_config->use_sudo);
        if (result == 0) {
            char *command_str = get_command_string(argc, argv);
            log_upgrade(package_name, command_str, manager_to_use);
            if (command_str) free(command_str);
            printf("Upgraded %s with %s\n", package_name, manager_to_use);
        } else {
            printf("Failed to upgrade %s\n", package_name);
        }
        if (manager_allocated) free(manager_to_use);
    } else {
        // System upgrade path
        manager_to_use = config->system_upgrade_manager[0] ? config->system_upgrade_manager : NULL;
        if (!manager_to_use) {
            for (int i = 0; i < config->manager_count; i++) {
                if (strcmp(config->managers[i].type, "aur") == 0) {
                    manager_to_use = config->managers[i].name;
                    break;
                }
            }
            if (!manager_to_use) {
                for (int i = 0; i < config->manager_count; i++) {
                    if (strcmp(config->managers[i].type, "official") == 0) {
                        manager_to_use = config->managers[i].name;
                        break;
                    }
                }
            }
        }

        // Set mgr_config based on manager_to_use
        if (manager_to_use) {
            for (int i = 0; i < config->manager_count; i++) {
                if (strcmp(config->managers[i].name, manager_to_use) == 0) {
                    mgr_config = &config->managers[i];
                    break;
                }
            }
        }

        if (!mgr_config) {
            printf("Error: No suitable manager for system upgrade\n");
            free(log_dir_path);
            return;
        }

        // Execute system upgrade
        char cmd[MAX_CMD_LEN];
        snprintf(cmd, MAX_CMD_LEN, "%s%s %s", mgr_config->use_sudo ? "sudo " : "",
                 manager_to_use, mgr_config->upgrade_flags);
        system(cmd);
        char *command_str = get_command_string(argc, argv);
        log_system_upgrade(command_str ? command_str : "unknown command");
        if (command_str) free(command_str);
        printf("System upgrade completed with %s\n", manager_to_use);
    }

    free(log_dir_path);
}

void search_packages(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Error: No search query specified\n");
        return;
    }
    PackfetchConfig config;
    load_config(&config);
    if (config.system_upgrade_manager[0] == '\0') {
        printf("Error: No system upgrade manager configured\n");
        return;
    }
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, MAX_CMD_LEN, "%s -Ss %s", config.system_upgrade_manager, argv[2]);
    printf("Searching for '%s'...\n", argv[2]);
    system(cmd);
}

int check_if_installed(const char *package_name) {
    char *log_dir_path = get_log_dir();
    char db_path[MAX_PATH_LEN];
    snprintf(db_path, MAX_PATH_LEN, "%s/%s", log_dir_path, DB_FILE);
    
    FILE *db = fopen(db_path, "r");
    if (db == NULL) {
        free(log_dir_path);
        return 0;
    }
    
    char line[MAX_CMD_LEN];
    int found = 0;
    
    while (fgets(line, MAX_CMD_LEN, db) != NULL) {
        char *pkg_name = strtok(line, ",");
        if (pkg_name != NULL && strcmp(pkg_name, package_name) == 0) {
            found = 1;
            break;
        }
    }
    
    fclose(db);
    free(log_dir_path);
    return found;
}

void help(void) {
    printf("PacFetch - A wrapper for pacman/yay with installation tracking\n\n");
    printf("Usage:\n");
    printf("  pacfetch [OPTION] [ARGUMENTS]\n\n");
    printf("  --manager=NAME               Specify package manager (e.g., pacman, yay)\n");
    printf("  -S, --sync PACKAGE           Install a package\n");
    printf("  -R, --remove PACKAGE         Remove a package\n");
    printf("  -Q, --query [PACKAGE]        Query all tracked packages or a specific package's history\n");
    printf("  -U, --upgrade [PACKAGE]      Upgrade all packages or a specific package\n");
    printf("  -D, --duration               Display how long each package has been installed\n");
    printf("  -V, --vuln-scan              Scan for package vulnerabilities using arch-audit\n");
    printf("  -E, --export FILENAME        Export the list of tracked packages to a file\n");
    printf("  -B, --backup FILENAME        Backup the package list to a file\n");
    printf("  -I, --import FILENAME        Import a package list from a file and install missing packages\n");
    printf("  -C, --clean-orphans          Identify and optionally remove orphaned packages\n");
    printf("  -Ss, --search TERM           Search for packages using the configured package manager\n");
    printf("  --check                      Check for consistency between tracked and installed packages\n");
    printf("  -h, --help                   Display this help message\n\n");
    printf("Configuration:\n");
    printf("  Edit ~/.pacfetch/config.ini to customize package manager and flags.\n\n");
    printf("Security:\n");
    printf("  PacFetch validates package names for security.\n");
    printf("  All operations are logged with timestamp and directory information.\n");
    printf("  Log files are stored in ~/.pacfetch/\n");
}


char* get_current_dir(void) {
    char *buffer = malloc(MAX_PATH_LEN);
    if (buffer == NULL) {
        return NULL;
    }
    
    if (getcwd(buffer, MAX_PATH_LEN) == NULL) {
        free(buffer);
        return NULL;
    }
    
    return buffer;
}

char* get_log_dir(void) {
    char *buffer = malloc(MAX_PATH_LEN);
    if (buffer == NULL) {
        return NULL;
    }
    
    struct passwd *pw = getpwuid(getuid());
    snprintf(buffer, MAX_PATH_LEN, "%s/%s", pw->pw_dir, LOG_DIR);
    
    return buffer;
}

void log_upgrade(const char *package_name, const char *command_used, const char *manager) {
    char *log_dir_path = get_log_dir();
    if (log_dir_path == NULL) {
        printf("Error: Failed to get log directory\n");
        return;
    }

    char log_path[MAX_PATH_LEN];
    char db_path[MAX_PATH_LEN];
    snprintf(log_path, MAX_PATH_LEN, "%s/%s", log_dir_path, LOG_FILE);
    snprintf(db_path, MAX_PATH_LEN, "%s/%s", log_dir_path, DB_FILE);

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

    PackageDetails details;
    if (get_package_details(package_name, &details) != 0) {
        printf("Warning: Failed to get package details for %s\n", package_name);
        free(log_dir_path);
        return;
    }

    char *user = getlogin();
    if (user == NULL) {
        user = "unknown";
    }

    FILE *log = fopen(log_path, "a");
    if (log != NULL) {
        fprintf(log, "%s,upgraded,%s,%s,%s,%lld,%d,%s,%s,%s\n",
            time_str, package_name, details.version, details.source, details.size,
            details.dependency_count, command_used, user, manager);
        fclose(log);
    } else {
        printf("Warning: Failed to write to log file %s\n", log_path);
    }

    if (check_if_installed(package_name)) {
        char temp_db_path[MAX_PATH_LEN];
        snprintf(temp_db_path, MAX_PATH_LEN, "%s/%s.tmp", log_dir_path, DB_FILE);

        FILE *db_read = fopen(db_path, "r");
        FILE *temp_db = fopen(temp_db_path, "w");

        if (db_read != NULL && temp_db != NULL) {
            char line[MAX_CMD_LEN];
            char line_copy[MAX_CMD_LEN];

            while (fgets(line, MAX_CMD_LEN, db_read) != NULL) {
                strcpy(line_copy, line);
                char *pkg_name = strtok(line_copy, ",");
                if (pkg_name != NULL && strcmp(pkg_name, package_name) == 0) {
                    char *install_date = strtok(NULL, ",");
                    char *install_dir = strtok(NULL, ",");
                    char *existing_manager = strtok(NULL, ",");
                    fprintf(temp_db, "%s,%s,%s,%s,%s,%s\n",
                            package_name, install_date, install_dir, existing_manager,
                            details.version, details.source);
                } else {
                    fputs(line, temp_db);
                }
            }
            fclose(db_read);
            fclose(temp_db);
            remove(db_path);
            rename(temp_db_path, db_path);
        }
    }

    free(log_dir_path);
}

void log_system_upgrade(const char *command_used) {
    char *log_dir_path = get_log_dir();
    if (log_dir_path == NULL) {
        printf("Error: Failed to get log directory\n");
        return;
    }
    
    char log_path[MAX_PATH_LEN];
    snprintf(log_path, MAX_PATH_LEN, "%s/%s", log_dir_path, LOG_FILE);
    
    // Get current time
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);
    
    // Log to install_log.txt
    FILE *log = fopen(log_path, "a");
    if (log != NULL) {
        fprintf(log, "[%s] SYSTEM UPGRADE: Full system upgrade performed\n", time_str);
        fprintf(log, "  Command: %s\n", command_used);
        fclose(log);
    } else {
        printf("Warning: Failed to write to log file %s\n", log_path);
    }
    
    free(log_dir_path);
}

void create_dir_if_not_exists(const char *path) {
    if (path == NULL) {
        printf("Error: Invalid path\n");
        return;
    }
    
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        if (mkdir(path, 0700) != 0) {
            printf("Error: Failed to create directory %s\n", path);
        }
    }
}
