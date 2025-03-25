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

// Function prototypes
typedef struct {
    char default_package_manager[32];
    int use_sudo;
    char install_flags[64];
    char remove_flags[64];
    char upgrade_flags[64];
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
void log_installation(const char *package_name, const char *install_dir, const char *command_used);
void install_package(int argc, char *argv[]);
void remove_package(int argc, char *argv[]);
void query_package(int argc, char *argv[]);
void log_upgrade(const char *package_name, const char *command_used);
void log_removal(const char *package_name, const char *command_used);
int check_if_installed(const char *package_name);
int validate_package_name(const char *package_name);
char* sanitize_input(const char *input);
void export_package_list(const char *filename);
void help(void);
char* get_current_dir(void);
char* get_log_dir(void);
void upgrade_packages(int argc, char *argv[]);
void create_dir_if_not_exists(const char *path);
void log_system_upgrade(const char *command_used);
void load_config(PackfetchConfig *config);
void init_default_config(PackfetchConfig *config);
int execute_package_manager(const char *package_manager, const char *action, const char *flags, const char *package);
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

    if (argc < 2) {
        help();
        return 1;
    }

    if (strcmp(argv[1], "-B") == 0 || strcmp(argv[1], "--backup") == 0) {
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
    } else if (strcmp(argv[1], "-S") == 0 || strcmp(argv[1], "--sync") == 0) {
        install_package(argc, argv);
    } else if (strcmp(argv[1], "-R") == 0 || strcmp(argv[1], "--remove") == 0) {
        remove_package(argc, argv);
    } else if (strcmp(argv[1], "-Q") == 0 || strcmp(argv[1], "--query") == 0) {
        query_package(argc, argv);
    } else if (strcmp(argv[1], "-U") == 0 || strcmp(argv[1], "--upgrade") == 0) {
        upgrade_packages(argc, argv);
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

void init_default_config(PackfetchConfig *config) {
    strcpy(config->default_package_manager, "pacman");
    config->use_sudo = 1;
    strcpy(config->install_flags, "-S --needed");
    strcpy(config->remove_flags, "-R");
    strcpy(config->upgrade_flags, "-Syu");
}

void install_package(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Error: No package specified for installation\n");
        return;
    }
    
    if (!validate_package_name(argv[2])) {
        printf("Error: Invalid package name '%s'\n", argv[2]);
        return;
    }
    
    // Check if package is already installed
    if (check_if_installed(argv[2])) {
        printf("Package %s is already tracked by PacFetch.\n", argv[2]);
        printf("Use 'pacfetch -U %s' to upgrade instead.\n", argv[2]);
        
        char query_cmd[MAX_CMD_LEN];
        snprintf(query_cmd, MAX_CMD_LEN, "pacman -Q %s >/dev/null 2>&1", argv[2]);
        if (system(query_cmd) == 0) {
            printf("Package is already installed according to pacman.\n");
            return;
        } else {
            printf("Warning: Package is tracked but not found by pacman.\n");
            printf("Proceeding with installation anyway...\n");
        }
    }
    
    // Load configuration
    PackfetchConfig config;
    load_config(&config);
    
    // Try installing with the default package manager first
    printf("Attempting to install %s with %s...\n", argv[2], config.default_package_manager);
    int result = execute_package_manager(config.default_package_manager, "install", 
                                       config.install_flags, argv[2]);
    
    // If default fails, try with alternative (yay for AUR)
    if (result != 0) {
        printf("Package not found in %s repositories, trying yay...\n", config.default_package_manager);
        result = execute_package_manager("yay", "install", config.install_flags, argv[2]);
        
        if (result != 0) {
            printf("Installation failed with both %s and yay.\n", config.default_package_manager);
            return;
        }
    }

    long long size = estimate_package_size(argv[2]);
    if (size >= 0) {
        printf("Estimated size for %s: %lld bytes\n", argv[2], size);
    }

    // Log the successful installation
    char *current_dir = get_current_dir();
    if (current_dir == NULL) {
        printf("Error: Failed to get current directory\n");
        return;
    }
    
    char *command_str = get_command_string(argc, argv);
    if (command_str != NULL) {
        log_installation(argv[2], current_dir, command_str);
        free(command_str);
    } else {
        log_installation(argv[2], current_dir, "unknown command");
    }
    free(current_dir);
    
    printf("Installation of %s completed and logged.\n", argv[2]);
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
    while (fgets(line, MAX_CMD_LEN, file) != NULL) {
        if (line[0] == '#') continue;  // Skip comments
        char *pkg_name = strtok(line, ",");
        if (pkg_name && !check_if_installed(pkg_name)) {
            execute_package_manager(config.default_package_manager, "install", config.install_flags, pkg_name);
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

int execute_package_manager(const char *package_manager, const char *action, const char *flags, const char *package) {
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
    
    // Load configuration
    PackfetchConfig config;
    load_config(&config);
    
    // Use action for logging purposes
    printf("Performing %s action on package %s using %s...\n", 
           action, sanitized_package, package_manager);
    
    // Build command with or without sudo
    if (config.use_sudo) {
        snprintf(cmd, MAX_CMD_LEN, "sudo %s %s %s", 
                 package_manager, flags, sanitized_package);
    } else {
        snprintf(cmd, MAX_CMD_LEN, "%s %s %s", 
                 package_manager, flags, sanitized_package);
    }
    
    printf("Executing: %s\n", cmd);
    int result = system(cmd);
    
    free(sanitized_package);
    return result;
}

void load_config(PackfetchConfig *config) {
    // Set defaults first
    init_default_config(config);
    
    char *log_dir_path = get_log_dir();
    if (log_dir_path == NULL) {
        printf("Warning: Failed to get log directory, using default configuration\n");
        return;
    }
    
    char config_path[MAX_PATH_LEN];
    snprintf(config_path, MAX_PATH_LEN, "%s/%s", log_dir_path, CONFIG_FILE);
    
    FILE *cfg = fopen(config_path, "r");
    if (cfg == NULL) {
        // Config file doesn't exist, create one with defaults
        FILE *new_cfg = fopen(config_path, "w");
        if (new_cfg != NULL) {
            fprintf(new_cfg, "# PacFetch Configuration File\n");
            fprintf(new_cfg, "default_package_manager = pacman\n");
            fprintf(new_cfg, "use_sudo = 1\n");
            fprintf(new_cfg, "install_flags = -S --needed\n");
            fprintf(new_cfg, "remove_flags = -R\n");
            fprintf(new_cfg, "upgrade_flags = -Syu\n");
            fclose(new_cfg);
        }
        free(log_dir_path);
        return;
    }
    
    char line[MAX_LINE_LEN];
    while (fgets(line, MAX_LINE_LEN, cfg) != NULL) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        char key[MAX_LINE_LEN];
        char value[MAX_LINE_LEN];
        
        // Parse key-value pairs
        if (sscanf(line, "%[^=]=%[^\n]", key, value) == 2) {
            // Trim whitespace
            char *k = key;
            while (isspace(*k)) k++;
            char *v = value;
            while (isspace(*v)) v++;
            
            char *end = k + strlen(k) - 1;
            while (end > k && isspace(*end)) *end-- = '\0';
            end = v + strlen(v) - 1;
            while (end > v && isspace(*end)) *end-- = '\0';
            
            if (strcmp(k, "default_package_manager") == 0) {
                strncpy(config->default_package_manager, v, sizeof(config->default_package_manager) - 1);
            } else if (strcmp(k, "use_sudo") == 0) {
                config->use_sudo = atoi(v);
            } else if (strcmp(k, "install_flags") == 0) {
                strncpy(config->install_flags, v, sizeof(config->install_flags) - 1);
            } else if (strcmp(k, "remove_flags") == 0) {
                strncpy(config->remove_flags, v, sizeof(config->remove_flags) - 1);
            } else if (strcmp(k, "upgrade_flags") == 0) {
                strncpy(config->upgrade_flags, v, sizeof(config->upgrade_flags) - 1);
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

void remove_package(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Error: No package specified for removal\n");
        return;
    }
    
    if (!validate_package_name(argv[2])) {
        printf("Error: Invalid package name '%s'\n", argv[2]);
        return;
    }
    
    // Check if package is tracked by pacfetch
    if (!check_if_installed(argv[2])) {
        printf("Warning: Package %s is not tracked by PacFetch\n", argv[2]);
        printf("Proceeding with removal anyway...\n");
    }
    
    // Load configuration
    PackfetchConfig config;
    load_config(&config);
    
    // Remove the package using configured package manager
    printf("Removing package %s...\n", argv[2]);
    int result = execute_package_manager(config.default_package_manager, "remove", 
                                       config.remove_flags, argv[2]);
    
if (result == 0) {
        // Log the successful removal
        char *command_str = get_command_string(argc, argv);
        if (command_str != NULL) {
            log_removal(argv[2], command_str);
            free(command_str);
        } else {
            log_removal(argv[2], "unknown command");
        }
        printf("Removal of %s completed and logged.\n", argv[2]);
    } else {
        printf("Failed to remove package %s\n", argv[2]);
        printf("Try using 'sudo %s %s %s' manually\n", 
               config.default_package_manager, 
               config.remove_flags, argv[2]);
    }
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

void log_installation(const char *package_name, const char *install_dir, const char *command_used) {
    char *log_dir_path = get_log_dir();
    if (log_dir_path == NULL) {
        printf("Error: Failed to get log directory\n");
        return;
    }

    char log_path[MAX_PATH_LEN];
    char db_path[MAX_PATH_LEN];
    snprintf(log_path, MAX_PATH_LEN, "%s/%s", log_dir_path, LOG_FILE);
    snprintf(db_path, MAX_PATH_LEN, "%s/%s", log_dir_path, DB_FILE);

    // Get current time
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

    // Get package details
    PackageDetails details;
    if (get_package_details(package_name, &details) != 0) {
        printf("Warning: Failed to get package details for %s\n", package_name);
        strcpy(details.version, "unknown");
        details.size = 0;
        details.dependency_count = 0;
        strcpy(details.source, "unknown");
    }

    // Get username
    char *user = getlogin();
    if (user == NULL) {
        user = "unknown";
    }

    // Log to install_log.txt in CSV format
    FILE *log = fopen(log_path, "a");
    if (log != NULL) {
        fprintf(log, "%s,installed,%s,%s,%s,%lld,%d,%s,%s\n",
                time_str, package_name, details.version, details.source, details.size,
                details.dependency_count, command_used, user);
        fclose(log);
    } else {
        printf("Warning: Failed to write to log file %s\n", log_path);
    }

    // Update packages.db
    FILE *db = fopen(db_path, "a+");
    if (db != NULL) {
        fseek(db, 0, SEEK_SET);
        char line[MAX_CMD_LEN];
        int exists = 0;

        while (fgets(line, MAX_CMD_LEN, db) != NULL) {
            char *pkg_name = strtok(line, ",");
            if (pkg_name != NULL && strcmp(pkg_name, package_name) == 0) {
                exists = 1;
                break;
            }
        }

        if (!exists) {
            fprintf(db, "%s,%s,%s,%s,%s\n", package_name, time_str, install_dir, details.version, details.source);
        } else {
            fclose(db);
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
                        fprintf(temp_db, "%s,%s,%s,%s,%s\n", package_name, time_str, install_dir, details.version, details.source);
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
    } else {
        printf("Warning: Failed to update package database %s\n", db_path);
    }

    free(log_dir_path);
}

void log_removal(const char *package_name, const char *command_used) {
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

    // Get current time
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

    // Get username
    char *user = getlogin();
    if (user == NULL) {
        user = "unknown";
    }

    // Log to install_log.txt in CSV format
    FILE *log = fopen(log_path, "a");
    if (log != NULL) {
        fprintf(log, "%s,removed,%s,%s,%s\n", time_str, package_name, command_used, user);
        fclose(log);
    } else {
        printf("Warning: Failed to write to log file %s\n", log_path);
    }

    // Remove entry from packages.db (unchanged)
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

void upgrade_packages(int argc, char *argv[]) {
    char *log_dir_path = get_log_dir();
    if (log_dir_path == NULL) {
        printf("Error: Failed to get log directory\n");
        return;
    }
    
    PackfetchConfig config;
    load_config(&config);
    
    if (argc >= 3) {
        if (!validate_package_name(argv[2])) {
            printf("Error: Invalid package name '%s'\n", argv[2]);
            free(log_dir_path);
            return;
        }
        
        printf("Upgrading package: %s\n", argv[2]);
        if (!check_if_installed(argv[2])) {
            printf("Warning: Package %s is not tracked by PacFetch\n", argv[2]);
            printf("Proceeding with upgrade anyway...\n");
        }
        
        int result = execute_package_manager(config.default_package_manager, "upgrade", 
                                           config.upgrade_flags, argv[2]);
        if (result != 0) {
            printf("Failed to upgrade with %s, trying yay...\n", config.default_package_manager);
            result = execute_package_manager("yay", "upgrade", config.upgrade_flags, argv[2]);
            if (result != 0) {
                printf("Failed to upgrade package %s.\n", argv[2]);
                free(log_dir_path);
                return;
            }
        }
        
        char *command_str = get_command_string(argc, argv);
        if (command_str != NULL) {
            log_upgrade(argv[2], command_str);
            free(command_str);
        } else {
            log_upgrade(argv[2], "unknown command");
        }
        printf("Upgrade of %s completed and successfully logged.\n", argv[2]);
    } else {
        printf("Upgrading all packages...\n");
        char cmd[MAX_CMD_LEN];
        if (config.use_sudo) {
            snprintf(cmd, MAX_CMD_LEN, "sudo %s %s", 
                    config.default_package_manager, config.upgrade_flags);
        } else {
            snprintf(cmd, MAX_CMD_LEN, "%s %s", 
                    config.default_package_manager, config.upgrade_flags);
        }
        system(cmd);
        
        if (strcmp(config.default_package_manager, "yay") != 0) {
            printf("Checking AUR packages for updates...\n");
            snprintf(cmd, MAX_CMD_LEN, "yay -Sua");
            system(cmd);
        }
        
        char *command_str = get_command_string(argc, argv);
        if (command_str != NULL) {
            log_system_upgrade(command_str);
            free(command_str);
        } else {
            log_system_upgrade("unknown command");
        }
        printf("System upgrade completed and logged.\n");
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
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, MAX_CMD_LEN, "%s -Ss %s", config.default_package_manager, argv[2]);
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
    printf("Options:\n");
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

void log_upgrade(const char *package_name, const char *command_used) {
    char *log_dir_path = get_log_dir();
    if (log_dir_path == NULL) {
        printf("Error: Failed to get log directory\n");
        return;
    }

    char log_path[MAX_PATH_LEN];
    char db_path[MAX_PATH_LEN];
    snprintf(log_path, MAX_PATH_LEN, "%s/%s", log_dir_path, LOG_FILE);
    snprintf(db_path, MAX_PATH_LEN, "%s/%s", log_dir_path, DB_FILE);

    // Get current time
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

    // Get package details
    PackageDetails details;
    if (get_package_details(package_name, &details) != 0) {
        printf("Warning: Failed to get package details for %s\n", package_name);
        return;
    }

    // Get username
    char *user = getlogin();
    if (user == NULL) {
        user = "unknown";
    }

    // Log to install_log.txt in CSV format
    FILE *log = fopen(log_path, "a");
    if (log != NULL) {
        fprintf(log, "%s,upgraded,%s,%s,%s,%lld,%d,%s,%s\n",
                time_str, package_name, details.version, details.source, details.size,
                details.dependency_count, command_used, user);
        fclose(log);
    } else {
        printf("Warning: Failed to write to log file %s\n", log_path);
    }

    // Update packages.db (unchanged)
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
                    fprintf(temp_db, "%s,%s,%s,%s,%s\n",
                            package_name, install_date, install_dir, details.version, details.source);
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
