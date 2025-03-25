# PacFetch

PacFetch is a command-line tool designed to enhance package management on Arch Linux systems. It serves as a wrapper around popular package managers like `pacman` and `yay`, offering additional functionality such as installation logging, package usage tracking, vulnerability scanning, and consistency checks between tracked and installed packages.

## Installation

To install PacFetch, clone the repository and build it using the provided Makefile:

```bash
git clone https://github.com/MaximVlas/PacFetch.git
cd PacFetch
make
sudo make install
```

**Prerequisites**:
- `pacman`: Required as the base package manager for Arch Linux.
- `yay`: Optional, for Arch User Repository (AUR) support.
- `arch-audit`: Optional, required for vulnerability scanning (`pacman -S arch-audit`).

## Configuration

PacFetch uses a configuration file located at `~/.pacfetch/config.ini` to customize its behavior. If the file does not exist, PacFetch creates it with default settings on first run.

### Example `config.ini`
```ini
default_package_manager = pacman
use_sudo = 1
install_flags = -S --needed
remove_flags = -R
upgrade_flags = -Syu
```

### Configuration Options
- `default_package_manager`: The primary package manager (`pacman` or `yay`). Default: `pacman`.
- `use_sudo`: Whether to prepend `sudo` to commands (1 for yes, 0 for no). Default: `1`.
- `install_flags`: Flags for installation commands. Default: `-S --needed`.
- `remove_flags`: Flags for removal commands. Default: `-R`.
- `upgrade_flags`: Flags for upgrade commands. Default: `-Syu`.

## Usage

PacFetch supports a variety of command-line options for managing packages and accessing its features.

### Command-Line Options
- `-S, --sync PACKAGE`: Install a package.
- `-R, --remove PACKAGE`: Remove a package.
- `-Q, --query [PACKAGE]`: Query all tracked packages or a specific package's history.
- `-U, --upgrade [PACKAGE]`: Upgrade all packages or a specific package.
- `-D, --duration`: Display how long each package has been installed.
- `-V, --vuln-scan`: Scan for package vulnerabilities using `arch-audit`.
- `-E, --export FILENAME`: Export the list of tracked packages to a file.
- `-B, --backup FILENAME`: Backup the package list to a file.
- `-I, --import FILENAME`: Import a package list from a file and install missing packages.
- `-C, --clean-orphans`: Identify and optionally remove orphaned packages.
- `-Ss, --search TERM`: Search for packages using the configured package manager.
- `--check`: Check for consistency between tracked and installed packages.
- `-h, --help`: Display the help message.

### Examples
- **Install a package**:
  ```bash
  pacfetch -S firefox
  ```
- **Remove a package**:
  ```bash
  pacfetch -R firefox
  ```
- **Query all tracked packages**:
  ```bash
  pacfetch -Q
  ```
- **Query a specific package**:
  ```bash
  pacfetch -Q firefox
  ```
- **Upgrade all packages**:
  ```bash
  pacfetch -U
  ```
- **Upgrade a specific package**:
  ```bash
  pacfetch -U firefox
  ```
- **Show package usage durations**:
  ```bash
  pacfetch -D
  ```
- **Scan for vulnerabilities**:
  ```bash
  pacfetch -V
  ```
- **Export tracked packages**:
  ```bash
  pacfetch -E package_list.txt
  ```
- **Backup package list**:
  ```bash
  pacfetch -B backup.txt
  ```
- **Import package list**:
  ```bash
  pacfetch -I backup.txt
  ```
- **Clean orphaned packages**:
  ```bash
  pacfetch -C
  ```
- **Search for a package**:
  ```bash
  pacfetch -Ss firefox
  ```
- **Check consistency**:
  ```bash
  pacfetch --check
  ```

## Features

### Duration Calculation
The `-D` or `--duration` option calculates and displays how long each package has been installed, based on log entries. Output is in days, hours, minutes, and seconds.

### Vulnerability Scan
The `-V` or `--vuln-scan` option scans installed packages for known vulnerabilities using `arch-audit`. Requires `arch-audit` to be installed:
```bash
pacman -S arch-audit
```

### Export Package List
The `-E` or `--export FILENAME` option saves the list of tracked packages to a specified file, including package names, install dates, directories, versions, and sources.

### Backup and Import
- **Backup**: Use `-B FILENAME` to save the tracked package list to a file.
- **Import**: Use `-I FILENAME` to import a package list and install any missing packages using the configured package manager.

### Clean Orphans
The `-C` or `--clean-orphans` option identifies orphaned packages (dependencies no longer required) and prompts the user to remove them.

### Consistency Check
The `--check` option compares the packages tracked in `packages.db` with those actually installed via `pacman`, reporting any discrepancies (e.g., tracked but not installed, or installed but not tracked).

## Logging and Database

PacFetch stores operational data in two files within the `~/.pacfetch/` directory:

- **`install_log.txt`**:
  - A CSV-formatted log of all package operations (installations, removals, upgrades).
  - Fields: timestamp, operation type, package name, version, source, size, dependency count, command used, user.
  - Example entry:
    ```
    2023-10-15 14:30:45,installed,firefox,106.0,official,12345678,5,pacfetch -S firefox,user
    ```

- **`packages.db`**:
  - A database of currently tracked packages.
  - Fields: package name, install date, install directory, version, source.
  - Example entry:
    ```
    firefox,2023-10-15 14:30:45,/home/user,official
    ```

These files enable PacFetch to track package history and provide querying capabilities. Users can inspect them manually, but the `-Q` command is recommended for querying.

## Security Considerations

PacFetch includes several security features:
- **Package Name Validation**: Only allows alphanumeric characters, hyphens, underscores, and periods in package names to prevent injection attacks.
- **Input Sanitization**: Strips invalid characters from inputs before executing commands.
- **Detailed Logging**: Records all operations with timestamps, commands, and usernames for auditing purposes.

These measures ensure safe and reliable package management.

## Contributing and License

PacFetch is open-source software licensed under the Apache License. Contributions are welcome! To contribute:
- Fork the repository at [GitHub](https://github.com/MaximVlas/PacFetch).
- Submit pull requests with improvements or bug fixes.
- Report issues via the GitHub issue tracker.

For more details, see the repository’s contributing guidelines.
