# System Cleaner

![Python Version](https://img.shields.io/badge/python-3.12-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Code Style](https://img.shields.io/badge/code%20style-ruff-000000.svg)
![Type Check](https://img.shields.io/badge/type%20check-pyright-blue.svg)

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/FUYOH666/Cleaner-OS)

> **Universal CLI tool for system cleanup and audit**

System Cleaner helps you find and remove junk, analyze dependencies, check security, and optimize disk space usage on macOS and Linux.

## 🎯 Problems Solved

- **Unused ML models** taking up gigabytes of space (Hugging Face, PyTorch, TensorFlow)
- **Dependency conflicts** in Python projects going unnoticed
- **Removed application leftovers** cluttering the system
- **Security issues** (incorrect file permissions, secrets in code)
- **Build artifacts** accumulating in development projects
- **Unused dependencies** increasing project size

## ✨ Features

- 🔍 **System scanning** - find caches, logs, application leftovers
- 🧠 **ML cache analysis** - detect unused Hugging Face, PyTorch, TensorFlow models
- 📦 **Dependency analysis** - check for conflicts, unused and outdated Python dependencies
- 🔒 **Security checks** - analyze file permissions, find secrets, check SSH keys
- 🗑️ **Cleanup recommendations** - what can be safely deleted and how much space will be freed
- 🌐 **Cross-platform** - works on macOS and Linux
- 📊 **Detailed reports** - Markdown and JSON formats

## 🌐 Cross-platform Support and Automatic Adaptation

System Cleaner **automatically adapts** to your system without additional configuration:

### Automatic Platform Detection
- Detects macOS or Linux on startup
- Adapts paths to your operating system:
  - **macOS:** `~/Library/Caches/`, `~/Library/Application Support/`
  - **Linux:** `~/.cache/`, `~/.local/share/`

### Automatic Project Discovery
The tool automatically finds development projects in standard locations:
- `~/development/`
- `~/dev/`
- `~/projects/`
- `~/code/`
- `~/workspace/`
- `~/Documents/Projects/`
- `~/Documents/Code/`

Finds projects by indicators:
- Git repositories (presence of `.git`)
- Python projects (`pyproject.toml`, `requirements.txt`)
- Node.js projects (`package.json`)
- Rust projects (`Cargo.toml`)
- Go projects (`go.mod`)

### Linux Distribution Detection
Automatically detects Linux distribution for more accurate path adaptation:
- Ubuntu/Debian
- Fedora/RHEL/CentOS
- Arch Linux
- Others (via `/etc/os-release`)

### Hardware Detection
The `health` command shows information about your system:
- **GPU:** presence and type (NVIDIA, AMD, Intel, Metal)
- **Disk:** size, free space, usage percentage

### Works Without Configuration
The tool works **out of the box** without `config.yaml`:
- Uses default values
- Automatically finds everything needed
- Adapts to your system

Configuration is only needed for:
- Excluding specific paths from scanning
- Setting minimum size for reports
- Enabling/disabling individual checks

## 📋 Requirements

- **Python 3.12** - the only supported version
- **uv** - package manager (installed automatically)
- **macOS** or **Linux** - the tool supports both platforms

## 🚀 Installation

### Using uv (recommended)

```bash
# Clone the repository
git clone git@github.com:FUYOH666/Cleaner-OS.git
cd Cleaner-OS

# Install dependencies
uv sync

# Verify installation
uv run python -m syscleaner health
```

### After Installation

After installing the package, you can use the command directly:

```bash
syscleaner health
# or
system-cleaner health
```

### Additional Scripts

The `scripts/` directory contains helper scripts for working with System Cleaner:

- **`system_health_check.sh.example`** - Comprehensive system health check (GPU, CPU, memory, disk, services, Docker GPU)
- **`backup_configs.sh.example`** - Backup critical system configurations

**Usage:**
```bash
# Copy example files to working scripts
cp scripts/system_health_check.sh.example scripts/system_health_check.sh
cp scripts/backup_configs.sh.example scripts/backup_configs.sh

# Make them executable
chmod +x scripts/*.sh

# Run
./scripts/system_health_check.sh
./scripts/backup_configs.sh
```

Scripts use relative paths and work on macOS and Linux. See [scripts/README.md](scripts/README.md) for details.

## 📖 Usage

### Full System Scan

```bash
syscleaner scan --all
```

This will perform:
- Cache and temporary file scanning
- Search for removed application leftovers
- Hidden file analysis
- Project artifact checks
- ML cache analysis (Hugging Face, PyTorch, TensorFlow)
- Python dependency checks
- Security analysis

### Scanning Individual Categories

```bash
# Caches only
syscleaner scan --caches

# Security only
syscleaner scan --security

# Projects only
syscleaner scan --projects

# Dependency analysis
syscleaner scan --dependencies

# ML cache analysis (Hugging Face, PyTorch, TensorFlow)
syscleaner scan --ml-cache
```

### Saving Results

```bash
# Save results to JSON
syscleaner scan --all --save-results scan_results.json
```

### Report Generation

```bash
# Markdown report
syscleaner report --format markdown --output report.md --from-scan scan_results.json

# JSON report
syscleaner report --format json --output report.json --from-scan scan_results.json
```

### System Health Check

```bash
syscleaner health
```

## ⚙️ Configuration

The tool uses `config.yaml` for scan configuration. If the file is missing, the tool works with default settings.

**Creating configuration:**
```bash
# Copy the example configuration
cp config.yaml.example config.yaml

# Edit to your needs
nano config.yaml
```

Example configuration (`config.yaml.example`):

```yaml
scan:
  exclude_paths:
    - ~/Library/Mail/      # macOS only
    - ~/Library/Messages/  # macOS only
    - ~/Library/Photos/    # macOS only
    - ~/.local/share/mail/  # Linux
  min_size_mb: 10
  check_security: true
  check_project_artifacts: true
  check_dependencies: true  # Check for conflicts and unused dependencies
  check_ml_cache: true  # Check ML model caches

security:
  sensitive_patterns:
    - "*.env"
    - "*credentials*"
    - "*secret*"
    - "*password*"
    - "*token*"
    - "*api_key*"
  check_ssh_permissions: true
  check_file_permissions: true

cleanup:
  safe_to_delete_patterns:
    - "**/__pycache__"
    - "**/.DS_Store"
    - "**/node_modules"
    - "**/*.pyc"
    - "**/.pytest_cache"
```

## 🔍 What the Tool Scans

### 1. Caches and Temporary Files
- **macOS:** `~/Library/Caches/` - size analysis by application
- **Linux:** `~/.cache/` - size analysis by application
- Removed application leftovers
- Old logs
- Trash
- System caches

### 2. Removed Application Leftovers
- **macOS:** Compare `~/Library/Application Support/` with `/Applications`
- **Linux:** Compare `~/.local/share/` with installed packages (apt, yum, dnf, pacman)
- Flatpak and Snap application support (Linux)
- Orphaned package detection

### 3. Security Checks
- Analysis of critical file permissions (~/.ssh/, ~/.aws/)
- SSH key checks (exposed private keys)
- Search for files with secrets (.env, credentials, API keys)
- Insecure config checks (world-readable sensitive files)
- Cross-platform support

### 4. Hidden File Analysis
- Search for hidden files/folders in home directory
- Analysis of hidden directory sizes
- Search for large hidden files (>100MB by default)

### 5. Development Project Optimization
- Find `__pycache__`, `.pytest_cache`, `.DS_Store`
- Analyze `node_modules` (if Node.js projects exist)
- Find large build artifacts (dist/, build/, *.egg-info)
- Clean virtual environments (venv, .venv)

### 6. ML Cache Analysis ⭐
- **Hugging Face:** `~/.cache/huggingface/` (Linux) or `~/Library/Caches/huggingface/` (macOS)
  - Identify all downloaded models
  - Size of each model
  - Last usage date
  - Identify unused models (older than 30 days)
- **PyTorch:** `~/.cache/torch/`
  - Preloaded models
  - Dataset cache
- **TensorFlow:** `~/.cache/tensorflow/` or `~/.keras/`
  - Saved models
  - Dataset cache
- Duplicate model detection
- Recommendations for cleaning unused models

### 7. Dependency Analysis ⭐
- **Python dependencies:**
  - Check for dependency conflicts via `uv pip check`
  - Find unused dependencies (import analysis)
  - Check for outdated dependencies
  - Analyze `pyproject.toml` and `uv.lock` for duplicates and conflicts

## 📊 Report Formats

### Markdown Report
Contains structured information with tables:
- Scan summary
- ML model caches (count, size, unused)
- Dependency analysis (conflicts, unused, outdated)
- Caches
- Application leftovers
- Hidden files
- Project artifacts
- Security issues
- Cleanup recommendations

### JSON Report
Structured data for automated processing:
```json
{
  "timestamp": "2025-11-04T12:00:00",
  "platform": "macOS 25.0.0",
  "scan_results": { ... },
  "security_results": { ... },
  "cleanup_analysis": { ... },
  "ml_cache_results": { ... },
  "dependency_results": { ... }
}
```

## 🛡️ Security

- **Fail-fast approach** - application stops on configuration errors
- **No automatic deletions** - tool only analyzes and recommends
- **Path validation** - all paths are validated before processing
- **Logging** - all actions are logged for audit
- **Cross-platform security** - checks work on macOS and Linux

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a branch for your feature (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Requirements

- Python 3.12
- Use `uv` for dependency management
- Follow code style (ruff)
- Type checking (pyright)
- Tests for new functionality

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## 👤 Author

**Aleksandr Mordvinov**

- GitHub: [@FUYOH666](https://github.com/FUYOH666)
- Repository: [Cleaner-OS](https://github.com/FUYOH666/Cleaner-OS)

## 🙏 Acknowledgments

Thanks to everyone who helps improve this project!

---

**Note**: This tool is intended for analysis and recommendations only. All file deletion actions are performed manually by the user.
