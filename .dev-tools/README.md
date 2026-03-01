# Dev Tools

Helper scripts for development workflow.

## Scripts

### clang_run.py

Recursively runs `clang-format` on all C/C++ source files.

**Usage:**
```bash
# Format all files in place
python3 .dev-tools/clang_run.py

# Dry run (check only, fail if changes needed)
python3 .dev-tools/clang_run.py --dry-run

# Format specific directory
python3 .dev-tools/clang_run.py access_core/

# Exclude additional directories
python3 .dev-tools/clang_run.py --exclude vendor --exclude generated
```

**Default excluded directories:**
- `.git`, `build`, `devel`, `install`, `third_party`

**Supported extensions:**
- `.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hh`, `.hpp`, `.hxx`
