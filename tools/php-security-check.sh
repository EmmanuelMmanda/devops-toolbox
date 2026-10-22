#!/bin/sh
# Portable launcher. The scanner itself requires Python 3.8+.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' >/dev/null 2>&1; then
    exec python3 "$script_dir/php_security_scan.py" "$@"
fi

printf '%s\n' 'Python 3.8+ is required for the PHP security check and is not available.'
printf '%s\n' 'No scan or package change was made.'
if command -v apt-get >/dev/null 2>&1; then
    printf '%s\n' 'On Ubuntu, review and run these commands, then retry:'
    printf '%s\n' '  sudo apt-get update'
    printf '%s\n' '  sudo apt-get --simulate --no-remove install python3'
    printf '%s\n' '  sudo apt-get --no-remove install python3'
    if [ "${1:-}" = '--mitigate' ]; then
        printf '%s\n' '  sudo sh tools/php-security-check.sh --mitigate'
    else
        printf '%s\n' '  sh tools/php-security-check.sh'
    fi
else
    printf '%s\n' 'Install Python 3.8+ from your OS vendor, then retry this launcher.'
fi
exit 2
