#!/bin/sh
# Собирает архив splitbox-<дата>.tar.gz для раздачи друзьям.
#
# Обычный путь установки — `curl | sh` из репозитория (см. README).
# Архив нужен, когда GitHub недоступен: друг получает файл любым способом,
# распаковывает и запускает install.sh из него.
set -eu

SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STAMP=$(date +%Y%m%d)
OUT="${1:-$SRC/../splitbox-$STAMP.tar.gz}"

cd "$SRC"
tar czf "$OUT" \
    --exclude='.env' \
    --exclude='state' \
    --exclude='core/.venv' \
    --exclude='__pycache__' \
    --exclude='*.egg-info' \
    --exclude='core/tests' \
    --exclude='.DS_Store' \
    -s '/^\./splitbox/' . 2>/dev/null || \
tar czf "$OUT" \
    --exclude='.env' \
    --exclude='state' \
    --exclude='core/.venv' \
    --exclude='__pycache__' \
    --exclude='*.egg-info' \
    --exclude='core/tests' \
    --exclude='.DS_Store' \
    --transform 's,^\.,splitbox,' .

echo "готово: $OUT"
echo
echo "инструкция для друга:"
echo "  tar xzf $(basename "$OUT")"
echo "  sudo sh splitbox/install.sh"
