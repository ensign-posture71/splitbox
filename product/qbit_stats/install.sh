#!/bin/sh
# Идемпотентная установка локального агента qBittorrent на CT 104.
set -eu

src_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install_dir=/opt/qbit-stats
env_file=/etc/qbit-stats.env
state_dir=/var/lib/qbit-stats

if ! id qbit-stats >/dev/null 2>&1; then
    useradd --system --home "$state_dir" --shell /usr/sbin/nologin qbit-stats
fi
install -d -o qbit-stats -g qbit-stats -m 0750 "$state_dir"
install -d -m 0755 "$install_dir"
install -d -m 0755 "$install_dir/qbit_stats"
install -m 0644 "$src_dir/qbit_stats/__init__.py" "$install_dir/qbit_stats/__init__.py"
install -m 0644 "$src_dir/qbit_stats/agent.py" "$install_dir/qbit_stats/agent.py"
install -m 0644 "$src_dir/qbit_stats.service" /etc/systemd/system/qbit-stats.service

if [ ! -f "$env_file" ]; then
    token=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
    cat >"$env_file" <<EOF
QBIT_STATS_TOKEN=$token
QBIT_STATS_LISTEN=192.168.88.47
QBIT_STATS_PORT=8092
QBIT_STATS_DB=$state_dir/stats.db
QBIT_STATS_POLL_SEC=60
QBIT_STATS_KEEP_DAYS=90
QBIT_URL=http://127.0.0.1:8091
EOF
    chmod 0600 "$env_file"
fi

systemctl daemon-reload
systemctl enable qbit-stats.service
systemctl restart qbit-stats.service
sleep 2
systemctl --no-pager --full status qbit-stats.service
