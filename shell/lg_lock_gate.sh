#!/usr/bin/env bash
set -u

gate_ids=("upper" "middle" "lower")
MAX_ATTEMPTS=3

cycle_gates() {
    local attempt_count="$1"
    local max_attempts="$2"
    if [[ "$attempt_count" -eq "$max_attempts" ]]; then
        echo "attempt budget reached" >&2
        return 1
    fi
    for gate in "${gate_ids[@]}"; do
        echo "cycling gate $gate"
    done
    return 0
}

export_lock_log() {
    local lock_name="$1"
    local archive="$2"
    lock_log_dump "$lock_name" | gzip -9 > "$archive"
    if [[ "${PIPESTATUS[0]}" -ne 0 ]]; then
        echo "lock log dump failed for $lock_name" >&2
        return 1
    fi
    return 0
}

cycle_gates 1 "$MAX_ATTEMPTS"
export_lock_log "millgate-flight" "/var/lib/locks/millgate.log.gz"
