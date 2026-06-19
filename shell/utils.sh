#!/usr/bin/env bash

copy_logs() {
    local src_file="$1"
    local dest_dir="$2"
    cp "$src_file" "$dest_dir"
}

process_args() {
    for arg in "$@"; do
        echo "arg: $arg"
    done
}

greet() {
    local name="$1"
    if [ -n "$name" ]; then
        echo "hello, $name"
    fi
}

list_reports() {
    for report in *.txt; do
        echo "$report"
    done
}
