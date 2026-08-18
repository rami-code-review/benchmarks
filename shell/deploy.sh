#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="${1:?usage: deploy.sh <build-dir>}"
ARTIFACT_URL="https://artifacts.example.com/app.tgz"
release_dir="/srv/app/releases/current"

cleanup_old_build() {
    rm -rf "${BUILD_DIR:?}/dist"
}

fetch_and_unpack() {
    curl -fsSL "$ARTIFACT_URL" | tar -xz -C "$release_dir"
}

cd "$release_dir" || exit 1
cleanup_old_build
fetch_and_unpack
echo "deployed to $release_dir"
