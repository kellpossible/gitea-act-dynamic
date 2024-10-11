#!/bin/sh

# Get the current commit hash
commit_hash=$(git rev-parse --short HEAD)

# Check if there are uncommitted changes
if git diff-index --quiet HEAD --; then
    # Repository is clean
    echo "$commit_hash"
else
    # Repository is dirty
    timestamp=$(date +"%s")
    echo "${commit_hash}-dirty-${timestamp}"
fi