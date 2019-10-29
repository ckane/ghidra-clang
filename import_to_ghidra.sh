#!/bin/bash
dir_of_ghidra="$1"
dir_of_files="$3"
dir_of_proj="$2"

if ! test -e "$dir_of_proj"; then
    mkdir -p "$dir_of_proj"
fi

ls -1 "$dir_of_files" | ( while read r; do \
    "${dir_of_ghidra}/support/analyzeHeadless" "$dir_of_proj" "test_proj" -import "$dir_of_files/$r"; done )

