#!/bin/bash
dir_of_sources="$4"
dir_of_files="$3"
dir_of_proj="$2"
dir_of_ghidra="$1"

if ! test -e "$dir_of_proj"; then
    mkdir -p "$dir_of_proj"
fi

if ! test -e "$dir_of_sources"; then
    mkdir -p "$dir_of_sources"
fi

ls -1 "$dir_of_files" | ( while read r; do \
    "${dir_of_ghidra}/support/analyzeHeadless" "$dir_of_proj" "test_proj" -process "$r" -postScript ~/ghidra_scripts/DecompileToC.java "$dir_of_sources/$r.c"; done )

