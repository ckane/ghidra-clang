#!/bin/bash
header="$1"

sed -i "s/^typedef struct bignum/typedef char/" "$header"
sed -i "s/ processEntry / /" "$header"
grep -vF '__x86.get_pc_thunk'< "$header" > "$header.tmp"
mv "$header.tmp" "$header"

(echo "#define true 1" && \
    echo "#define false 0" && \
    echo "typedef char *pointer;" && \
    echo "typedef unsigned int uint;" && \
    echo "typedef unsigned short ushort;" && \
    echo "typedef char* string;" && \
    echo "typedef unsigned long undefined8;" && \
    cat "$header" \
) > "$header.tmp"
mv "$header.tmp" "$header"
