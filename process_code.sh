#!/bin/bash
code_dir="$1"
min_size="$2"
ls -1 "${code_dir}" | (while read r; do
  clang-10 -cc1 -load ./StmtParser.so -plugin parse-stmts -E "${code_dir}/$r" -I/usr/include -I/usr/lib/llvm-9/lib/clang/10.0.0/include 2> /dev/null | (while read p; do
        func=`echo $p | cut -d: -f 1`
        sig=`echo $p | sed 's/^.*: //' | sed s/,//g`
        if echo "$sig" | grep -q -P ".{$min_size}" >& /dev/null ; then
          echo "$r:$func:$sig"
        fi
    done )
done )
