#!/bin/bash
code_dir="$1"
min_size="$2"
ls -1 "${code_dir}" | (while read r; do
  clang -cc1 -fsyntax-only -load ./StmtParser.so -std=c17 -plugin parse-stmts -E -include nocode.h "${code_dir}/$r" `llvm-config --cflags` | (while read p; do
  # Old C++ version that would be too strict around syntax
  #clang++ -cc1 -x c++ -fsyntax-only -load ./StmtParser.so -std=gnu++11 -plugin parse-stmts -E -include nocode.h "${code_dir}/$r" `llvm-config --cflags` | (while read p; do
        func=`echo $p | cut -d: -f 1`
        sig=`echo $p | sed 's/^.*: //' | sed s/,//g`
        if echo "$sig" | grep -q -P ".{$min_size}" >& /dev/null ; then
          echo "$r:$func:$sig"
        fi
    done )
done )
