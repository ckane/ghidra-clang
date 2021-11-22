# Clang and Ghidra integrations for analysis

I've been working on some tools to facilitate using Ghidra's decompiler and Clang's front-end plugins to
help provide some functional code analysis. This folder contains some of this work.

I borrowed `DecompileToC.java` from the work provided in the following repository:
* https://github.com/h4sh5/ghidra-headless-decompile

## Compilation of Clang plugin

The source code in StmtParser.cpp is intended to be compiled as a front-end plugin for `clang`. The following
is an example of compiling/linking it:

```bash
clang++ -g2 -DPIC -fpic -shared -o StmtParser.so StmtParser.cpp `llvm-config --cxxflags`
```

## Running

To use this plugin with `clang` (doesn't try to compile, but instead just pre-processes and parses the
source with `-E`):

```bash
clang -cc1 -load ./StmtParser.so -plugin parse-stmts -E your_source_code.c `llvm-config --cflags` > sigs.txt
```

The above command will write the list of signatures and function call relationships to `sigs.txt`, while
writing any parsing errors or warnings to `stderr`.
