#include <string>
#include <map>
#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"

using namespace clang;

namespace ckllvm {
  /* Storage for the function signatures: 1:1 Map func_name -> sig */
  std::map<std::string,std::string> func_sigs;

  /* Helps us keep track of the name of the function currently in process. */
  std::string *cur_func = NULL;

  /* Keep track of whether we're in a function or not. If not in a function, don't append statement
   * operators to signature string. */
  bool in_func = false;

  class ParseStmtsConsumer : public ASTConsumer {
    private:
      CompilerInstance &Instance;
    public:
      ParseStmtsConsumer(CompilerInstance &inst) : Instance(inst) {};

      //virtual bool shouldSkipFunctionBody(Decl *D) override { return false; };

      virtual bool HandleTopLevelDecl(DeclGroupRef DG) override {
        for (DeclGroupRef::iterator i = DG.begin(), e = DG.end(); i != e; ++i) {
          const Decl *D = *i;
          if (const NamedDecl *ND = dyn_cast<NamedDecl>(D)) {
            in_func = true;
          } else {
            in_func = false;
          }
        }

        return true;
      }

      virtual void HandleTranslationUnit(ASTContext &ctx) override {
        struct StmtVisitor : public RecursiveASTVisitor<StmtVisitor> {
          std::string mystring;
          int b;
          ASTContext &ctx;
          StmtVisitor(ASTContext &c) : b(0), ctx(c), mystring("") {};

          /* When we encounter a Function Declaration, the following will get executed. */
          virtual bool TraverseFunctionDecl(FunctionDecl *fndecl) {
            //llvm::errs() << "TraverseFnDecl " << fndecl->getName() << "\n";
            if(fndecl->getBody() && func_sigs.count(fndecl->getNameAsString()) == 0) {
              func_sigs.insert(std::pair<std::string,std::string>(fndecl->getNameAsString(), std::string("")));
              cur_func = &(func_sigs[fndecl->getNameAsString()]);
              in_func = true;
              //llvm::errs() << "top-level-decl: \"" << fndecl->getNameAsString() << "\"\n";
              this->TraverseStmt(fndecl->getBody());
              in_func = false;
            }
            return true;
          }

          /* Code to dump out details of current AST position. For debugging. */
          void displayASTSummary(Stmt *s) {
            llvm::outs() << "AST Summary\n";
            s->dumpPretty(this->ctx);
            llvm::outs() << "\n";
            s->dumpColor();
            llvm::errs() << "\n";
          }

          /* When we encounter a C/C++ statement (code that will be compiled), the following will get executed. */
          virtual bool VisitStmt(Stmt *s) {
            //displayASTSummary(s);
            b++;
            /* XXX - I don't believe I need this.
            if(DeclStmt::classof(s)) {
              DeclStmt *ds = (DeclStmt*)s;
              //llvm::errs() << "Class of DeclStmt " << ds->getOpcodeStr() << "\n";
            }
            */
            if(in_func && BinaryOperator::classof(s)) {
              BinaryOperator *bs = (BinaryOperator*)s;
              //llvm::outs() << "Class of Binary " << bs->getOpcodeStr() << "\n";

              std::string op = bs->getOpcodeStr();
              if(cur_func->size() > 1 && op != ",") {
                cur_func->push_back(',');
              }

              /* There are a number of multi-character operators. I would like to make all operators one character,
               * so that within strings they all contribute equal quantity of information.
               */
              if(op == ">=") {
                op = "G";
              } else if(op == "<=") {
                op = "B";
              } else if(op == "==") {
                op = "E";
              } else if(op == "!=") {
                op = "N";
              } else if(op == "<<") {
                op = "L";
              } else if(op == ">>") {
                op = "R";
              } else if(op == "&&") {
                op = "A";
              } else if(op == "||") {
                op = "O";
              } else if(op == "^^") {
                op = "X";
              }

              if(op.size() == 2 && op[1] == '=') {
                /* Consider all "=?" form operators not covered above to be two operations,
                 * first the arithmetic operation, and then the assignment.
                 * This is largely a product of that x += b is short for x = x + b
                 */
                cur_func->append(op.substr(0,1));
                cur_func->append(",");
                cur_func->append(op.substr(1,1));
              } else if(op.size() > 1) {
                /* If a multi-byte operator is uncovered here, it means I've missed something and
                 * need to update the earlier code.
                 */
                llvm::outs() << "Error (multi-char operator): " << op << "\n";
              } else if(op != ",") {
                cur_func->append(op);
              }
              if(op.size() < 1) {
                llvm::outs() << "Empty op ";
                s->dumpColor();
              }
            }
            return true;
          };

          /* Enforce post-order traversal, giving us operations in the order they will be executed. */
          virtual bool shouldTraversePostOrder() { return true; };
        };

        /* Create a new StmtVisitor instance. */
        StmtVisitor sv(ctx);

        if(sv.TraverseAST(ctx)) {
          // llvm::errs() << sv.b << "\n";
          // The below loop will dump the results
          for(std::map<std::string,std::string>::iterator s_i = func_sigs.begin(); s_i != func_sigs.end(); ++s_i) {
            if(s_i->second.size() > 6) {
              llvm::outs() << s_i->first << ": " << s_i->second << "\n";
            }
          }
        }
      };
  };

  /* Configure an action class for inserting my ParseStmtsConsumer into the pipeline when my plugin is loaded. */
  class ParseStmtsAction : public PluginASTAction {
    protected:
      std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &ci, llvm::StringRef) {
        return llvm::make_unique<ParseStmtsConsumer>(ci);
      };

      /* At some point I may want to add cmdline args, such as if I want to test multiple
       * signature generation algorithms.
       */
      bool ParseArgs(const CompilerInstance &ci, const std::vector<std::string> &args) {
        return true;
      }
  };
}

/* Instantiate the plugin and add it to the toolchain. */
static FrontendPluginRegistry::Add<ckllvm::ParseStmtsAction>
stmts_parser("parse-stmts", "Parse Statments");
