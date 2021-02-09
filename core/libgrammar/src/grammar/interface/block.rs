use libtype::{TypeAttrubute};
use libtype::interface::{InterfaceDefine};
use libresult::{DescResult};
use libcommon::ptr::{HeapPtr};
use crate::grammar::{FunctionDefineContext
    , FunctionDefineParamMutContext, FunctionStatementContext
    , InterfaceFunctionStatementContext};
use crate::grammar::{GrammarParser, Grammar, NextToken, ExpressContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue, TokenData};

enum Status {
    Continue,
    End
}

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn interface_block_process(&mut self) {
        /*
         * 左大括号
         * */
        self.expect_and_take_next_token_unchecked(TokenType::LeftBigParenthese);
        /*
         * 解析 interface 中的 所有 func
         * */
        let mut status = Status::Continue;
        loop {
            match self.interface_block() {
                Status::End => {
                    break;
                },
                Status::Continue => {
                }
            }
        }
    }

    fn interface_block(&mut self) -> Status {
        let tp = self.skip_white_space_token();
        match tp {
            Some(p) => {
                return self.interface_block_select(&p);
            },
            None => {
                return Status::End;
            }
        }
    }

    fn interface_block_select(&mut self, tp: &TokenPointer) -> Status {
        let token = tp.as_ref::<T, CB>();
        match token.context_token_type() {
            TokenType::Function => {
                return self.interface_block_function();
            },
            TokenType::Annotate => {
                return Status::Continue;
            },
            TokenType::RightBigParenthese => {
                self.skip_next_one();
                return Status::End;
            },
            _ => {
                self.panic(&format!("expect fn statement, but meet {:?}", token.context_token_type()));
                panic!();
            }
        }
    }

    fn interface_block_function(&mut self) -> Status {
        /*
         * 跳过 func 关键字
         * */
        self.skip_next_one();
        let tp = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * func 后面是 io EOF => 语法错误
                 * */
                self.panic("expect id or `(` / `[` after func, but arrive IO EOF");
                panic!();
            }
        };
        let next_token = tp.as_ref::<T, CB>();
        match next_token.context_ref().token_type() {
            TokenType::Id => {
                /*
                 * 跳过 id
                 * */
                self.skip_next_one();
            },
            _ => {
                self.panic(&format!("expect id after func, but meet: {:?}"
                        , next_token.context_token_type()));
            }
        }
        let mut context = FunctionDefineContext::new_with_all(false, HeapPtr::new_null());
        let mut define = InterfaceDefine::default();
        let mut interface_function_statement_context = InterfaceFunctionStatementContext::new_with_all();
        check_desc_result!(self, self.cb().interface_function_statement_start(&mut define
                            , &mut interface_function_statement_context));
        self.interface_function_parse_param_list(0, &mut context, &mut define);
        let mut func_statement_context = FunctionStatementContext::new_with_all(false);
        let is_end = self.interface_function_parse_return(&mut func_statement_context);
        check_desc_result!(self, self.cb().interface_function_statement_end(&mut define
                            , &mut interface_function_statement_context));
        if is_end {
            Status::End
        } else {
            Status::Continue
        }
    }
}
