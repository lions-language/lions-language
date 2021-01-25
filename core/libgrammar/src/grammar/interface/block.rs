use libtype::{TypeAttrubute};
use libtype::interface::{InterfaceDefine};
use crate::grammar::{GrammarParser, Grammar, NextToken, ExpressContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue, TokenData};
use libresult::{DescResult};

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
                return Status::End;
            },
            _ => {
                self.panic(&format!("expect fn statement, but meet {:?}", token.context_token_type()));
                panic!();
            }
        }
    }

    fn interface_block_function(&mut self) -> Status {
        unimplemented!();
    }
}
