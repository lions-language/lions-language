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
    pub fn enum_block_process(&mut self) {
        /*
         * 左大括号
         * */
        self.expect_and_take_next_token_unchecked(TokenType::LeftBigParenthese);
        /*
         * 解析 enum 中的 所有 func
         * */
        let mut status = Status::Continue;
        loop {
            match self.enum_block() {
                Status::End => {
                    break;
                },
                Status::Continue => {
                }
            }
        }
    }

    fn enum_block(&mut self) -> Status {
    }
}

