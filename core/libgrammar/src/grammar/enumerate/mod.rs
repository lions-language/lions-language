use libtype::{TypeAttrubute};
use libtype::interface::{InterfaceDefine};
use crate::grammar::{GrammarParser, Grammar, NextToken, ExpressContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue, TokenData};
use libresult::{DescResult};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn enum_process(&mut self) {
        /*
         * 跳过 enum 关键字
         * */
        self.skip_next_one();
    }
}

