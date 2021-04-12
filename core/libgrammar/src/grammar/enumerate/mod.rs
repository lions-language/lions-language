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
        let tp = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                self.panic("expect id after interface, but arrive EOF");
                panic!();
            }
        };
        let next = tp.as_ref::<T, CB>();
        if let TokenType::Id = next.context_token_type() {
        } else {
            self.panic(&format!("expect id after interface, but meet {:?}"
                , next.context_token_type()));
        }
        let next_token = self.take_next_one();
        let name = extract_token_data!(next_token.token_value().token_data_unchecked(), Id);
        self.enum_block_process();
    }

    fn enum_block_process(&mut self) {
    }
}

