use libtype::{TypeAttrubute};
use libtype::interface::{InterfaceDefine};
use crate::grammar::{GrammarParser, Grammar, NextToken, ExpressContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue, TokenData};
use libresult::{DescResult};

enum FunctionType {
    Unknown,
    Named,
    Anonymous,
    ObjectMethod,
    StructMethod
}

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn interface_process(&mut self) {
        /*
         * 跳过 interface 关键字
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
        let mut define = InterfaceDefine::new_with_all(name, None);
        check_desc_result!(self, self.cb().interface_define_start(&mut define));
        /*
         * 解析 block 中的函数
         * */
        self.interface_block_process();
        check_desc_result!(self, self.cb().interface_define_end(&mut define));
    }
}

mod block;
mod param;
mod ret;
