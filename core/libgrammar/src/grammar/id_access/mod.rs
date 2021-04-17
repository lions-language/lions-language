use crate::lexical::{CallbackReturnStatus};
use crate::grammar::{GrammarParser, Grammar};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn format_define(&mut self) {
        /*
         * 处理如: a is math::Get
         * env:
         *  1. 从 math 开始, 不要跳过 math
         * */
        let tp = self.skip_white_space_token();
        let token = tp.as_ref::<T, CB>();
        match token.context_token_type() {
            TokenType::Id => {
                return self.enum_block_item();
            },
            _ => {
                self.panic(&format!("expect id, but meet {:?}", token.context_token_type()));
                panic!();
            }
        }
    }
}
