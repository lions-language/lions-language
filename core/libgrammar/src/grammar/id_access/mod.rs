use crate::lexical::{CallbackReturnStatus};
use crate::grammar::{GrammarParser, Grammar};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn format_define(&mut self) {
        /*
         * 处理如: a is math::Get
         * env:
         *  1. 从 math 开始, 不要跳过 math
         * */
    }
}
