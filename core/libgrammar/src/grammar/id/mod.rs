use super::{GrammarParser, Grammar, AfterIdProcess};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn id_process(&mut self) -> AfterIdProcess {
        /*
         * 1. 判断是否是函数调用
         * */
        self.set_backtrack_point();
        self.virtual_skip_next_one();
        match self.virtual_skip_white_space_token() {
            Some(tp) => {
                let token = tp.as_ref::<T, CB>();
                match token.context_token_type() {
                    TokenType::LeftParenthese => {
                        let bl = self.restore_from_backtrack_point();
                        self.funccall_process(bl);
                        return AfterIdProcess::FunctionCall;
                    },
                    _ => {
                        unimplemented!();
                    }
                }
            },
            None => {
                /*
                 * 去掉空白之后, 遇到的是 EOF => id 后面没有有效的 token
                 *  => 处理 id token
                 * */
                self.restore_from_backtrack_point();
                return AfterIdProcess::Id;
            }
        }
    }
}

