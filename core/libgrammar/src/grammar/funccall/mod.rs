use super::{Grammar, GrammarParser
    , ExpressContext};
use crate::lexical::{CallbackReturnStatus
    , TokenVecItem};
use crate::token::{TokenMethodResult
    , TokenType};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn funccall_process(&mut self, backtrack_len: usize) {
        /*
         * 获取名称
         * */
        let token = self.take_next_one();
        /*
         * 因为在之前的 virtual lookup 的时候已经判断了到达这里一定是函数调用
         * 为了效率, 这里不再依次判断, 应该直接跳过, 直到 `(` 之后的 token
         * */
        self.skip_next_n(backtrack_len+1);
        /*
         * 查看下一个有效 token 是否是 `)`
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                self.panic("expect `)` after `(`");
                return;
            }
        };
        let typ = tp.as_ref::<T, CB>().context_token_type();
        match typ {
            TokenType::RightParenthese => {
                /*
                 * xxx() 形式 => 跳过 )
                 * */
                self.skip_next_one();
            },
            _ => {
                self.expression_process(&tp, &ExpressContext::new(
                        GrammarParser::<T, CB>::expression_end_param_list));
            }
        }
    }
}

