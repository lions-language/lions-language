use super::{GrammarParser, Grammar};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn structure_process(&mut self) {
        /*
         * 跳过 struct 关键字
         * */
        self.skip_next_one();
        /*
         * 匹配 id (结构体名称)
         * */
        let name_token = self.expect_and_take_next_token(TokenType::Id);
        /*
         * 匹配 `{`
         * */
        self.expect_and_take_next_token(TokenType::LeftBigParenthese);
        /*
         * 判断 `{` 之后是 id 还是 `}`
         * */
        let tp = self.expect_next_token(|_, _| {
        }, "id or `}`").expect("should not happend");
        let token = tp.as_ref::<T, CB>();
        match token.context_token_type() {
            TokenType::RightBigParenthese => {
                /*
                 * `{` 之后直接是 `}`
                 * 跳过 `}`
                 * */
                self.skip_next_one();
            },
            TokenType::Id => {
                /*
                 * 解析成员
                 * */
                self.structure_member_parse();
            },
            _ => {
                self.panic(
                    &format!("expect id or `{}` after struct `{}`, but meet: {:?}"
                        , "{", "}", token.context_token_type()));
            }
        }
    }

    pub fn structure_member_parse(&mut self) {
    }
}
 
