use libresult::{DescResult};
use super::{GrammarParser, Grammar
    , ModuleStmtContext};
use crate::token::TokenType;
use crate::lexical::{CallbackReturnStatus};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn module_process(&mut self) {
        /*
         * 跳过 module 关键字
         * */
        self.skip_next_one();
        /*
         * module 后面只有能有一个 Id token
         * */
        self.expect_next_token(|grammar, tp| {
            let token = tp.as_ref::<T, CB>();
            match token.context_token_type() {
                TokenType::Id => {
                },
                _ => {
                    grammar.panic(
                        &format!("expect id after module, but meet {:?}", token.context_token_type()));
                }
            }
        }, "id after module");
        let t = self.take_next_one();
        check_desc_result!(self, self.cb().module_stmt(
            ModuleStmtContext::new_with_all(t.token_value())));
    }
}
