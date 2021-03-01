use libresult::DescResult;
use super::{GrammarParser, Grammar
    , ExpressContext, OperatorIsContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenMethodResult};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn is_process(&mut self, express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        /*
         * 移除 is token
         * */
        let t = self.take_next_one();
        /*
         * 查找, 直到找到比 is 优先级小或者等于的为止
         * */
        let tp = match self.lookup_next_one_ptr() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * 操作符之后没有token => 语法错误
                 * */
                self.panic("expect one token, but arrive EOF");
                return TokenMethodResult::Panic;
            }
        };
        let r =  self.expression(t.token_attrubute().bp, express_context, &tp);
        if let DescResult::Error(err) = self.grammar_context().cb.operator_is(
            OperatorIsContext::new_with_all(t.token_value(), express_context.scope_context.clone())) {
            self.panic(&err);
        };
        r
    }
}

