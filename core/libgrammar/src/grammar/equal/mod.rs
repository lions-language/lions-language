use libresult::DescResult;
use super::{GrammarParser, Grammar
    , ExpressContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenMethodResult};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn equal_process(&mut self, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        /*
         * 移除 = token
         * */
        let t = self.take_next_one();
        /*
         * 查找, 直到找到比 = 优先级小或者等于的为止
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
        if let DescResult::Error(err) = self.grammar_context().cb.operator_equal(t.token_value()) {
            self.panic(&err);
        };
        r
    }

    pub fn equal_equal_process(&mut self, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        /*
         * 移除 = token
         * */
        let t = self.take_next_one();
        /*
         * 查找, 直到找到比 = 优先级小或者等于的为止
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
        if let DescResult::Error(err) = self.grammar_context().cb.operator_equal_equal(
            crate::grammar::OperatorEqualEqualContext::new_with_all(
                t.token_value(), express_context.desc_ctx.clone())) {
            self.panic(&err);
        };
        r
    }
}

