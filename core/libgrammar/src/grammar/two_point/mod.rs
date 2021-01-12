use libresult::DescResult;
use libtype::{TypeAttrubute};
use super::{GrammarParser, Grammar
    , ExpressContext, DescContext
    , NupContextValue, OperatorTwoPointContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenMethodResult, TokenType};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn two_point_process(&mut self, express_context: &mut ExpressContext<T, CB>)
        -> TokenMethodResult {
        /*
         * 移除 .. token
         * */
        let t = self.take_next_one();
        /*
         * 查找, 直到找到比 .. 优先级小或者等于的为止
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
        if let DescResult::Error(err) = self.grammar_context().cb.operator_two_point(
            crate::grammar::OperatorTwoPointContext::new_with_all(
                t.token_value(), express_context.desc_ctx.clone())) {
            self.panic(&err);
        };
        r
    }
}

