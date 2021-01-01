use libtype::{TypeAttrubute};
use super::{GrammarParser, Grammar
    , ExpressContext, DescContext
    , NupContextValue, PrefixPlusPlusContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenMethodResult, TokenType};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn prefix_plus_plus_process(&mut self, express_context: &mut ExpressContext<T, CB>)
        -> TokenMethodResult {
        let count = match express_context.nup_context.value_mut() {
            NupContextValue::PrefixPlusPlus(v) => {
                *v += 1;
                *v
            },
            NupContextValue::None => {
                *express_context.nup_context.value_mut() = NupContextValue::PrefixPlusPlus(0);
                1
            }
        };
        /*
         * 移除 token
         * */
        let t = self.take_next_one();
        /*
         * 找到下一个 token, 然后调用下一个 token 的 nup
         * */
        let tp = match self.lookup_next_one_ptr() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * - 后面遇到了 EOF => 语法错误
                 * */
                self.panic("expect operand, but arrive EOF");
                return TokenMethodResult::Panic;
            }
        };
        let next = tp.as_ref::<T, CB>();
        match next.context_token_type() {
            TokenType::Id => {
                self.id_process(DescContext::new(
                        TypeAttrubute::Ref));
                self.grammar_context().cb.operator_prefix_plus_plus(
                    PrefixPlusPlusContext::new_with_all(t.token_value(), count));
                return TokenMethodResult::StmtEnd;
            },
            TokenType::PlusPlus => {
                let r = next.nup(self, express_context);
                match r {
                    TokenMethodResult::None => {
                        self.panic(&format!("expect operand, but found: {:?}", next.context_token_type()));
                    },
                    _ => {
                    }
                }
                return r;
            },
            _ => {
                self.panic(&format!("expect id or ++, but found: {:?}", next.context_token_type()));
                panic!();
            }
        }
    }

    pub fn suffix_plus_plus_process(&mut self, express_context: &mut ExpressContext<T, CB>)
        -> TokenMethodResult {
        /*
         * 移除 ++ token
         * */
        let t = self.take_next_one();
        self.grammar_context().cb.operator_suffix_increase(t.token_value());
        /*
         * 后置运算符, 不用继续查找下一个运算符
         * 但是后缀运算符后面只有如下几种token是合法的
         *  1. 结束串
         *  2. io EOF
         *  3. 后缀运算符 (a++++ <=> a++ ++)
         * */
        let tp = match self.lookup_next_one_ptr() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * 后缀运算符后面遇到 EOF => 结束 (情况 1)
                 * */
                return TokenMethodResult::StmtEnd;
            }
        };
        let next = tp.as_ref::<T, CB>();
        let cb_r = (express_context.end_f)(self, next);
        match cb_r {
            TokenMethodResult::StmtEnd
            | TokenMethodResult::End => {
                /*
                 * 情况 2
                 * */
                return cb_r;
            },
            _ => {
            }
        }
        /*
         * 调用 next 的 led 方法, 处理连续后缀运算符的情况 (情况 3)
         * */
        next.led(self, express_context)
    }
}

