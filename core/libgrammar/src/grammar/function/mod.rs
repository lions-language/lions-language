use libtype::{TypeAttrubute};
use libtype::function::{FunctionParamLengthenAttr};
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , FunctionDefineParamContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

enum FunctionType {
    Unknown,
    Named,
    Anonymous,
    ObjectMethod,
    StructMethod
}

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn function_process(&mut self) {
        /*
         * 跳过 function 关键字
         * */
        self.skip_next_one();
        let tp = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * func 后面是 io EOF => 语法错误
                 * */
                self.panic("expect id or `(` after func, but arrive IO EOF");
                return;
            }
        };
        let next_token = tp.as_ref::<T, CB>();
        match next_token.context_ref().token_type() {
            TokenType::Id => {
                /*
                 * func xxx(...)
                 * */
                self.function_named();
            },
            TokenType::LeftSquareBrackets => {
                /*
                 * func [Type]() => 结构的静态方法
                 * func [self: Type]() => 结构的成员方法
                 * */
                self.function_method();
            },
            TokenType::LeftParenthese => {
                /*
                 * func() => 匿名
                 * */
                self.function_anonymous();
            },
            _ => {
                /*
                 * 两种形式都不是 => 语法错误
                 * */
                self.panic(
                    &format!("expect id or `(` after func, but found {:?}"
                        , next_token.context_ref().token_type()));
            }
        }
    }
}

mod anonymous;
mod method;
mod named;
mod param;
mod block;
mod ret;
