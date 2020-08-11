use libtype::{TypeAttrubute};
use libtype::primeval::{PrimevalType};
use libtype::package::{PackageStr};
use libresult::DescResult;
use super::{GrammarParser, Grammar
    , DescContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn and_process(&mut self) {
        /*
         * 跳过 `&`
         * */
        self.skip_next_one();
        /*
         * 判断 & 后面的 token
         * */
        let tp = self.expect_next_token(|_, _| {
        }, "const or id");
        let next_token = tp.expect("should not happend").as_ref::<T, CB>();
        let next_token_type = next_token.context_token_type();
        match next_token_type {
            TokenType::Id => {
                self.id_process(DescContext::new(
                        TypeAttrubute::Ref));
            },
            TokenType::Const(t) => {
                match t {
                    PrimevalType::Str => {
                        /*
                         * string
                         * */
                        self.string_process(DescContext::new(
                                TypeAttrubute::Ref));
                    },
                    _ => {
                        /*
                         * number
                         * */
                        self.number_process(DescContext::new(
                                TypeAttrubute::Ref));
                    }
                }
            },
            _ => {
                self.panic(&format!("{:?} should not after `&`", next_token_type));
            }
        }
    }
}

