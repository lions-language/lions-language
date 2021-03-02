use libtype::{TypeAttrubute};
use libtype::primeval::{PrimevalType};
use libtype::package::{PackageStr};
use libresult::DescResult;
use super::{GrammarParser, Grammar
    , DescContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn nup_star_process(&mut self) {
        /*
         * 检测后面是否是 id
         * 如果不是 id 就不符合语法, 只有 id 才可以获取地址指向的内存
         * */
        self.skip_next_one();
        self.expect_next_token_unchecked(|grammar, tp| {
            let token = tp.as_ref::<T, CB>();
            match token.context_token_type() {
                TokenType::Id => {
                },
                _ => {
                    grammar.panic(
                        &format!("expect id after `*`, but meet {:?}", token.context_token_type()));
                }
            }
        }, "id after `*`");
        self.id_process(DescContext::new_with_all(TypeAttrubute::default(), true, false));
    }
}

