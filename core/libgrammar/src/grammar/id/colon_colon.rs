use libtype::{TypeAttrubute};
use libtype::package::{PackageStr};
use libresult::DescResult;
use crate::grammar::{GrammarParser, Grammar
    , ExpressContext
    , CallFuncScopeContext, LoadVariantContext
    , DescContext, EnterColonColonContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType, TokenData};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn id_process_coloncolon(&mut self, mut desc_ctx: DescContext) {
        /*
         * 宗旨: 最多一层 ::, 因为 import 的时候已经指定了
         * */
        let mut t = self.take_next_one();
        let module_prefix = extract_token_data!(
            t.token_value().token_data().expect("should not happend")
            , Id);
        /*
         * 跳过 ::
         * */
        self.skip_next_one();
        self.cb().enter_colon_colon(EnterColonColonContext::new_with_all(
                module_prefix.clone()));
        self.id_process_inner(desc_ctx, Some(module_prefix));
        self.cb().leave_colon_colon();
    }
}

