use libtype::{PackageType, PackageTypeValue
    , TypeAttrubute};
use libtype::package::{PackageStr};
use libresult::DescResult;
use super::{GrammarParser, Grammar
    , CallFuncScopeContext, LoadVariantContext
    , DescContext, ConstStringContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn string_process(&mut self, desc_ctx: DescContext) {
        let token_value = self.take_next_one().token_value();
        self.cb().const_string(ConstStringContext{
            value: token_value,
            typ_attr: TypeAttrubute::Move
        });
    }
}

