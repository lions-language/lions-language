use libtype::{PackageType, PackageTypeValue
    , TypeAttrubute};
use libtype::package::{PackageStr};
use libresult::DescResult;
use super::{GrammarParser, Grammar
    , CallFuncScopeContext, LoadVariantContext
    , DescContext, ConstNumberContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone> GrammarParser<'a, T, CB> {
    pub fn number_process(&mut self, desc_ctx: DescContext) {
        let token_value = self.take_next_one().token_value();
        self.cb().const_number(ConstNumberContext{
            value: token_value,
            typ_attr: desc_ctx.typ_attr()
        });
    }
}

