use super::{GrammarParser, Grammar
    , DescContext, ConstNumberContext};
use crate::lexical::{CallbackReturnStatus};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn number_process(&mut self, desc_ctx: DescContext) {
        let token_value = self.take_next_one().token_value();
        self.cb().const_number(ConstNumberContext{
            value: token_value,
            typ_attr: desc_ctx.typ_attr()
        });
    }
}

