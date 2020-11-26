use super::{GrammarParser, Grammar
    , DescContext, ConstStringContext};
use crate::lexical::{CallbackReturnStatus};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn string_process(&mut self, desc_ctx: DescContext) {
        let token_value = self.take_next_one().token_value();
        // println!("{:?}", desc_ctx.typ_attr_ref());
        self.cb().const_string(ConstStringContext{
            value: token_value,
            typ_attr: desc_ctx.typ_attr()
        });
    }
}

