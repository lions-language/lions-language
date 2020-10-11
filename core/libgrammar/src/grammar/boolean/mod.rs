use crate::grammar::ConstBooleanContext;
use super::{GrammarParser, Grammar
    , DescContext};
use crate::lexical::{CallbackReturnStatus};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn true_process(&mut self, desc_ctx: DescContext) {
        let token_value = self.take_next_one().token_value();
        let context = ConstBooleanContext::new_with_all(
            token_value, desc_ctx.typ_attr);
        self.grammar_context().cb.const_boolean_true(context);
    }

    pub fn false_process(&mut self, desc_ctx: DescContext) {
        let token_value = self.take_next_one().token_value();
        let context = ConstBooleanContext::new_with_all(
            token_value, desc_ctx.typ_attr);
        self.grammar_context().cb.const_boolean_false(context);
    }
}
