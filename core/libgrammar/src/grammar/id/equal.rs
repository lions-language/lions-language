use libresult::DescResult;
use crate::grammar::{GrammarParser, Grammar
    , ExpressContext
    , VarUpdateStmtContext, ValueUpdateStmtContext
    , DescContext};
use crate::lexical::{CallbackReturnStatus};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn id_process_equal(&mut self, desc_ctx: DescContext, name: Option<String>) {
        /*
         * 跳过 = token
         * */
        self.skip_next_one();
        /*
         * 处理表达式
         * */
        self.expect_next_token(|parser, tp| {
            parser.expression_process(&tp
                , &ExpressContext::new(GrammarParser::<T, CB>::expression_end_normal));
        }, "expression");
        if *desc_ctx.star_prefix_ref() {
            check_desc_result!(self, self.cb().value_update_stmt(ValueUpdateStmtContext::new_with_all(
            )))
        } else {
            check_desc_result!(self, self.cb().var_update_stmt(VarUpdateStmtContext::new_with_all(
                        name)));
        }
    }
}
 
