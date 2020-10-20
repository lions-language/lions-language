use libtype::{PackageType, PackageTypeValue
    , TypeAttrubute};
use libtype::package::{PackageStr};
use libresult::DescResult;
use crate::grammar::{GrammarParser, Grammar
    , ExpressContext
    , VarUpdateStmtContext, LoadVariantContext
    , DescContext, EnterPointAccessContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType, TokenData};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn id_process_equal(&mut self) {
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
        self.cb().var_update_stmt(VarUpdateStmtContext::default());
    }
}
 
