use libtype::{PackageType, PackageTypeValue
    , TypeAttrubute};
use libtype::package::{PackageStr};
use libresult::DescResult;
use super::{GrammarParser, Grammar
    , ExpressContext
    , CallFuncScopeContext, LoadVariantContext
    , DescContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType, TokenData};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn id_process_point(&mut self, backtrack_len: usize
        , scope_context: CallFuncScopeContext) {
        self.id_process_id(scope_context.desc_ctx_clone());
        /*
         * 跳过 点
         * */
        self.skip_next_one();
        /*
         * enter point access
         * */
        self.cb().enter_point_access();
        /*
         * 解析表达式
         * */
        self.expression_process_without_token(&ExpressContext::new(
                GrammarParser::expression_end_normal));
        while let Some(p) = self.skip_white_space_token() {
            let nt = p.as_ref::<T, CB>();
            match nt.context_token_type() {
                TokenType::Point => {
                    self.skip_next_one();
                    self.expression_process_without_token(&ExpressContext::new(
                            GrammarParser::expression_end_normal));
                },
                _ => {
                    break;
                }
            }
        }
        self.cb().leave_point_access();
    }
}

