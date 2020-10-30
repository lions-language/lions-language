use libtype::{PackageType, PackageTypeValue
    , TypeAttrubute};
use libtype::package::{PackageStr};
use libresult::DescResult;
use crate::grammar::{GrammarParser, Grammar
    , ExpressContext
    , CallFuncScopeContext, LoadVariantContext
    , DescContext, EnterPointAccessContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType, TokenData};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone> GrammarParser<'a, T, CB> {
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
        /*
         * 判断 . 之后是不是 &
         * */
        let mut object_typ_attr = TypeAttrubute::Move;
        match self.skip_white_space_token() {
            Some(t) => {
                let token = t.as_ref::<T, CB>();
                match token.context_token_type() {
                    TokenType::And => {
                        object_typ_attr = TypeAttrubute::Ref;
                        self.skip_next_one();
                    },
                    _ => {
                    }
                }
            },
            None => {
            }
        }
        let context = EnterPointAccessContext::new_with_all(
            object_typ_attr);
        self.cb().enter_point_access(context);
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
        self.id_after_process_id_without_next(None);
    }
}

