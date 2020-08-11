use libtype::{PackageType, PackageTypeValue
    , TypeAttrubute};
use libtype::package::{PackageStr};
use libresult::DescResult;
use super::{GrammarParser, Grammar
    , CallFuncScopeContext, LoadVariantContext
    , DescContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn id_process_id(&mut self, desc_ctx: DescContext) {
        let mut token_value = self.take_next_one().token_value();
        let context = LoadVariantContext::new_with_all(
            token_value, None, desc_ctx.typ_attr);
        match self.grammar_context().cb.load_variant(context) {
            DescResult::Error(e) => {
                self.panic(&e);
            },
            _ => {
            }
        }
    }

    pub fn id_process(&mut self, desc_ctx: DescContext) {
        /*
         * 1. 判断是否是函数调用
         * */
        let scope_context = CallFuncScopeContext{
            package_type: Some(PackageType::new(PackageTypeValue::Crate)),
            package_str: PackageStr::Itself,
            typ: None
        };
        self.set_backtrack_point();
        self.virtual_skip_next_one();
        match self.virtual_skip_white_space_token() {
            Some(tp) => {
                let token = tp.as_ref::<T, CB>();
                match token.context_token_type() {
                    TokenType::LeftParenthese => {
                        let bl = self.restore_from_backtrack_point();
                        self.funccall_process(bl, scope_context);
                        return;
                    },
                    TokenType::Point => {
                        unimplemented!();
                    },
                    _ => {
                        self.restore_from_backtrack_point();
                        self.id_process_id(desc_ctx);
                        return;
                    }
                }
            },
            None => {
                /*
                 * 去掉空白之后, 遇到的是 EOF => id 后面没有有效的 token
                 *  => 处理 id token
                 * */
                self.restore_from_backtrack_point();
                self.id_process_id(desc_ctx);
                return;
            }
        }
    }
}

