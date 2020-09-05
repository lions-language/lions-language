use libresult::*;
use libcommon::ptr::RefPtr;
use libtype::structure::{StructDefine};
use super::{Grammar, GrammarParser
    , ExpressContext, CallFuncScopeContext
    , StructInitContext, StructInitFieldContext
    , DescContext};
use crate::lexical::{CallbackReturnStatus
    , TokenPointer, TokenVecItem};
use crate::token::{TokenMethodResult
    , TokenType, TokenData};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn structinit_process(&mut self, backtrack_len: usize
        , scope_context: CallFuncScopeContext) {
        /*
         * 获取名称
         * */
        let token = self.take_next_one();
        let name_data = token.token_value().token_data_unchecked();
        let struct_name = extract_token_data!(name_data, Id);
        let struct_define = StructDefine::default();
        let mut init_context = StructInitContext::new_with_all(
            struct_name, RefPtr::new_null(), DescContext::default());
        match self.cb().struct_init_start(&mut init_context) {
            DescResult::Error(e) => {
                self.panic(&e);
            },
            _ => {
            }
        }
        /*
         * 因为在之前的 virtual lookup 的时候已经判断了到达这里一定是结构体初始化
         * 为了效率, 这里不再依次判断, 应该直接跳过, 直到 `(` 之后的 token
         * */
        self.skip_next_n(backtrack_len+1);
        /*
         * 查看下一个有效 token 是否是 `}`
         * */
        let tp = self.expect_next_token_unchecked(|_, _| {
        }, "expect `}` or init list after `{`");
        let typ = tp.as_ref::<T, CB>().context_token_type();
        let mut field_len = 0;
        match typ {
            TokenType::RightBigParenthese => {
                /*
                 * xxx{} 形式 => 跳过 }
                 * */
                self.skip_next_one();
            },
            _ => {
                self.structinit_single_field(&mut init_context);
                field_len += 1;
                while let Some(p) = self.skip_white_space_token() {
                    let nt = p.as_ref::<T, CB>();
                    match nt.context_token_type() {
                        TokenType::Comma => {
                            self.skip_next_one();
                        },
                        TokenType::RightBigParenthese => {
                            self.skip_next_one();
                            break;
                        },
                        _ => {
                            panic!("should not happend, {:?}"
                                , nt.context_token_type());
                        }
                    }
                    self.structinit_single_field(&mut init_context);
                    field_len += 1;
                }
            }
        }
    }

    fn structinit_single_field(&mut self
        , init_context: &mut StructInitContext) {
        /*
         * 查找 name: expr
         * */
        /*
         * 查找 name
         * */
        let name_token = self.expect_and_take_next_token_unchecked(TokenType::Id);
        // let field_name = extract_token_data!(name_token.token_value().token_data_unchecked(), Id);
        let field_conext = StructInitFieldContext::new_with_all(
            name_token.token_value());
        /*
         * 查找 :
         * */
        self.expect_and_take_next_token_unchecked(TokenType::Colon);
        /*
         * expr
         * */
        self.cb().struct_init_field_before_expr(init_context
            , field_conext);
        self.expression_process_without_token(&ExpressContext::new(
                GrammarParser::<T, CB>::expression_end_structinit_list));
        self.cb().struct_init_field_after_expr(init_context);
    }
}

