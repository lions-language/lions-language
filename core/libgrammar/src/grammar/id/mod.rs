use libresult::DescResult;
use super::{GrammarParser, Grammar
    , CallFuncScopeContext, LoadVariantContext
    , DescContext};
use crate::lexical::{CallbackReturnStatus, TokenPointer};
use crate::token::{TokenType, TokenData};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn id_process_id(&mut self, desc_ctx: DescContext) {
        let mut token_value = self.take_next_one().token_value();
        let mut lengthen_offset = 0;
        match self.lookup_next_one_ptr() {
            Some(tp) => {
                /*
                 * 查看下一个 token
                 * */
                let token = tp.as_ref::<T, CB>();
                match token.context_token_type() {
                    TokenType::ThreePoint => {
                        lengthen_offset = self.id_process_three_point();
                    },
                    _ => {
                    }
                }
            },
            None => {
            }
        }
        let name =
            extract_token_data!(token_value.token_data_ref().as_ref().expect("should not happend")
                , Id).to_string();
        let context = LoadVariantContext::new_with_all(
            token_value, None, desc_ctx.typ_attr_clone(), lengthen_offset);
        match self.grammar_context().cb.load_variant(context) {
            DescResult::Error(e) => {
                self.panic(&e);
            },
            _ => {
            }
        }
        self.id_after_process_id_without_next(desc_ctx, Some(name));
    }

    /*
     * 如果匹配 => 返回 true, 否则返回 false
     * */
    fn id_after_process_id_with_next(&mut self, desc_ctx: DescContext
        , tp: &TokenPointer, name: Option<String>) -> bool {
        let next = tp.as_ref::<T, CB>();
        match next.context_token_type() {
            TokenType::Equal => {
                self.id_process_equal(desc_ctx, name);
                return true;
            },
            _ => {
            }
        }
        false
    }

    fn id_after_process_id_without_next(&mut self, desc_ctx: DescContext
        , name: Option<String>) -> bool {
        let tp = match self.lookup_next_one_ptr() {
            Some(tp) => tp,
            None => {
                return false;
            }
        };
        self.id_after_process_id_with_next(desc_ctx, &tp, name)
    }

    pub fn id_process_three_point(&mut self) -> usize {
        /*
         * 跳过 ...
         * */
        self.skip_next_one();
        /*
         * 取出 ... 后面的 `[index]`
         * */
        self.expect_and_take_next_token(TokenType::LeftSquareBrackets);
        /*
         * 查找 数值
         * */
        let tp = self.expect_next_token_unchecked(|_, _| {
        }, "integer");
        let token = tp.as_ref::<T, CB>();
        if !token.context_token_type().is_integer() {
            self.panic(&format!("expect integer, but meet: {:?}"
                    , token.context_token_type()));
        }
        let next = self.take_next_one();
        let primeval_data = extract_token_data!(
            next.token_value().token_data().unwrap(), Const);
        let lengthen_offset = primeval_data.fetch_number_to_usize();
        /*
         * 查找闭合的 `]`
         * */
        self.expect_and_take_next_token(TokenType::RightSquareBrackets);
        lengthen_offset
    }

    fn id_process_coloncolon(&mut self, mut desc_ctx: DescContext) {
        /*
         * 宗旨: 最多一层 ::, 因为 import 的时候已经指定了
         * */
        *desc_ctx.coloncolon_prefix_mut() = true;
        let mut t = self.take_next_one();
        let module_prefix = extract_token_data!(
            t.token_value().token_data().expect("should not happend")
            , Id);
        /*
         * 跳过 ::
         * */
        self.skip_next_one();
        // self.cb().enter_colon_colon()
        self.id_process_inner(desc_ctx, Some(module_prefix));
    }

    pub fn id_process(&mut self, desc_ctx: DescContext) {
        self.id_process_inner(desc_ctx, None);
    }

    fn id_process_inner(&mut self, desc_ctx: DescContext
        , module_prefix: Option<String>) {
        /*
         * 1. 判断是否是函数调用
         * */
        // println!("{:?}", &desc_ctx);
        let mut scope_context = CallFuncScopeContext{
            module_prefix: module_prefix,
            desc_ctx: desc_ctx.clone()
        };
        self.set_backtrack_point();
        self.virtual_skip_next_one();
        match self.lookup_next_one_ptr() {
            Some(tp) => {
                let token = tp.as_ref::<T, CB>();
                match token.context_token_type() {
                    TokenType::LeftBigParenthese => {
                        let bl = self.restore_from_backtrack_point();
                        self.structinit_process(bl, scope_context);
                        return;
                    },
                    TokenType::NewLine => {
                        self.restore_from_backtrack_point();
                        self.id_process_id(desc_ctx);
                        return;
                    },
                    _ => {
                    }
                }
            },
            None => {
                self.restore_from_backtrack_point();
                self.id_process_id(desc_ctx);
                return;
            }
        }
        match self.virtual_skip_white_space_token() {
            Some(tp) => {
                let token = tp.as_ref::<T, CB>();
                match token.context_token_type() {
                    TokenType::LeftParenthese => {
                        let bl = self.restore_from_backtrack_point();
                        self.funccall_process(bl, scope_context);
                        if *desc_ctx.star_prefix_ref() {
                            self.id_after_process_id_without_next(desc_ctx, None);
                        }
                        return;
                    },
                    TokenType::LeftBigParenthese => {
                        let bl = self.restore_from_backtrack_point();
                        self.structinit_process(bl, scope_context);
                        return;
                    },
                    TokenType::Point => {
                        let bl = self.restore_from_backtrack_point();
                        self.id_process_point(desc_ctx, bl, scope_context);
                        return;
                    },
                    TokenType::ColonColon => {
                        let bl = self.restore_from_backtrack_point();
                        self.id_process_coloncolon(desc_ctx);
                        return;
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

mod point_access;
mod equal;

