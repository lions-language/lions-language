use libtype::{PackageType, PackageTypeValue};
use libtype::package::{PackageStr};
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

    pub fn id_process(&mut self, desc_ctx: DescContext) {
        /*
         * 1. 判断是否是函数调用
         * */
        // println!("{:?}", &desc_ctx);
        let scope_context = CallFuncScopeContext{
            package_type: Some(PackageType::new(PackageTypeValue::Crate)),
            package_str: PackageStr::Itself,
            module_str: None,
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
                        /*
                         * TODO 填充 scope_context 中的 module_str
                         * */
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

mod point_access;
mod equal;

