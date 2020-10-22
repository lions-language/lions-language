use libresult::DescResult;
use libtype::{TypeAttrubute};
use libtype::function::{FunctionParamLengthenAttr};
use libtype::structure::{StructDefine};
use super::{GrammarParser, Grammar};
use crate::grammar::{FunctionDefineParamMutContext
    , StructDefineFieldContext
    , TypeToken, StructDefineContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn struct_parse_field_list(&mut self, define_context: &mut StructDefineContext
        , define: &mut StructDefine) {
        /*
         * 查找 (
         * */
        self.expect_next_token(|parser, t| {
            let token = t.as_ref::<T, CB>();
            match token.context_token_type() {
                TokenType::LeftBigParenthese => {
                    parser.skip_next_one();
                },
                _ => {
                    parser.panic(&format!(
                            "expect `{}`, but found {:?}", "{", token.context_token_type()));
                }
            }
        }, "`(`");
        /*
         * 查找 参数 (id id) 或者 (id: id)
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                self.panic("expect `}` or fields, but arrive IO EOF");
                return;
            }
        };
        let next = tp.as_ref::<T, CB>();
        match next.context_ref().token_type() {
            TokenType::Id => {
                self.struct_find_fields(define_context, define);
            },
            TokenType::RightBigParenthese => {
                /*
                 * 方法没有参数
                 * 跳过 )
                 */
                self.skip_next_one();
            },
            _ => {
                /*
                 * 既不是 ) 也不是 id => 语法错误
                 * */
                self.panic(
                    &format!(
                        "expect `{}` or id, after `{}`, but found: {:?}"
                        , "}", "{"
                        , next.context_ref().token_type()));
                return;
            }
        }
    }

    fn struct_find_fields(&mut self, define_context: &mut StructDefineContext
        , define: &mut StructDefine) {
        let mut mut_context = FunctionDefineParamMutContext::default();
        loop {
            self.struct_find_field(&mut mut_context, define_context
                , define);
            let tp = match self.lookup_next_one_ptr() {
                Some(tp) => {
                    tp
                },
                None => {
                    /*
                     * id as type 后面是 ) 或者 ,
                     * 但是遇到了 IO EOF => 语法错误
                     * */
                    self.panic("expect `,` or `}`, but arrive IO EOF");
                    return;
                }
            };
            let next = tp.as_ref::<T, CB>();
            match next.context_ref().token_type() {
                TokenType::Comma => {
                    /*
                     * name type,
                     * */
                    self.skip_next_one();
                    continue;
                },
                TokenType::RightBigParenthese => {
                    /*
                     * name type)
                     * */
                    self.skip_next_one();
                    break;
                },
                _ => {
                }
            }
        }
    }

    fn struct_find_field_name(&mut self) -> TokenVecItem<T, CB> {
        /*
         * 查找 name id
         * */
        self.expect_next_token(|parser, t| {
            let token = t.as_ref::<T, CB>();
            match token.context_ref().token_type() {
                TokenType::Id => {
                },
                _ => {
                    /*
                     * 期望一个id作为参数名, 但是token不是id => 语法错误
                     * */
                    parser.panic(&format!(
                            "expect id as field name, but found {:?}"
                            , token.context_ref().token_type()));
                    return;
                }
            }
        }, "id as field name");
        self.take_next_one()
    }

    fn struct_find_field_type_with_token(&mut self, t: TokenPointer) 
        -> (TypeAttrubute, FunctionParamLengthenAttr, TypeToken) {
        let token = t.as_ref::<T, CB>();
        match token.context_ref().token_type() {
            TokenType::Colon => {
                /*
                 * name: type 形式
                 * */
                self.skip_next_one();
                let tp = self.expect_next_token(|_, _| {
                }, "expect id / `*` / `&`").expect("should not happend");
                /*
                 * 查找 : 后面的 id
                 * 如果不是 id => 语法错误
                 * */
                self.typ_parse_with_next(tp)
            },
            _ => {
                self.typ_parse_with_next(t)
            }
        }
    }

    fn struct_find_field_type(&mut self, tp: Option<TokenPointer>)
        -> (TypeAttrubute, FunctionParamLengthenAttr, TypeToken) {
        /*
         * 如果已经获取了next token, 那么直接传入 token
         * 否则, 查看下一个, 再调用
         * */
        match tp {
            Some(tp) => {
                self.struct_find_field_type_with_token(tp)
            },
            None => {
                let tp = self.expect_next_token(|_, _| {
                }, "type");
                self.struct_find_field_type_with_token(tp.expect("should not happend"))
            }
        }
    }

    fn struct_find_field(&mut self
        , mut_context: &mut FunctionDefineParamMutContext
        , define_context: &mut StructDefineContext
        , define: &mut StructDefine) {
        /*
         * 查找 name id
         * */
        let name_token = self.struct_find_field_name();
        let (typ_attr, lengthen_attr, type_token) = self.struct_find_field_type(None);
        if let FunctionParamLengthenAttr::Lengthen = lengthen_attr {
            // *define_context.has_lengthen_param_mut() = true;
        };
        check_desc_result!(self, self.grammar_context().cb.struct_define_field(
            StructDefineFieldContext::new_with_all(
                name_token.token_value(), type_token
                , typ_attr), define));
    }
}

