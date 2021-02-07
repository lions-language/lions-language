use libresult::DescResult;
use libtype::{TypeAttrubute};
use libtype::function::{FunctionParamLengthenAttr};
use libtype::interface::{InterfaceDefine};
use crate::grammar::{GrammarParser, Grammar
    , FunctionDefineParamContext};
use crate::grammar::{FunctionDefineParamMutContext
    , TypeToken, FunctionDefineContext
    , FunctionDefineParamContextType};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn interface_function_parse_param_list(&mut self, start_param_no: usize
        , define_context: &mut FunctionDefineContext
        , define: &mut InterfaceDefine) {
        /*
         * 查找 (
         * */
        self.expect_next_token(|parser, t| {
            let token = t.as_ref::<T, CB>();
            match token.context_token_type() {
                TokenType::LeftParenthese => {
                    parser.skip_next_one();
                },
                _ => {
                    parser.panic(&format!("expect `(`, but found {:?}", token.context_token_type()));
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
                self.panic("expect `)` or params, but arrive IO EOF");
                return;
            }
        };
        let next = tp.as_ref::<T, CB>();
        match next.context_ref().token_type() {
            TokenType::Id => {
                self.interface_function_find_params(start_param_no, define_context, define);
            },
            TokenType::RightParenthese => {
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
                        "expect `)` or id, after `(`, but found: {:?}"
                        , next.context_ref().token_type()));
                return;
            }
        }
    }

    fn interface_function_find_params(&mut self, start_param_no: usize
        , define_context: &mut FunctionDefineContext
        , define: &mut InterfaceDefine) {
        let mut param_no = start_param_no.clone();
        loop {
            self.interface_function_find_param(param_no, define, define_context);
            param_no += 1;
            let tp = match self.lookup_next_one_ptr() {
                Some(tp) => {
                    tp
                },
                None => {
                    /*
                     * id as type 后面是 ) 或者 ,
                     * 但是遇到了 IO EOF => 语法错误
                     * */
                    self.panic("expect `,` or `)`, but arrive IO EOF");
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
                TokenType::RightParenthese => {
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

    fn interface_function_find_param_name(&mut self) -> TokenVecItem<T, CB> {
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
                    parser.panic(&format!("expect id as param name, but found {:?}"
                            , token.context_ref().token_type()));
                    return;
                }
            }
        }, "id as param name");
        self.take_next_one()
    }

    fn interface_function_find_param_type_with_token(&mut self, t: TokenPointer) 
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

    fn interface_function_find_param_type(&mut self, tp: Option<TokenPointer>)
        -> (TypeAttrubute, FunctionParamLengthenAttr, TypeToken) {
        /*
         * 如果已经获取了next token, 那么直接传入 token
         * 否则, 查看下一个, 再调用
         * */
        match tp {
            Some(tp) => {
                self.interface_function_find_param_type_with_token(tp)
            },
            None => {
                let tp = self.expect_next_token(|_, _| {
                }, "type");
                self.interface_function_find_param_type_with_token(tp.expect("should not happend"))
            }
        }
    }

    fn interface_function_find_param(&mut self, param_no: usize
        , define: &mut InterfaceDefine
        , context: &mut FunctionDefineContext) {
        /*
         * 查找 name id
         * */
        let name_token = self.interface_function_find_param_name();
        let (typ_attr, lengthen_attr, type_token) = self.interface_function_find_param_type(None);
        if let FunctionParamLengthenAttr::Lengthen = lengthen_attr {
            *context.has_lengthen_param_mut() = true;
        };
        check_desc_result!(self, self.grammar_context().cb.interface_function_define_param(
            define, FunctionDefineParamContext::new_with_all(
                name_token.token_value(), FunctionDefineParamContextType::Token(type_token)
                , typ_attr, lengthen_attr, param_no)));
    }
}

