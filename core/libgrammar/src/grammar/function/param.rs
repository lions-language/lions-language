use libtype::{TypeAttrubute};
use libtype::function::{FunctionParamLengthenAttr};
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , FunctionDefineParamContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

enum FunctionType {
    Unknown,
    Named,
    Anonymous,
    ObjectMethod,
    StructMethod
}

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn function_parse_param_list(&mut self) {
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
        let tp = match self.lookup_next_one_ptr() {
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
                self.function_find_params();
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
                self.panic(&format!("expect `)` or id, after `(`, but found: {:?}", next.context_ref().token_type()));
                return;
            }
        }
    }

    fn function_find_params(&mut self) {
        let mut param_no = 0;
        loop {
            self.function_find_param(param_no);
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

    fn function_find_param_name(&mut self) -> TokenVecItem<T, CB> {
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
                    parser.panic(&format!("expect id as param name, but found {:?}", token.context_ref().token_type()));
                    return;
                }
            }
        }, "id as param name");
        self.take_next_one()
    }

    fn function_find_param_type_with_token(&mut self, t: TokenPointer) 
        -> (TypeAttrubute, FunctionParamLengthenAttr) {
        /*
         * 支持 name type 的方式, 也支持 name: type 的方式
         * 所以如果后面是 :(冒号) => 跳过
         * */
        let mut typ_attr = TypeAttrubute::default();
        let mut lengthen_attr = FunctionParamLengthenAttr::Fixed;
        let token = t.as_ref::<T, CB>();
        match token.context_ref().token_type() {
            TokenType::Id => {
                /*
                 * name type 形式
                 * */
                typ_attr = TypeAttrubute::Move;
            },
            TokenType::Multiplication => {
                /*
                 * name *type 形式
                 * */
                typ_attr = TypeAttrubute::Pointer;
                self.skip_next_one();
            },
            TokenType::And => {
                typ_attr = TypeAttrubute::Ref;
                self.skip_next_one();
            },
            TokenType::Colon => {
                /*
                 * name: type 形式
                 * */
                self.skip_next_one();
                /*
                 * 查找 : 后面的 id
                 * 如果不是 id => 语法错误
                 * */
                // println!("colon");
                self.expect_next_token(|parser, t| {
                    let token = t.as_ref::<T, CB>();
                    // println!("{:?}", token.context_token_type());
                    match token.context_ref().token_type() {
                        TokenType::Id => {
                            typ_attr = TypeAttrubute::Move;
                        },
                        TokenType::Multiplication => {
                            typ_attr = TypeAttrubute::Pointer;
                            parser.skip_next_one();
                        },
                        TokenType::And => {
                            typ_attr = TypeAttrubute::Ref;
                            parser.skip_next_one();
                        },
                        _ => {
                            /*
                             * : 后面不是 id => 语法错误
                             * */
                            parser.panic(&format!("expect id as type, but found: {:?}", token.context_ref().token_type()));
                        }
                    }
                }, "id as type");
            },
            _ => {
                /*
                 * 应该是 id (type), 但是没有给定 id token => 语法错误
                 * */
                self.panic(&format!("expect id as type or `:`, but found: {:?}", token.context_ref().token_type()));
            }
        }
        (typ_attr, lengthen_attr)
    }

    fn function_find_param_type(&mut self, tp: Option<TokenPointer>)
        -> (TypeAttrubute, FunctionParamLengthenAttr, TokenVecItem<T, CB>) {
        /*
         * 如果已经获取了next token, 那么直接传入 token
         * 否则, 查看下一个, 再调用
         * */
        let (typ_attr, lengthen_attr) = match tp {
            Some(tp) => {
                self.function_find_param_type_with_token(tp)
            },
            None => {
                let tp = self.expect_next_token(|_, _| {
                }, "type");
                self.function_find_param_type_with_token(tp.expect("should not happend"))
            }
        };
        /*
         * 语法正确的情况下, 到达了这里 => 下一个 token 一定是 id
         * */
        self.expect_next_token(|_, _| {
        }, "id as type");
        let type_token = self.take_next_one();
        // println!("{:?}", type_token.context_token_type());
        (typ_attr, lengthen_attr, type_token)
    }

    fn function_find_param(&mut self, param_no: usize) {
        /*
         * 查找 name id
         * */
        let name_token = self.function_find_param_name();
        let (typ_attr, lengthen_attr, type_token) = self.function_find_param_type(None);
        self.grammar_context().cb.function_define_param(
            FunctionDefineParamContext::new_with_all(
                name_token.token_value(), type_token.token_value()
                , typ_attr, lengthen_attr, param_no));
    }
}

