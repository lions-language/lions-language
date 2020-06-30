use super::{GrammarParser, Grammar, NextToken, ExpressContext};
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
    fn function_parse_param_list(&mut self) {
        /*
         * 查找 (
         * */
        if let NextToken::<T, CB>::False(t) = self.expect_and_take_next_token(TokenType::LeftParenthese) {
            self.panic(&format!("expect `(`, but found {:?}", t.as_ref::<T, CB>().context_ref().token_type));
            return;
        }
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
        match &next.context_ref().token_type {
            TokenType::Id(_) => {
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
                self.panic(&format!("expect `)` or id, after `(`, but found: {:?}", &next.context_ref().token_type));
                return;
            }
        }
    }

    fn function_parse_block(&mut self) {
        /*
         * 查找 {
         * */
        match self.expect_and_take_next_token(TokenType::LeftBigParenthese) {
            NextToken::<T, CB>::False(t) => {
                self.panic(&format!("expect `{}`, but found {:?}", "{", t.as_ref::<T, CB>().context_ref().token_type));
                return;
            },
            NextToken::<T, CB>::True(t) => {
                /*
                 * 回调定义开始
                 * */
                self.cb().function_define_start(TokenValue::from_token(t));
            },
            _ => {
                return;
            }
        }
        /*
         * { 后面可能是语句, 也可能是 } (空语句)
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                self.panic("expect `}` or function body, but arrive IO EOF");
                return;
            }
        };
        let next = tp.as_ref::<T, CB>();
        match &next.context_ref().token_type {
            TokenType::RightBigParenthese => {
                /*
                 * { 后面是 }
                 * */
            },
            _ => {
                /*
                 * { 后面是语句块 => 处理语句块
                 * */
                self.select_with_exprcontext(&tp, &ExpressContext::new(GrammarParser::<T, CB>::expression_end_right_big_parenthese));
                /*
                 * 删除所有的空白
                 * */
                let tp = match self.skip_white_space_token() {
                    Some(tp) => {
                        tp
                    },
                    None => {
                        /*
                         * 取出空白后不存在下一个token, 到达了 IO EOF, 但是期望的是 } => 语法错误
                         * */
                        self.panic("expect `}`, but arrive IO EOF");
                        return;
                    }
                };
                let token = tp.as_ref::<T, CB>();
                /*
                 * 判断是否是 }, 如果不是 } => 语法错误
                 * */
                if let TokenType::RightBigParenthese = &token.context_ref().token_type {
                } else {
                    self.panic(&format!("expect `{}`, but found: {:?}", "}", &token.context_ref().token_type));
                    return;
                }
            }
        }
        /*
         * 到达这里说明 next token 是 } => 表达式结束
         * */
        let t = self.take_next_one();
        self.grammar_context().cb.function_define_end(TokenValue::from_token(t));
    }

    fn function_find_params(&mut self) {
        loop {
            self.function_find_param();
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
            match &next.context_ref().token_type {
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
            match token.context_ref().token_type {
                TokenType::Id(_) => {
                },
                _ => {
                    /*
                     * 期望一个id作为参数名, 但是token不是id => 语法错误
                     * */
                    parser.panic(&format!("expect id as param name, but found {:?}", &token.context_ref().token_type));
                    return;
                }
            }
        }, "id as param name");
        self.take_next_one()
    }

    fn function_find_param_type_with_token(&mut self, t: TokenPointer) {
        /*
         * 支持 name type 的方式, 也支持 name: type 的方式
         * 所以如果后面是 :(冒号) => 跳过
         * */
        let token = t.as_ref::<T, CB>();
        match token.context_ref().token_type {
            TokenType::Id(_) => {
                /*
                 * name type 形式
                 * */
            },
            TokenType::Multiplication => {
                /*
                 * name *type 形式
                 * */
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
                self.expect_next_token(|parser, t| {
                    let token = t.as_ref::<T, CB>();
                    match token.context_ref().token_type {
                        TokenType::Id(_) => {
                        },
                        _ => {
                            /*
                             * : 后面不是 id => 语法错误
                             * */
                            parser.panic(&format!("expect id as type, but found: {:?}", &token.context_ref().token_type));
                        }
                    }
                }, "id as type");
            },
            _ => {
                /*
                 * 应该是 id (type), 但是没有给定 id token => 语法错误
                 * */
                self.panic(&format!("expect id as type or `:`, but found: {:?}", &token.context_ref().token_type));
            }
        }
    }

    fn function_find_param_type(&mut self, tp: Option<TokenPointer>) -> TokenVecItem<T, CB> {
        /*
         * 如果已经获取了next token, 那么直接传入 token
         * 否则, 查看下一个, 再调用
         * */
        match tp {
            Some(tp) => {
                self.function_find_param_type_with_token(tp);
            },
            None => {
                self.expect_next_token(|parser, t| {
                    parser.function_find_param_type_with_token(t);
                }, "type");
            }
        }
        /*
         * 语法正确的情况下, 到达了这里 => 下一个 token 一定是 id
         * */
        let type_token = self.take_next_one();
        type_token
    }

    fn function_find_param(&mut self) {
        /*
         * 查找 name id
         * */
        let name_token = self.function_find_param_name();
        let type_token = self.function_find_param_type(None);
        self.grammar_context().cb.function_define_param(TokenValue::from_token(name_token), TokenValue::from_token(type_token));
    }

    pub fn function_process(&mut self) {
        /*
         * 跳过 function 关键字
         * */
        self.skip_next_one();
        let tp = match self.lookup_next_one_ptr() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * func 后面是 io EOF => 语法错误
                 * */
                self.panic("expect id or `(` after func, but arrive IO EOF");
                return;
            }
        };
        let next_token = tp.as_ref::<T, CB>();
        match &next_token.context_ref().token_type {
            TokenType::Id(_) => {
                /*
                 * func xxx(...)
                 * */
                self.function_named();
            },
            TokenType::LeftSquareBrackets => {
                /*
                 * func [Type]() => 结构的静态方法
                 * func [self: Type]() => 结构的成员方法
                 * */
                self.function_method();
            },
            TokenType::LeftParenthese => {
                /*
                 * func() => 匿名
                 * */
                self.function_anonymous();
            },
            _ => {
                /*
                 * 两种形式都不是 => 语法错误
                 * */
                self.panic(&format!("expect id or `(` after func, but found {:?}", next_token.context_ref().token_type));
            }
        }
    }
}

mod anonymous;
mod method;
mod named;
