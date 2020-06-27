use super::{GrammarParser, Grammar, NextToken};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    fn function_anonymous(&mut self) {
        /*
         * 匿名 function
         * */
    }

    fn function_with_name(&mut self) {
        /*
         * 含有名称 function
         * */
        let next = self.take_next_one();
        self.grammar_context().cb.function_named_start(TokenValue::from_token(next));
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
        /*
         * 查找 {
         * */
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

    fn function_find_param(&mut self) {
        /*
         * 进入这里时, next 一定是 id token
         * */
        let name_token = self.take_next_one();
        /*
         * 支持 name type 的方式, 也支持 name: type 的方式
         * 所以如果后面是 :(冒号) => 跳过
         * */
        self.expect_next_token(|parser, t| {
            let token = t.as_ref::<T, CB>();
            match token.context_ref().token_type {
                TokenType::Id(_) => {
                    /*
                     * name type 形式
                     * */
                },
                TokenType::Colon => {
                    /*
                     * name: type 形式
                     * */
                    parser.skip_next_one();
                    /*
                     * 查找 : 后面的 id
                     * 如果不是 id => 语法错误
                     * */
                    parser.expect_next_token(|parser, t| {
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
                    parser.panic(&format!("expect id as type or `:`, but found: {:?}", &token.context_ref().token_type));
                }
            }
        }, "id as type or `:`");
        /*
         * 语法正确的情况下, 到达了这里 => 下一个 token 一定是 id
         * */
        let type_token = self.take_next_one();
        self.grammar_context().cb.function_param(TokenValue::from_token(name_token), TokenValue::from_token(type_token));
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
                self.function_with_name();
            },
            TokenType::LeftParenthese => {
                /*
                 * func(...)
                 * */
                self.function_anonymous();
            },
            _ => {
                /*
                 * 两种形式否不是 => 语法错误
                 * */
                self.panic(&format!("expect id or `(` after func, but found {:?}", next_token.context_ref().token_type));
            }
        }
    }
}
