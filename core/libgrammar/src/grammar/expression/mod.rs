use super::{GrammarParser, ExpressContext, Grammar};
use crate::lexical::{CallbackReturnStatus, TokenPointer, TokenVecItem};
use crate::token::{TokenType, TokenMethodResult, TokenOperType};

macro_rules! expression_check_end {
    ($self:ident, $express_context:ident) => {
        {
            let mut next_tp = match $self.lexical_parser.lookup_next_one_ptr() {
                Some(tp) => {
                    tp
                },
                None => {
                    /*
                     * 操作数之后是 EOF => 结束
                     * */
                    return TokenMethodResult::StmtEnd;
                }
            };
            let mut next_token = next_tp.as_ref::<T, CB>();
            let cb_r = ($express_context.end_f)($self, next_token);
            match cb_r {
                TokenMethodResult::StmtEnd
                | TokenMethodResult::ParentheseEnd => {
                    /*
                     * 语句结束 或者 是 () 内的结束
                     * */
                    return cb_r;
                },
                _ => {
                }
            }
            (next_tp, next_token)
        }
    }
}

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn expression_end_normal(grammar: &mut GrammarParser<T, CB>
        , token: &TokenVecItem<T, CB>) -> TokenMethodResult {
        // println!("normal end ... ");
        match token.context_ref().token_type() {
            TokenType::Semicolon
            | TokenType::NewLine => {
                grammar.skip_next_one();
                return TokenMethodResult::StmtEnd;
            },
            _ => {
            }
        }
        match token.token_attrubute().oper_type {
            TokenOperType::Operator => {
            },
            _ => {
                /*
                 * 如果 token 不是操作符 => 表达式结束
                 * */
                return TokenMethodResult::StmtEnd;
            }
        }
        TokenMethodResult::Continue
    }

    pub fn expression_end_block(grammar: &mut GrammarParser<T, CB>
        , token: &TokenVecItem<T, CB>) -> TokenMethodResult {
        // println!("normal end ... ");
        match token.context_ref().token_type() {
            TokenType::Semicolon
            | TokenType::NewLine
            | TokenType::RightBigParenthese => {
                grammar.skip_next_one();
                return TokenMethodResult::StmtEnd;
            },
            _ => {
            }
        }
        match token.token_attrubute().oper_type {
            TokenOperType::Operator => {
            },
            _ => {
                /*
                 * 如果 token 不是操作符 => 表达式结束
                 * */
                return TokenMethodResult::StmtEnd;
            }
        }
        TokenMethodResult::Continue
    }

    pub fn expression_end_right_big_parenthese(
        grammar: &mut GrammarParser<T, CB>
        , token: &TokenVecItem<T, CB>) -> TokenMethodResult {
        match token.context_ref().token_type() {
            TokenType::RightBigParenthese => {
                return TokenMethodResult::StmtEnd;
            },
            _ => {
            }
        }
        TokenMethodResult::Continue
    }

    pub fn expression_end_right_parenthese(grammar: &mut GrammarParser<T, CB>
        , token: &TokenVecItem<T, CB>) -> TokenMethodResult {
        let tp = match grammar.skip_white_space_token_with_input(TokenPointer::from_ref(token)) {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * 查找 ) 时, 遇到了 IoEOF => 语法错误
                 * */
                 grammar.panic("expect a `)`, but arrive IoEOF");
                 return TokenMethodResult::Panic;
            }
        };
        let t = tp.as_ref::<T, CB>();
        match t.context_ref().token_type() {
            TokenType::RightParenthese => {
                grammar.skip_next_one();
                return TokenMethodResult::ParentheseEnd;
            },
            _ => {
            }
        }
        TokenMethodResult::Continue
    }


    pub fn expression_end_param_list(
        grammar: &mut GrammarParser<T, CB>
        , token: &TokenVecItem<T, CB>) -> TokenMethodResult {
        match token.context_ref().token_type() {
            TokenType::RightParenthese
                | TokenType::Comma => {
                // grammar.skip_next_one();
                return TokenMethodResult::StmtEnd;
            },
            _ => {
            }
        }
        TokenMethodResult::Continue
    }

    pub fn expression_process_start_with_parenthese(&mut self) -> TokenMethodResult {
        /*
         * 表达式中遇到 ( 符号
         * 1. 先跳过  (
         * 2. 调用 expression (因为 小括号内的可以视为一个完整的语句)
         * */
        self.skip_next_one();
        let tp = match self.lookup_next_one_ptr() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * ( 后面是 EOF => 语法错误
                 * */
                self.panic("expect operand after `(`, but arrive EOF");
                return TokenMethodResult::Panic;
            }
        };
        self.expression(&0, &ExpressContext::new(GrammarParser::expression_end_right_parenthese), &tp)
    }

    pub fn expression_process_default_exprcontext(&mut self, token: &TokenPointer) {
        self.expression(&0, &ExpressContext::new(
                GrammarParser::<T, CB>::expression_end_normal), token);
    }

    pub fn expression_process(&mut self, token: &TokenPointer, express_context: &ExpressContext<T, CB>) {
        /*
         * 因为 0 比任何的操作数都要小, 所以可以将整个表达式遍历完全
         * */
        self.expression(&0, express_context, token);
    }

    /*
    pub fn express(&mut self, operator_bp: &u8, express_context: &ExpressContext<T, CB>, input_token_ptr: &TokenPointer) -> TokenMethodResult {
        let input_token = input_token_ptr.as_ref::<T, CB>();
        input_token.nup(self, express_context);
        let mut next_tp = self.lexical_parser.lookup_next_one_ptr().unwrap();
        let mut next_token = next_tp.as_ref::<T, CB>();
        while next_token.token_attrubute().bp > operator_bp {
            next_token.led(self, express_context);
            next_tp = self.lexical_parser.lookup_next_one_ptr().unwrap();
            next_token = next_tp.as_ref::<T, CB>();
        }
        TokenMethodResult::End
    }
    */

    /*
     * 找到比输入的优先级小的操作符为止
     * 1. 方法返回时, 下一个 token 应该是操作符
     * 2. token 的 nup方法结束后, 下一个 token 应该是 操作符 (或者是结束符)
     * 3. token 的 led方法结束后, 下一个 token 应该是 操作符
     * 4. 提供一个函数指针, 用于判断是否结束 (不需要捕获周边环境, 所以使用函数指针, 提高性能)
     * */
    pub fn expression(&mut self, operator_bp: &u8, express_context: &ExpressContext<T, CB>, input_token_ptr: &TokenPointer) -> TokenMethodResult {
        // expression_check_end!(self, express_context);
        let input_token = input_token_ptr.as_ref::<T, CB>();
        // println!("{:?}", input_token.context_token_type());
        let nup_r = input_token.nup(self, express_context);
        match nup_r {
            TokenMethodResult::None => {
                /*
                 * 如果 nup 中遇到了 前缀运算符, 内部会进行自身调用, 如果 前缀运算符后面不是 nup 可以处理的 token, 对应的 token 会自己抛出异常
                 * 比如说, 解析到 -1:
                 * 1. 首先调用 - 号的 nup 方法, - 号的 nup 方法中获取 next token. 调用 next token 的 nup 方法, 如果 next token 的  nup 方法返回 None, 需要报错
                 * */
                self.panic(&format!("expect operand, but found {:?}", input_token.context_ref().token_type()));
            },
            TokenMethodResult::StmtEnd => {
                // println!("stmt send");
                return nup_r;
            },
            _ => {}
        }
        // let (mut next_tp, mut next_token) = expression_check_end!(self, express_context);
        let mut next_tp = match self.lexical_parser.lookup_next_one_ptr() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * 操作数之后是 EOF => 结束
                 * */
                return TokenMethodResult::StmtEnd;
            }
        };
        let mut next_token = next_tp.as_ref::<T, CB>();
        /*
         * 检测是否需要结束
         * 一条语句的结束一定在操作数之后
         * */
        let cb_r = (express_context.end_f)(self, next_token);
        match cb_r {
            TokenMethodResult::StmtEnd
            | TokenMethodResult::ParentheseEnd => {
                /*
                 * 语句结束 或者 是 () 内的结束
                 * */
                return cb_r;
            },
            _ => {
            }
        }
        /*
        */
        // println!("{}", next_token.context.token_type.format());
        /*
         * 如果到达这里, 说明 next_token 是操作符
         * 比较优先级, 找到比输入的小(或者等于)的为止 (也就是说 只要大于就继续)
         * */
        while next_token.token_attrubute().bp > operator_bp {
            /*
             * 这里的 led 就是继续比对 next_token 这个操作符的 优先级, 找到比 next_token 优先级还要低(或者等于)的为止
             * */
            // println!{"{}", next_token.context.token_type.format()};
            let led_r = next_token.led(self, express_context);
            match led_r {
                TokenMethodResult::None => {
                    /*
                     * 操作符的 led 方法没有实现
                     * */
                    panic!(format!("operator: {:?} not implement", next_token.context_token_type()));
                },
                TokenMethodResult::StmtEnd
                | TokenMethodResult::ParentheseEnd => {
                    return led_r;
                },
                _ => {}
            }
            next_tp = match self.lexical_parser.lookup_next_one_ptr() {
                Some(tp) => {
                    tp
                },
                None => {
                    /*
                     * 如果到达这里, 说明 led 方法返回的不是 IoEOF, 那么这一次的 lookup next 一定不会是 None
                     * */
                    panic!("should not happend");
                    return TokenMethodResult::Panic;
                }
            };
            next_token = next_tp.as_ref::<T, CB>();
        }
        TokenMethodResult::End
    }
}

