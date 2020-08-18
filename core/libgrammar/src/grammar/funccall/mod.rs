use libresult::*;
use super::{Grammar, GrammarParser
    , ExpressContext, CallFuncScopeContext
    , CallFunctionContext};
use crate::lexical::{CallbackReturnStatus
    , TokenVecItem};
use crate::token::{TokenMethodResult
    , TokenType, TokenData};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn funccall_process(&mut self, backtrack_len: usize
        , scope_context: CallFuncScopeContext) {
        let mut call_context = CallFunctionContext::default();
        /*
         * 获取名称
         * */
        let token = self.take_next_one();
        let name = token.token_value();
        if let DescResult::Error(s) = self.cb().call_function_prepare(scope_context
            , name, &mut call_context) {
            self.panic(&s);
        };
        /*
         * 因为在之前的 virtual lookup 的时候已经判断了到达这里一定是函数调用
         * 为了效率, 这里不再依次判断, 应该直接跳过, 直到 `(` 之后的 token
         * */
        self.skip_next_n(backtrack_len+1);
        /*
         * 查看下一个有效 token 是否是 `)`
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                self.panic("expect `)` after `(`");
                return;
            }
        };
        let typ = tp.as_ref::<T, CB>().context_token_type();
        let mut param_len = 0;
        match typ {
            TokenType::RightParenthese => {
                /*
                 * xxx() 形式 => 跳过 )
                 * */
                self.skip_next_one();
            },
            _ => {
                // println!("{:?}", tp.as_ref::<T, CB>().context_token_value_ref().token_data_ref());
                self.cb().call_function_param_before_expr(param_len, &mut call_context);
                self.expression_process(&tp, &ExpressContext::new(
                        GrammarParser::<T, CB>::expression_end_param_list));
                self.cb().call_function_param_after_expr(param_len, &mut call_context);
                param_len += 1;
                while let Some(p) = self.skip_white_space_token() {
                    let nt = p.as_ref::<T, CB>();
                    // println!("{:?}", nt.context_token_type());
                    // println!("{:?}", nt.context_token_value_ref().token_data_ref());
                    match nt.context_token_type() {
                        TokenType::Comma => {
                            self.skip_next_one();
                        },
                        TokenType::RightParenthese => {
                            self.skip_next_one();
                            break;
                        },
                        _ => {
                            /*
                            let name_data = name.token_data().expect("should not happend");
                            let func_str = extract_token_data!(name_data, Id);
                            panic!("should not happend, func_str: {}, {:?}"
                                , func_str, nt.context_token_type());
                            */
                            panic!("should not happend, {:?}"
                                , nt.context_token_type());
                        }
                    }
                    match self.skip_white_space_token() {
                        Some(tp) => {
                            self.cb().call_function_param_before_expr(param_len, &mut call_context);
                            self.expression_process(&tp, &ExpressContext::new(
                                    GrammarParser::<T, CB>::expression_end_param_list));
                            self.cb().call_function_param_after_expr(param_len, &mut call_context);
                            param_len += 1;
                        },
                        None => {
                            /*
                             * 没有遇到闭合的 `)`, 就到达了文件 结尾 => 语法错误
                             * */
                            self.panic("expect expression, but found arrive IOEOF");
                        }
                    }
                }
                // println!("param len: {}", param_len);
            }
        }
        if let DescResult::Error(s) = self.cb().call_function(param_len
            , call_context) {
            self.panic(&s);
        };
    }
}

