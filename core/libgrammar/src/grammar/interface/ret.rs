use libresult::DescResult;
use super::{GrammarParser, Grammar};
use crate::grammar::{FunctionDefineReturnContext
    , FunctionStatementContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn interface_function_parse_return(&mut self
        , define_context: &mut FunctionStatementContext) -> bool {
        /*
         * 参数解析完成之后, 被调用
         *  参数后:
         *      `{`
         *      `->`
         *      other
         * 返回值: 如果是true, 表示遇到 interface 结尾的 }, 如果是 false, 表示没有结束, 继续解析
         * */
        let tp = self.expect_next_token(|_, _| {
        }, "new line / `->`");
        let token = tp.expect("should not happend").as_ref::<T, CB>();
        let tt = token.context_token_type();
        match tt {
            TokenType::NewLine
                | TokenType::Semicolon => {
                /*
                 * 无返回值
                 * */
                self.skip_next_one();
                /*
                 * 判断有没有到达 interface block 的结尾
                 * */
                let tp = self.expect_next_token(|_, _| {
                }, "`}` / fn");
                let token = tp.expect("should not happend").as_ref::<T, CB>();
                let tt = token.context_token_type();
                match tt {
                    TokenType::RightBigParenthese => {
                        self.skip_next_one();
                        return true;
                    },
                    _ => {}
                }
                return false;
            },
            TokenType::RightBigParenthese => {
                self.skip_next_one();
                return true;
            },
            TokenType::RightArrow => {
                /*
                 * -> 返回值
                 * 跳过 ->
                 * */
                self.skip_next_one();
            }
            _ => {
                /*
                 * 既不是 { 也不是 ->, 交给 类型处理函数
                 * (golang 风格的返回值定义)
                 * */
                self.panic(&format!("expect new_line / ->, but meet: {:?}"
                        , token.context_token_type()));
                panic!();
            }
        }
        let (typ_attr, lengthen_attr, type_token) = self.typ_parse();
        /*
        check_desc_result!(self, self.cb().interface_function_define_return(
                FunctionDefineReturnContext::new_with_all(typ_attr, lengthen_attr, type_token)
                , define_context));
        */
        false
    }
}

