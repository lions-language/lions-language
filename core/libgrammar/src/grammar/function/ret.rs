use libresult::DescResult;
use super::{GrammarParser, Grammar};
use crate::grammar::{FunctionDefineReturnContext
    , FunctionDefineContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone> GrammarParser<'a, T, CB> {
    pub fn function_parse_return(&mut self, define_context: &mut FunctionDefineContext) {
        /*
         * 参数解析完成之后, 被调用
         *  参数后:
         *      `{`
         *      `->`
         *      other
         * */
        let tp = self.expect_next_token(|_, _| {
        }, "`{` / `->`");
        let token = tp.expect("should not happend").as_ref::<T, CB>();
        let tt = token.context_token_type();
        match tt {
            TokenType::LeftBigParenthese => {
                /*
                 * 无返回值
                 * */
                return;
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
            }
        }
        let (typ_attr, lengthen_attr, type_token) = self.typ_parse();
        check_desc_result!(self, self.cb().function_define_return(FunctionDefineReturnContext::new_with_all(
            typ_attr, lengthen_attr, type_token
        ), define_context));
    }
}

