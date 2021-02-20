use libresult::DescResult;
use super::{GrammarParser, Grammar
    , FindInterfaceContext
    , DescContext};
use crate::lexical::{CallbackReturnStatus, TokenPointer};
use crate::token::{TokenType, TokenData};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    /*
     * 查找接口 (包括 其他包中的)
     * */
    pub fn find_interface(&mut self, context: &mut FindInterfaceContext) {
        /*
         * 判断下一个token是否是 id
         * */
        let id_token = self.expect_and_take_next_token_unchecked(TokenType::Id);
        /*
         * 判断后面是不是 ::
         * */
        let tp = match self.lookup_next_one_ptr() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * 不存在 :: => 调用结束的cb
                 * */
                check_desc_result!(self, self.cb().find_interface_end(context));
                return;
            }
        };
        let next = tp.as_ref::<T, CB>();
        if let TokenType::ColonColon = next.context_token_type() {
            /*
             * 调用 中间 的cb
             * */
            self.find_interface(context);
            check_desc_result!(self, self.cb().find_interface_mid(context));
        } else {
            /*
             * 调用 结束的cb
             * */
            check_desc_result!(self, self.cb().find_interface_end(context));
            return;
        };
    }
}

