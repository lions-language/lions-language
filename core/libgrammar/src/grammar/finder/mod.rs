use libresult::DescResult;
use super::{GrammarParser, Grammar
    , FindInterfaceContext
    , FindInterfacePrefixContext
    , FindInterfaceEndContext
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
                let end = FindInterfaceEndContext::new_with_all(id_token.token_value());
                check_desc_result!(self, self.cb().find_interface_end(end, context));
                return;
            }
        };
        let next = tp.as_ref::<T, CB>();
        if let TokenType::ColonColon = next.context_token_type() {
            self.find_interface_after_coloncolon(context);
        } else {
            /*
             * 调用 结束的cb
             * */
            let end = FindInterfaceEndContext::new_with_all(id_token.token_value());
            check_desc_result!(self, self.cb().find_interface_end(end, context));
            return;
        };
    }

    fn find_interface_after_coloncolon(&mut self, context: &mut FindInterfaceContext) {
        /*
         * 跳过 ::
         * */
        self.skip_next_one();
        /*
         * 获取 :: 后的 id
         * */
        let id_token = self.expect_and_take_next_token_unchecked(TokenType::Id);
        let prefix = FindInterfacePrefixContext::new_with_all(id_token.token_value());
        check_desc_result!(self, self.cb().find_interface_prefix(prefix, context));
    }
}

