use libresult::{DescResult};
use crate::grammar::{GrammarParser, Grammar
    , ImplStmtContext, DescContext
    , FindInterfaceContext};
use crate::token::{TokenData, TokenMethodResult};
use crate::lexical::{CallbackReturnStatus};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn impl_process(&mut self, desc_context: DescContext) -> TokenMethodResult {
        /*
         * 跳过 impl 关键字
         * */
        self.skip_next_one();
        /*
         * 解析后面的 interface
         * */
        let mut find_interface_context = FindInterfaceContext::default();
        self.find_interface(&mut find_interface_context);
        TokenMethodResult::End
    }
}
