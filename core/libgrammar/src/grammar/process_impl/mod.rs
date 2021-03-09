use libresult::{DescResult};
use super::{GrammarParser, Grammar
    , ImplStmtContext, DescContext};
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
        self.find_interface();
        TokenMethodResult::End
    }
}
