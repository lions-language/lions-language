use libresult::{DescResult};
use super::{GrammarParser, Grammar
    , ImplStmtContext};
use crate::token::{TokenData};
use crate::lexical::{CallbackReturnStatus};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn impl_process(&mut self) {
        /*
         * 跳过 impl 关键字
         * */
        self.skip_next_one();
        check_desc_result!(self, self.cb().impl_stmt(
            ImplStmtContext::new_with_all()));
    }
}
