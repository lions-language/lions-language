use libresult::DescResult;
use super::{GrammarParser, Grammar};
use crate::grammar::{FirstStmtContext};
use crate::lexical::{CallbackReturnStatus};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn first_stmt_process(&mut self) {
        check_desc_result!(self, self.cb().first_stmt(FirstStmtContext::new_with_all()));
    }
}

