use libresult::{DescResult};
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , ReturnStmtContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn import_process(&mut self) {
        /*
         * 跳过 import 关键字
         * */
        self.skip_next_one();
    }
}
