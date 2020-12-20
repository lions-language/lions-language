use libcommon::ptr::{HeapPtr};
use libcommon::address::{FunctionAddrValue};
use libresult::{DescResult};
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , VarStmtContext};
use crate::grammar::{BlockDefineContext, IfStmtContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn while_process(&mut self) {
        /*
         * 跳过 while 关键字
         * */
        self.skip_next_one();
    }
}
