use super::{LexicalParser};
use libresult::{DescResult};
use libcommon::strtool::strcompare::{U8ArrayIsEqual
    , U8ArrayIsEqualResult};
use libcommon::ptr::{RefPtr};
use libcommon::consts;
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , ReturnStmtContext, ImportStmtContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn relmod_process(&mut self) {
        /*
         * 跳过 relmod 关键字
         * */
        self.skip_next_one();
    }
}
