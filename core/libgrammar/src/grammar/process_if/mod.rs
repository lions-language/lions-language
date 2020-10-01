use libresult::{DescResult};
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , VarStmtContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn if_process(&mut self) {
    }
}
