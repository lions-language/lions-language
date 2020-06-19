use super::{GrammarParser};
use crate::lexical::{CallbackReturnStatus, TokenPointer};

impl<FT: FnMut() -> CallbackReturnStatus> GrammarParser<FT> {
    pub fn expression_process(&mut self, token: &TokenPointer) {
    }

    fn expression(&mut self, operator_bp: u8) {
    }
}
