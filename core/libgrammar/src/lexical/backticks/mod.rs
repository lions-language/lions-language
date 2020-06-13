use super::{LexicalParser, CallbackReturnStatus};
use libcommon::token::{TokenType, NoFunctionToken};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    pub fn backticks_process(&mut self) {
        self.content.skip_next_one();
    }
}
