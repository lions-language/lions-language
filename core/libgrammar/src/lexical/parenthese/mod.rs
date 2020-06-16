use super::{LexicalParser, CallbackReturnStatus};
use libcommon::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    pub fn parenthese_left_process(&mut self) {
    }

    pub fn parenthese_right_process(&mut self) {
    }
}

pub mod left_parenthese;
pub mod right_parenthese;

