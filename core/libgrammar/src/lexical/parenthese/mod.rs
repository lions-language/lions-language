use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    pub fn parenthese_left_process(&mut self) {
        /*
         * 跳过 (
         * */
        self.content.skip_next_one();
        self.push_token_left_parenthese();
    }

    pub fn parenthese_right_process(&mut self) {
        /*
         * 跳过 )
         * */
        self.content.skip_next_one();
        self.push_token_right_parenthese();
    }
}

pub mod left_parenthese;
pub mod right_parenthese;

