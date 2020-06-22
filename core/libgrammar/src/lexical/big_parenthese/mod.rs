use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    pub fn big_parenthese_left_process(&mut self) {
        /*
         * 跳过 {
         * */
        self.content.skip_next_one();
        let context = self.build_token_context(TokenType::LeftBigParenthese);
        self.push_to_token_buffer(left_big_parenthese::LeftBigParentheseToken::new(context));
    }

    pub fn big_parenthese_right_process(&mut self) {
        /*
         * 跳过 }
         * */
        self.content.skip_next_one();
        let context = self.build_token_context(TokenType::RightBigParenthese);
        self.push_to_token_buffer(right_big_parenthese::RightBigParentheseToken::new(context));
    }
}

pub mod left_big_parenthese;
pub mod right_big_parenthese;

