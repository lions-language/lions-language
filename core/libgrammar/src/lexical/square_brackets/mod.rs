use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone> LexicalParser<T, CB> {
    pub fn square_brackets_left_process(&mut self) {
        /*
         * 跳过 {
         * */
        self.content.skip_next_one();
        let context = self.build_token_context_without_data(TokenType::LeftSquareBrackets);
        self.push_to_token_buffer(left_square_brackets::LeftSquareBracketsToken::new(context));
    }

    pub fn square_brackets_right_process(&mut self) {
        self.content.skip_next_one();
        let context = self.build_token_context_without_data(TokenType::RightSquareBrackets);
        self.push_to_token_buffer(right_square_brackets::RightSquareBracketsToken::new(context));
    }
}

mod left_square_brackets;
mod right_square_brackets;

