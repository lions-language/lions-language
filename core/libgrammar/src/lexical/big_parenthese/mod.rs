use super::{LexicalParser, CallbackReturnStatus};
use libcommon::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    pub fn big_parenthese_left_process(&mut self) {
        /*
         * 跳过 {
         * */
        self.content.skip_next_one();
        let context = self.build_token_context(TokenType::LeftBigParenthese);
        self.push_to_token_buffer(Box::new(left_big_parenthese::LeftBigParentheseToken::new(context)));
    }

    pub fn big_parenthese_right_process(&mut self) {
        /*
         * 跳过 }
         * */
        self.content.skip_next_one();
        let context = self.build_token_context(TokenType::RightBigParenthese);
        self.push_to_token_buffer(Box::new(right_big_parenthese::RightBigParentheseToken::new(context)));
    }
}

pub mod left_big_parenthese;
pub mod right_big_parenthese;

