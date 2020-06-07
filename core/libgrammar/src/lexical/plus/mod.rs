use super::{LexicalParser, CallbackReturnStatus};
use libcommon::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    pub fn plus(&mut self) {
        // 跳过 + 号
        self.content.skip_next_one();
        match self.content.lookup_next_one() {
            Some(c) => {
                match c {
                    '+' => {
                        // ++
                    },
                    '=' => {
                        // +=
                    },
                    _ => {
                        let context = self.build_token_context(TokenType::Plus);
                        self.push_to_token_buffer(Box::new(plus::PlusToken::new(context)));
                    }
                }
            },
            None => {
            }
        }
    }
}

mod plus;
mod plus_plus;

