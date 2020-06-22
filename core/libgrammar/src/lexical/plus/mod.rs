use super::{LexicalParser, CallbackReturnStatus};
use crate::grammar::Grammar;

use crate::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    fn plus(&mut self) {
        let context = self.build_token_context(TokenType::Plus);
        self.push_to_token_buffer(plus::PlusToken::new(context));
    }

    pub fn plus_process(&mut self) {
        // 跳过 + 号
        self.content.skip_next_one();
        loop {
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
                            // +
                            self.plus();
                            break;
                        }
                    }
                },
                None => {
                    match (self.cb)() {
                        CallbackReturnStatus::Continue(content) => {
                            *(&mut self.content) = content;
                            continue;
                        },
                        CallbackReturnStatus::End => {
                            break;
                        }
                    }
                }
            }
        }
    }
}

pub mod plus;
mod plus_plus;

