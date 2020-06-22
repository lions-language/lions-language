use super::{LexicalParser, CallbackReturnStatus};
use crate::grammar::Grammar;

use crate::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    fn minus(&mut self) {
        let context = self.build_token_context(TokenType::Minus);
        self.push_to_token_buffer(minus::MinusToken::new(context));
    }

    pub fn minus_process(&mut self) {
        // 跳过 + 号
        self.content.skip_next_one();
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    match c {
                        '-' => {
                            // --
                        },
                        '=' => {
                            // -=
                        },
                        _ => {
                            // -
                            self.minus();
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

mod minus;
mod minus_minus;

