use super::{LexicalParser, CallbackReturnStatus};
use crate::grammar::Grammar;

use crate::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone> LexicalParser<T, CB> {
    fn minus(&mut self) {
        let context = self.build_token_context_without_data(TokenType::Minus);
        self.push_to_token_buffer(minus::MinusToken::new(context));
    }

    fn minus_right_angular_brackets(&mut self) {
        let context = self.build_token_context_without_data(TokenType::RightArrow);
        self.push_to_token_buffer(right_arrow::RightArrowToken::new(context));
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
                        '>' => {
                            self.content.skip_next_one();
                            self.minus_right_angular_brackets();
                            break;
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
mod right_arrow;

