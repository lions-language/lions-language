use super::{LexicalParser, CallbackReturnStatus};
use crate::grammar::Grammar;

use crate::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    pub fn left_angular_bracket(&mut self) {
        let context = self.build_token_context_without_data(TokenType::LeftAngularBracket);
        self.push_to_token_buffer(left_angular_bracket::LeftAngularBracketToken::new(context));
    }

    pub fn left_angular_bracket_equal(&mut self) {
        /*=
         * 跳过 <
         * */
        self.content.skip_next_one();
        let context = self.build_token_context_without_data(TokenType::LeftAngularBracketEqual);
        self.push_to_token_buffer(
            left_angular_bracket_equal::LeftAngularBracketEqualToken::new(context));
    }

    pub fn angular_brackets_left_process(&mut self) {
        // 跳过 < 号
        self.content.skip_next_one();
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    match c {
                        '=' => {
                            // <=
                            self.left_angular_bracket_equal();
                        },
                        _ => {
                            // <
                            self.left_angular_bracket();
                        }
                    }
                    return;
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

mod left_angular_bracket;
mod left_angular_bracket_equal;

