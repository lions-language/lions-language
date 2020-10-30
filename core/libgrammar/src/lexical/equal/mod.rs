use super::{LexicalParser, CallbackReturnStatus};
use crate::grammar::Grammar;

use crate::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone> LexicalParser<T, CB> {
    fn equal(&mut self) {
        let context = self.build_token_context_without_data(TokenType::Equal);
        self.push_to_token_buffer(equal::EqualToken::new(context));
    }

    fn equal_equal(&mut self) {
        /*
         * 跳过 == 号
         * */
        self.content.skip_next_one();
        let context = self.build_token_context_without_data(TokenType::PlusPlus);
        self.push_to_token_buffer(equal_equal::EqualEqualToken::new(context));
    }

    pub fn equal_process(&mut self) {
        // 跳过 = 号
        self.content.skip_next_one();
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    match c {
                        '=' => {
                            // ==
                            self.equal_equal();
                        },
                        _ => {
                            // =
                            self.equal();
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

mod equal;
mod equal_equal;

