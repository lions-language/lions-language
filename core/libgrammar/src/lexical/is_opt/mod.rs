use super::{LexicalParser, CallbackReturnStatus};
use crate::grammar::Grammar;

use crate::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    fn is_opt(&mut self) {
        let context = self.build_token_context_without_data(TokenType::Is);
        self.push_to_token_buffer(is_opt::IsOptToken::new(context));
    }

    pub fn is_process(&mut self) {
        // 跳过 is 操作符
        self.content.skip_next_one();
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    match c {
                        _ => {
                            // is_opt
                            self.is_opt();
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

mod is_opt;

