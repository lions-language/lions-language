use super::{LexicalParser, CallbackReturnStatus};
use libcommon::token::{TokenType, NoFunctionToken};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    pub fn id(&mut self, start_c: char) {
        let mut s = String::new();
        s.push(start_c);
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    if self.is_id(c) {
                        s.push(c);
                        self.content.skip_next_one();
                    } else {
                        break;
                    }
                },
                None => {
                    match (self.cb)() {
                        CallbackReturnStatus::Continue(content) => {
                            *(&mut self.content) = content;
                            continue;
                        },
                        CallbackReturnStatus::End => {
                            break
                        }
                    }
                }
            }
        }
        match s.as_str() {
            "if" => {
            },
            "else" => {
            },
            _ => {
                let context = self.build_token_context(TokenType::Id(s.to_string()));
                self.push_to_token_buffer(Box::new(NoFunctionToken::new(context)));
            }
        }
    }
}

