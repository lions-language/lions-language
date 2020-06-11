use super::number::{NumberPrefix};
use super::{LexicalParser, CallbackReturnStatus};

use libcommon::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    fn minus(&mut self) {
        // 判断 - 后面是否是数值
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    if self.is_number_start(c) {
                        // + 后面是 数值
                        self.number(c, &Some(NumberPrefix::Minus));
                        return;
                    }
                    // - 后面不是 数值 => 生成 Minus token
                    let context = self.build_token_context(TokenType::Minus);
                    self.push_to_token_buffer(Box::new(minus::MinusToken::new(context)));
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

