use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};
use string::StringToken;
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    pub fn double_quotes_process_content(&mut self) -> Vec<u8> {
        // 跳过双引号
        self.content.skip_next_one();
        let mut vecu8_content = Vec::new();
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    match c {
                        '"' => {
                            self.content.skip_next_one();
                            break;
                        },
                        '\\' => {
                            // 遇到了转义字符
                            match self.escape_change() {
                                Some(ch) => {
                                    vecu8_content.push(ch as u8);
                                },
                                None => {
                                    vecu8_content.push(c as u8);
                                }
                            }
                        },
                        _ => {
                            self.new_line_check(c);
                            // 添加到字符串中
                            vecu8_content.push(c as u8);
                            self.content.skip_next_one();
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
                            // 到达 IO尾部, 但是没有遇到结束的 双引号 (没有配对)
                            self.panic("expect double quote, but arrive EOF");
                        }
                    }
                }
            }
        }
        vecu8_content
    }

    pub fn double_quotes_process(&mut self) {
        let content = self.double_quotes_process_content();
        self.push_string_token_to_token_buffer(content);
    }

    pub fn push_string_token_to_token_buffer(&mut self, content: Vec<u8>) {
        let context = self.build_token_context(TokenType::Str(content));
        self.push_to_token_buffer(Box::new(StringToken::new(context)));
    }
}

pub mod string;
