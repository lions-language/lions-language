use super::{LexicalParser, CallbackReturnStatus};
use libcommon::token::{TokenType, NoFunctionToken};
use crate::lexical::plus::plus;
use crate::lexical::parenthese::left_parenthese;
use crate::lexical::parenthese::right_parenthese;

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    fn escape_change_select(&mut self, c: char) -> Option<char> {
        let mut r = None;
        match c {
            't' => {
                r = Some('\t');
            },
            'r' => { r = Some('\r');
            },
            'n' => {
                r = Some('\n');
            },
            '"'|'\\' => {
                // \" \\
                r = Some(c);
            },
            _ => {
            }
        }
        if let Some(_) = r {
            self.content.skip_next_one();
        }
        r
    }

    pub fn escape_change(&mut self) -> Option<char> {
        // 跳过 \ 符号
        self.content.skip_next_one();
        match self.content.lookup_next_one() {
            Some(c) => {
                return self.escape_change_select(c);
            },
            None => {
                match (self.cb)() {
                    CallbackReturnStatus::Continue(content) => {
                        *(&mut self.content) = content;
                        match self.content.lookup_next_one(){
                            Some(c) => {
                                return self.escape_change_select(c);
                            },
                            None => {
                                // 不可能发生的, 除非是 cb 返回的 content 是空的
                                panic!("should not happend");
                            }
                        }
                    },
                    CallbackReturnStatus::End => {
                        // 到了 IO的结尾, 还是没有找到 \ 后面的字符 => 返回没有没有找到
                        return None
                    }
                }
            }
        }
    }

    // 检测是否是新的一行 (用于字符串中的换行)
    pub fn new_line_check(&mut self, c: char) -> bool {
        match c {
            '\r' => {
                match self.content.lookup_next_one() {
                    Some(ch) => {
                        if ch == '\n' {
                            self.content.virtual_skip_next_one();
                            self.content.backtrack_n(2);
                        } else {
                            self.content.backtrack_n(1);
                        }
                        self.line += 1;
                    },
                    None => {
                        match (self.cb)() {
                            CallbackReturnStatus::Continue(content) => {
                                self.content_assign(content);
                                match self.content.lookup_next_one() {
                                    Some(ch) => {
                                        if ch == '\n' {
                                            self.content.virtual_skip_next_one();
                                            self.content.backtrack_n(2);
                                        } else {
                                            self.content.backtrack_n(1);
                                        }
                                        self.line += 1;
                                    },
                                    None => {
                                        panic!("should not happend");
                                    }
                                }
                            },
                            CallbackReturnStatus::End => {
                                self.content.backtrack_n(1);
                                self.line += 1;
                            }
                        }
                    }
                }
            },
            '\n' => {
                self.line += 1;
            },
            _ => {
                return false;
            }
        }
        true
    }

    pub fn push_token_plus(&mut self) {
        let context = self.build_token_context(TokenType::Plus);
        self.push_to_token_buffer(Box::new(plus::PlusToken::new(context)));
    }

    pub fn push_token_left_parenthese(&mut self) {
        let context = self.build_token_context(TokenType::LeftParenthese);
        self.push_to_token_buffer(Box::new(left_parenthese::LeftParentheseToken::new(context)));
    }

    pub fn push_token_right_parenthese(&mut self) {
        let context = self.build_token_context(TokenType::RightParenthese);
        self.push_to_token_buffer(Box::new(right_parenthese::RightParentheseToken::new(context)));
    }

    pub fn push_token_annotate(&mut self, content: Vec<u8>) {
        self.push_nofunction_token_to_token_buffer(TokenType::Annotate(content));
    }

    pub fn push_token_div(&mut self) {
    }
}

pub mod strtool;
pub mod content_wrap;
