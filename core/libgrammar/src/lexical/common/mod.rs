use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType, TokenData, NoOperateToken};
use crate::lexical::plus::plus;
use crate::lexical::parenthese::left_parenthese;
use crate::lexical::parenthese::right_parenthese;
use crate::lexical::whitespace::newline;
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
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
                self.content.virtual_skip_next_one();
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

    /*
     * 在这一行中, 向后查看下一个字符, 直到不是空格为止
     * */
    pub fn lookup_next_one_not_spacewhite_in_this_line(&mut self) -> Option<char> {
        let mut is = true;
        let mut ret = None;
        while is {
            self.lookup_next_one_with_cb_wrap(|parser, c| {
                match c {
                    ' ' => {
                        parser.content_skip_next_one();
                    },
                    '\r'|'\n' => {
                        is = false;
                    },
                    _ => {
                        ret = Some(c);
                        is = false;
                    }
                }
            }, |_| {
            });
        }
        ret
    }

    pub fn push_token_plus(&mut self) {
        let context = self.build_token_context_without_data(TokenType::Plus);
        self.push_to_token_buffer(plus::PlusToken::new(context));
    }

    pub fn push_token_left_parenthese(&mut self) {
        let context = self.build_token_context_without_data(TokenType::LeftParenthese);
        self.push_to_token_buffer(left_parenthese::LeftParentheseToken::new(context));
    }

    pub fn push_token_right_parenthese(&mut self) {
        let context = self.build_token_context_without_data(TokenType::RightParenthese);
        self.push_to_token_buffer(right_parenthese::RightParentheseToken::new(context));
    }

    pub fn push_token_newline(&mut self) {
        let context = self.build_token_context_without_data(TokenType::NewLine);
        self.push_to_token_buffer(newline::NewLineToken::new(context));
    }

    pub fn push_nooperate_nodata_token_to_token_buffer(&mut self, token_type: TokenType) {
        let context = self.build_token_context_without_data(token_type);
        self.push_to_token_buffer(NoOperateToken::new(context));
    }

    pub fn push_token_div(&mut self) {
    }
}

pub mod strtool;
pub mod content_wrap;
