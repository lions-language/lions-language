use super::super::{LexicalParser, CallbackReturnStatus};
use libcommon::token::{TokenType};
use libcommon::strtool::strcompare::{U8ArrayIsEqual, U8ArrayIsEqualResult};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    fn id_kw_strfmt_process_double_quotes(&mut self) {
        // 跳过 "
        self.content.skip_next_one();
        enum Status {
            DoubleQuotes,
            EndSymbol
        }
        let start = "${";
        let end = "}";
        let mut content = String::new();
        let mut buffer = String::new();
        let mut status = Status::DoubleQuotes;
        let mut start_u8_array_is_equal = U8ArrayIsEqual::new(start.as_bytes());
        let mut end_u8_array_is_equal = U8ArrayIsEqual::new(start.as_bytes());
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    // println!("{}", c);
                    match status {
                        Status::DoubleQuotes => {
                            match c {
                                '"' => {
                                    self.content.skip_next_one();
                                    if content.len() > 0 {
                                        self.push_nofunction_token_to_token_buffer(TokenType::Str(content.clone()));
                                    }
                                    break;
                                },
                                _ => {
                                    match start_u8_array_is_equal.dynamic_match(c) {
                                        U8ArrayIsEqualResult::Match(length) => {
                                            // 匹配了 起始串
                                            status = Status::EndSymbol;
                                            content.clear();
                                            println!("1 => {}", c);
                                            self.content.backtrack_n(length);
                                            self.content.skip_next_n(length);
                                            self.push_nofunction_token_to_token_buffer(TokenType::Str(content.clone()));
                                        },
                                        U8ArrayIsEqualResult::NoMatchArriveLength(length) => {
                                            content.push_str(&buffer);
                                            buffer.clear();
                                            println!("2 => {}", c);
                                            self.content.backtrack_n(length);
                                            self.content.skip_next_n(length);
                                        },
                                        U8ArrayIsEqualResult::NoMatchLessLength(length) => {
                                            buffer.push(c);
                                            println!("3 => {}", c);
                                            self.content.virtual_skip_next_one();
                                        },
                                        U8ArrayIsEqualResult::Continue => {
                                            buffer.push(c);
                                            println!("4 => {}", c);
                                            self.content.virtual_skip_next_one();
                                        }
                                    }
                                    /*
                                    if start_u8_array_is_equal.dynamic_match(c) {
                                        // 匹配了 ${
                                        status = Status::EndSymbol;
                                        content.clear();
                                        self.content.skip_next_n(start.len());
                                        self.push_nofunction_token_to_token_buffer(TokenType::Str(content.clone()));
                                    } else {
                                        // 没有匹配 起始串 => 普通字符串
                                        content.push(c);
                                        self.content.skip_next_one();
                                    }
                                    */
                                }
                            }
                        },
                        Status::EndSymbol => {
                            match end_u8_array_is_equal.dynamic_match(c) {
                                U8ArrayIsEqualResult::Match(length) => {
                                    // 匹配了终结串
                                    status = Status::DoubleQuotes;
                                    self.content.skip_next_n(length);
                                },
                                _ => {
                                    self.select(c);
                                }
                            }
                            /*
                            if end_u8_array_is_equal.dynamic_match(c) {
                                // 匹配了终结串
                                status = Status::DoubleQuotes;
                            } else {
                                self.select(c);
                            }
                            */
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
                            self.panic("expect \", but arrive IO EOF");
                        }
                    }
                }
            }
        }
    }

    fn id_kw_strfmt_process_left_angle_bracket(&mut self) {
        // 跳过 <
        self.content.skip_next_one();
    }

    pub fn id_kw_strfmt_process(&mut self) {
        // strfmt""
        // strfmt<><>""
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    match c {
                        '"' => {
                            self.id_kw_strfmt_process_double_quotes();
                            break;
                        },
                        '<' => {
                            self.id_kw_strfmt_process_left_angle_bracket();
                            break;
                        },
                        _ => {
                            self.panic(&format!("expect \" or < after strfmt, but found {}", c));
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
                            self.panic("expect \" or < after strfmt, but meet IO EOF");
                        }
                    }
                }
            }
        }
    }
}

