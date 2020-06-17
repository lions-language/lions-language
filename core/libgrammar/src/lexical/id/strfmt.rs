use super::super::{LexicalParser, CallbackReturnStatus};
use libcommon::token::{TokenType};
use libcommon::strtool::strcompare::{U8ArrayIsEqual, U8ArrayIsEqualResult};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    fn id_kw_strfmt_process_content(&mut self, start: &[u8], end: &[u8]) {
        // 跳过 "
        self.content.skip_next_one();
        enum Status {
            DoubleQuotes,
            EndSymbol
        }
        enum FindEndStatus {
            Finding,
            NotFound
        }
        let mut content = Vec::new();
        // let mut buffer = Vec::new();
        let mut status = Status::DoubleQuotes;
        let mut start_u8_array_is_equal = U8ArrayIsEqual::new(start);
        let mut end_u8_array_is_equal = U8ArrayIsEqual::new(end);
        let mut find_end_status = FindEndStatus::Finding;
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    match status {
                        Status::DoubleQuotes => {
                            match c {
                                '"' => {
                                    self.content.skip_next_one();
                                    self.push_nofunction_token_to_token_buffer(TokenType::Str(content.clone()));
                                    break;
                                },
                                _ => {
                                    if self.input_str_match_with_u8arrayisequal(&mut start_u8_array_is_equal) {
                                        // match start
                                        status = Status::EndSymbol;
                                        self.push_nofunction_token_to_token_buffer(TokenType::Str(content.clone()));
                                        // 模拟生成 token => ... + (...) + ...
                                        content.clear();
                                        self.push_token_plus();
                                        self.push_token_left_parenthese();
                                    } else {
                                        self.new_line_check(c);
                                        content.push(c as u8);
                                        self.content.skip_next_one();
                                    }
                                }
                            }
                        },
                        Status::EndSymbol => {
                            if self.input_str_match_with_u8arrayisequal(&mut end_u8_array_is_equal) {
                                status = Status::DoubleQuotes;
                                self.push_token_right_parenthese();
                                self.push_token_plus();
                            } else {
                                if c == '"' {
                                    self.panic(&format!("expect {:?}, but arrive \"", &unsafe{String::from_utf8_unchecked(end.to_vec())}));
                                }
                                self.select(c);
                            }
                        }
                    }
                },
                None => {
                    match (self.cb)() {
                        CallbackReturnStatus::Continue(content) => {
                            self.content_assign(content);
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

    fn id_kw_strfmt_process_double_quotes(&mut self) {
        self.id_kw_strfmt_process_content("${".as_bytes(), "}".as_bytes());
    }

    fn id_kw_strfmt_process_left_angle_bracket_find_content(&mut self) -> Vec<u8> {
        // 查找 <> 中的内容
        // 跳过 <
        self.content.skip_next_one();
        let mut vecu8_content = Vec::new();
        // 判断是否是 "
        self.lookup_next_one_with_cb_wrap(|parser, c: char| {
            if c != '"' {
                parser.panic(&format!("expect \" after <, but found {}", c));
            } else {
                /*
                 * double_quotes_process_content 中会跳过第一个 "
                 * */
                vecu8_content = parser.double_quotes_process_content();
            }
        }, |parser| {
            parser.panic("expect \" after <, but arrive IO EOF");
        });
        // 判断是否是 >
        self.lookup_next_one_with_cb_wrap(|parser, c: char| {
            if c != '>' {
                parser.panic(&format!("expect > after \", but found {}", c));
            } else {
                parser.content.skip_next_one();
            }
        }, |parser| {
            parser.panic("expect > after \", buf arrive IO EOF");
        });
        vecu8_content
    }

    fn id_kw_strfmt_process_left_angle_bracket(&mut self) {
        /*
         * 解析 第一个 < 后的内容
         * */
        let start = self.id_kw_strfmt_process_left_angle_bracket_find_content();
        /*
         * 解析 第二个 < 开始的内容
         * */
        self.lookup_next_one_with_cb_wrap(|parser, c: char| {
            if c != '<' {
                parser.panic(&format!("expect < after first <>, but found {}", c));
            }
        }, |parser| {
            parser.panic("expect < after first <>, buf arrive IO EOF");
        });
        let end = self.id_kw_strfmt_process_left_angle_bracket_find_content();
        /*
         * 查找 <><> 后是不是 '"'
         * */
        self.lookup_next_one_with_cb_wrap(|parser, c: char| {
            if c != '"' {
                parser.panic(&format!("expect \" after strfmt<><>, but found {}", c));
            }
        }, |parser| {
            parser.panic("expect \" after strfmt<><>, buf arrive IO EOF");
        });
        self.id_kw_strfmt_process_content(start.as_slice(), end.as_slice());
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

