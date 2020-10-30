use super::super::{LexicalParser, CallbackReturnStatus};
use libcommon::strtool::strcompare::{U8ArrayIsEqual};
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    fn id_kw_strfmt_process_next_is_strend(&mut self) -> bool {
        /*
         * 检测下一个字符是否是字符串结束符
         * */
        let mut is_strend = false;
        self.lookup_next_one_with_cb_wrap(|_, c| {
            if c == '"' {
                is_strend = true;
            }
        }, |parser| {
            /*
             * next 要么是 `"`, 要么不是 `"`, 但是一定应该存在字符
             * */
            parser.panic("expect `\"` or other char, but arrive EOF");
        });
        return is_strend;
    }

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
        // let mut content = Vec::new();
        let mut content = String::new();
        let mut status = Status::DoubleQuotes;
        let mut start_u8_array_is_equal = U8ArrayIsEqual::new(start);
        let mut end_u8_array_is_equal = U8ArrayIsEqual::new(end);
        let mut find_end_status = FindEndStatus::Finding;
        let mut prefix_is_exist_parenthese = false;
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    match status {
                        Status::DoubleQuotes => {
                            match c {
                                '"' => {
                                    self.content.skip_next_one();
                                    // self.push_string_token_to_token_buffer(content.clone());
                                    // if !self.id_kw_strfmt_process_next_is_strend() {
                                    if content.len() > 0 {
                                        // println!("{}", content);
                                        self.push_utf8_token_to_token_buffer(content.clone());
                                    }
                                    break;
                                },
                                _ => {
                                    if self.input_str_match_with_u8arrayisequal(
                                        /*
                                         * 找到 开始符号 => 进入查找 结束符号 模式
                                         * */
                                        &mut start_u8_array_is_equal) {
                                        // match start
                                        status = Status::EndSymbol;
                                        // self.push_string_token_to_token_buffer(content.clone());
                                        // println!("{}", content);
                                        if !content.is_empty() {
                                            self.push_utf8_token_to_token_buffer(content.clone());
                                            self.push_token_plus();
                                            self.push_token_left_parenthese();
                                            prefix_is_exist_parenthese = true;
                                        } else {
                                            prefix_is_exist_parenthese = false;
                                        }
                                        // 模拟生成 token => ... + (...) + ...
                                        content.clear();
                                    } else {
                                        self.new_line_check(c);
                                        // content.push(c as u8);
                                        content.push(c);
                                        self.content.skip_next_one();
                                    }
                                }
                            }
                        },
                        Status::EndSymbol => {
                            /*
                             * 查找 结束符号 模式
                             * */
                            if self.input_str_match_with_u8arrayisequal(&mut end_u8_array_is_equal) {
                                status = Status::DoubleQuotes;
                                if prefix_is_exist_parenthese {
                                    self.push_token_right_parenthese();
                                }
                                if !self.id_kw_strfmt_process_next_is_strend() {
                                    /*
                                     * 如果下一个字符不是 `"`, 说明后面还有字符串,
                                     * 那么就需要添加 `+` token
                                     * */
                                    self.push_token_plus();
                                }
                            } else {
                                if c == '"' {
                                    self.panic(&format!("expect {:?}, but arrive \""
                                        , &unsafe{String::from_utf8_unchecked(end.to_vec())}));
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
                vecu8_content = parser.double_quotes_process_vecu8();
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

