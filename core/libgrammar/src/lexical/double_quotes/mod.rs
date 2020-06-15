use super::{LexicalParser, CallbackReturnStatus};
use libcommon::token::{TokenType, NoFunctionToken};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
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
        self.push_nofunction_token_to_token_buffer(TokenType::Str(content));
    }
}
