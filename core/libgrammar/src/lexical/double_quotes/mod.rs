use super::{LexicalParser, CallbackReturnStatus};
use libcommon::token::{TokenType, NoFunctionToken};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    pub fn double_quotes_process(&mut self) {
        // 跳过双引号
        self.content.skip_next_one();
        let mut str_content = String::new();
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
                                    str_content.push(ch);
                                },
                                None => {
                                    str_content.push(c);
                                }
                            }
                        },
                        _ => {
                            // 添加到字符串中
                            str_content.push(c);
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
        self.push_nofunction_token_to_token_buffer(TokenType::Str(str_content));
    }
}
