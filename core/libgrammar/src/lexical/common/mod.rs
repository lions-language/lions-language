use super::{LexicalParser, CallbackReturnStatus};
use libcommon::token::{TokenType, NoFunctionToken};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    fn escape_change_select(&mut self, c: char) -> Option<char> {
        let mut r = None;
        match c {
            't' => {
                r = Some('\t');
            },
            'r' => {
                r = Some('\r');
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
}
