use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    pub fn backslash_r(&mut self) {
        // 跳过 \r 号
        self.content.skip_next_one();
        match self.content.lookup_next_one() {
            Some(c) => {
                if c == '\n' {
                    // \r后面是 \n => 跳过 \n
                    self.content.skip_next_one();
                } else {
                    // \r后面不是 \n => 不需要跳过任何字符
                }
            },
            None => {
                match (self.cb)() {
                    CallbackReturnStatus::Continue(content) => {
                        *(&mut self.content) = content;
                        // 更新后仍然有字符 => 判断下一个是否是 \n, 如果是就跳过
                        match self.content.lookup_next_one() {
                            Some(c) => {
                                if (c == '\n') {
                                    self.content.skip_next_one();
                                }
                            },
                            None => {
                                // 更新 content 后, 还是没有next one => 不应该发生的
                                panic!("shoud not happend, maybe cb error");
                            }
                        }
                    },
                    CallbackReturnStatus::End => {
                        // 文件尾部
                        // \r后面是文件结束
                    }
                }
            }
        }
        // 不管是 \r 还是 \r\n, 都记为 NewLine
        self.push_token_newline();
        self.add_one_line();
    }
}

