use libcommon::token;

/// store Vec<u8> struct
pub struct VecU8(Vec<u8>);
impl VecU8 {
    fn lookup_next_n(&mut self, n: usize) -> Option<char> {
        None
    }
    
    fn lookup_next_one(&mut self) -> Option<char> {
        None
    }

    fn from_vec_u8(v: Vec<u8>) -> Self {
        Self(v)
    }

    fn new() -> Self {
        Self(Vec::new())
    }
}

impl Iterator for VecU8 {
    type Item = char;
    fn next(&mut self) -> Option<char> {
        None
    }
}

/// lexical parser
pub enum CallbackReturnStatus {
    Continue(VecU8),
    End
}

pub type TokenVecItem = Box<dyn token::Token>;

pub struct LexicalParser<T: FnMut() -> CallbackReturnStatus> {
    // content: std::str::Chars<'a>,
    // cb: Callback<'a>
    content: VecU8,
    cb: T,
    tokens_buffer: Vec<TokenVecItem>
}

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    fn parser(&self) {
    }

    /*
    // 为什么下面的是错误的呢 ?
    // 因为 返回值是 self.tokens_buffer的引用
    // 查看下n个token
    fn lookup_next_n(&mut self, n: usize) -> Option<&TokenVecItem> {
        let tokens_len = self.tokens_buffer.len();
        if tokens_len == 0 {
            /*
            ** 缓存中没有数据 => 从 content 中读取
            */
        } else {
            /*
            * 缓存中存在数据
            */
            match self.tokens_buffer.get(n - 1) {
                Some(token) => {
                    /*
                    * 缓存中的token满足n个
                    */
                    return Some(token);
                },
                None => {
                    /*
                    * 缓存中的token不足n个
                    */
                }
            }
        }
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    self.select(c as char);
                    return None;
                },
                None => {
                    match (self.cb)() {
                        CallbackReturnStatus::Continue(content) => {
                            /*
                             * 回调的结果是继续 => 当前解析的文件还存在待解析的字符串
                             * 1. 使用 回调的content, 修改 self.content
                             * 2. 下一次的时候就是用最新的 content 循环
                             */
                            *(&mut self.content) = content;
                            continue;
                        },
                        CallbackReturnStatus::End(content) => {
                            // 不存在待解析的字符串 (读到了文件的最尾部)
                            /*
                             * 不存在待解析的字符串
                             * 1. 判断已经获取到的token是否达到了n
                             */
                             return None;
                        }
                    }
                }
            }
        }
    }
    */

    fn lookup_next_n(&mut self, n: usize) -> Option<&TokenVecItem> {
        match self.lookup_next_n_index(n) {
            Some(index) => {
                return self.tokens_buffer.get(index);
            },
            None => {
                return None;
            }
        }
    }

    fn lookup_next_n_index(&mut self, n: usize) -> Option<usize> {
        loop {
            let tokens_len = self.tokens_buffer.len();
            if tokens_len == 0 {
                /*
                ** 缓存中没有数据 => 从 content 中读取
                */
            } else {
                /*
                * 缓存中存在数据
                */
                if tokens_len >= n {
                    /*
                    * 缓存中的token满足n个
                    */
                    return Some(n - 1);
                } else {
                    /*
                    * 缓存中的token不足n个 => 从 content 中读取
                    */
                }
            }

            match self.content.lookup_next_one() {
                Some(c) => {
                    self.select(c as char);
                },
                None => {
                    match (self.cb)() {
                        CallbackReturnStatus::Continue(content) => {
                            /*
                             * 回调的结果是继续 => 当前解析的文件还存在待解析的字符串
                             * 1. 使用 回调的content, 修改 self.content
                             * 2. 下一次的时候就是用最新的 content 循环
                             */
                            *(&mut self.content) = content;
                            continue;
                        },
                        CallbackReturnStatus::End => {
                            /*
                             * 不存在待解析的字符串 (读到了文件的最尾部)
                             */
                             return None;
                        }
                    }
                }
            }
        }
    }

    fn push_to_token_buffer(&mut self, item: TokenVecItem) {
        self.tokens_buffer.push(item);
    }

    fn lookup_next_one(&mut self) -> Option<TokenVecItem> {
        None
    }

    fn lookup_next_n_with_vec(&mut self) {
    }

    fn select(&mut self, c: char) {
        match c {
            '+' => self.start_with_plus(),
            _ => {}
        }
    }
}

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    pub fn new(cb: T) -> LexicalParser<T> {
        let parser = LexicalParser{
            content: VecU8::new(),
            cb: cb,
            tokens_buffer: Vec::new()
        };
        parser
    }
}

mod plus;

mod test {
    use super::*;

    #[test]
    fn leical_parser() {
        let mut len = 0;
        let obj = LexicalParser::new(&mut || -> CallbackReturnStatus {
            len += 1;
            if len == 2 {
                return CallbackReturnStatus::End;
            } else {
                return CallbackReturnStatus::Continue(VecU8::from_vec_u8(String::from("a = ").as_bytes().to_vec()));
            }
        });
    }
}
