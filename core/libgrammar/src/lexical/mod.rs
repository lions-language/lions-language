use libcommon::token::{self, TokenContext, TokenType, NoFunctionToken};

/// store Vec<u8> struct
#[derive(Debug)]
pub struct VecU8{
    v: Vec<u8>
}

impl VecU8 {
    fn skip_next_n(&mut self, n: usize) {
        // 跳过n个字符
        if n > self.v.len() {
            panic!("skip next must be called after lookup");
        }
        for _ in 0..n {
            self.v.remove(0);
        }
    }

    fn skip_next_one(&mut self) {
        self.skip_next_n(1);
    }

    fn lookup_next_n(&self, n: usize) -> Option<char> {
        if n == 0 {
            panic!("n > 0");
        }
        let index = n - 1;
        if (self.v.len() > 0) && (index > self.v.len() - 1) {
            // 没有可以获取的值了
            return None;
        } else {
            if self.v.len() == 0 {
                return None;
            }
            return Some(self.v[index] as char)
        }
    }
    
    fn lookup_next_one(&self) -> Option<char> {
        return self.lookup_next_n(1);
    }

    fn from_vec_u8(v: Vec<u8>) -> Self {
        Self{
            v: v
        }
    }

    fn new() -> Self {
        Self{
            v: Vec::new()
        }
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
    file: String,
    line: u64,
    col: u64,
    content: VecU8,
    cb: T,
    tokens_buffer: Vec<TokenVecItem>
}

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    /*
    fn lookup_next_n(&mut self, n: usize) -> Option<&TokenVecItem> {
        let tokens_len = self.tokens_buffer.len();
        if tokens_len == 0 {
        } else {
            match self.tokens_buffer.get(n - 1) {
                Some(token) => {
                    return Some(token);
                },
                None => {
                }
            }
        }
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    self.select('a');
                    return None;
                },
                None => {
                    match (self.cb)() {
                        CallbackReturnStatus::Continue(content) => {
                            *(&mut self.content) = content;
                            continue;
                        },
                        CallbackReturnStatus::End => {
                             return None;
                        }
                    }
                }
            }
        }
    }
    */

    fn skip_next_n(&mut self, n: usize) {
        // 在 lookup 之后调用
        // 也就是说, 此时缓存中一定存在足够skip n个token的长度
        if self.tokens_buffer.len() < n {
            // 缓存中不存在足够的token => 调用顺序有误 => 拋异常
            panic!("skip next n must be called after lookup");
        }
        for _ in 0..n {
            self.tokens_buffer.remove(0);
        }
    }

    fn skip_next_one(&mut self) {
        self.skip_next_n(1);
    }

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

    fn push_nofunction_token_to_token_buffer(&mut self, token_type: TokenType) {
        let context = self.build_token_context(token_type);
        self.push_to_token_buffer(Box::new(NoFunctionToken::new(context)));
    }

    fn lookup_next_one(&mut self) -> Option<TokenVecItem> {
        None
    }

    fn lookup_next_n_with_vec(&mut self) {
    }

    fn is_id_start(&self, c: char) -> bool {
        if (c == '_') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
            return true;
        }
        false
    }

    // 除第一位外, 字符是否属于ID
    fn is_id(&self, c: char) -> bool {
        if (c == '_') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
            return true;
        }
        false
    }

    // 是否是数字
    fn is_number(&self, c: char) -> bool {
        if c >= '0' && c <= '9' {
            return true;
        }
        false
    }

    fn select(&mut self, c: char) {
        // 此时的 content 位置是 c (没有提取出来)
        match c {
            '\r' => self.backslash_r(),
            '\n' => self.backslash_n(),
            '+' => self.plus(),
            _ => {
                if self.is_id_start(c) {
                    self.id(c);
                } else if self.is_number(c) {
                    self.number(c, &None);
                }
            }
        }
    }

    fn build_token_context(&self, token_type: TokenType) -> TokenContext {
        TokenContext {
            line: self.line,
            col: self.col,
            token_type: token_type
        }
    }

    fn add_one_line(&mut self) {
        self.line += 1;
    }

    fn panic(&self, msg: &str) {
        panic!("{}: {} => {}", &self.file, self.line, msg);
    }

}

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    pub fn get_file(&self) -> &String {
        &self.file
    }

    pub fn new(file: String, cb: T) -> LexicalParser<T> {
        let parser = LexicalParser{
            file: file,
            line: 0,
            col: 0,
            content: VecU8::new(),
            cb: cb,
            tokens_buffer: Vec::new()
        };
        parser
    }
}

mod plus;
mod backslash_r;
mod backslash_n;
mod number;
mod id;

mod test {
    use super::*;

    use std::fs;
    use std::io::Read;

    #[test]
    fn lexical_lookup_next_n_test() {
        let mut file = String::from("main.lions");
        let mut f = match fs::File::open(&file) {
            Ok(f) => f,
            Err(err) => {
                panic!("read file error");
            }
        };
        let mut obj = LexicalParser::new(file.clone(), || -> CallbackReturnStatus {
            let mut v = Vec::new();
            let mut f_ref = f.by_ref();
            match f_ref.take(1024).read_to_end(&mut v) {
                Ok(len) => {
                    if len == 0 {
                        return CallbackReturnStatus::End;
                    } else {
                        return CallbackReturnStatus::Continue(VecU8::from_vec_u8(v));
                    }
                },
                Err(_) => {
                    return CallbackReturnStatus::End;
                }
            }
        });
        loop {
            match obj.lookup_next_n(1) {
                Some(t) => {
                    let token_type = &t.context().token_type;
                    println!("{:?}", token_type);
                    obj.skip_next_one();
                },
                None => {
                    break;
                }
            }
        }
    }
}
