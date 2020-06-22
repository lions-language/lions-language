use crate::token::{self, TokenContext, TokenType, NoOperateToken};
use crate::grammar::Grammar;

/// store Vec<u8> struct
#[derive(Debug)]
pub struct VecU8{
    v: Vec<u8>,
    index: usize
}

impl VecU8 {
    fn skip_next_n(&mut self, n: usize) {
        // 跳过n个字符
        if n > self.v.len() {
            panic!(format!("skip next must be called after lookup, n: {}, self.v.len(): {}", n, self.v.len()));
        }
        for _ in 0..n {
            self.v.remove(0);
        }
        self.index = 0;
    }

    fn skip_next_one(&mut self) {
        self.skip_next_n(1);
    }

    fn virtual_skip_next_n(&mut self, n: usize) {
        self.index += n;
    }

    fn virtual_skip_next_one(&mut self) {
        self.virtual_skip_next_n(1);
    }

    fn backtrack_n(&mut self, n: usize) {
        // 回溯
        if n > self.index {
            panic!(format!("backtrack n > self.index(backtrack_n be called times > 1), n: {}, self.index: {}", n, self.index));
        }
        self.index -= n;
    }

    fn lookup_next_n(&self, n: usize) -> Option<char> {
        if n == 0 {
            panic!("n > 0");
        }
        let index = self.index + n - 1;
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

    fn append(&mut self, mut content: VecU8) {
        self.v.append(&mut content.v);
    }

    pub fn from_vec_u8(v: Vec<u8>) -> Self {
        Self{
            v: v,
            index: 0
        }
    }

    fn new() -> Self {
        Self{
            v: Vec::new(),
            index: 0
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

pub type TokenVecItem<T, CB> = token::Token<T, CB>;

pub struct TokenPointer(usize);

impl TokenPointer {
    pub fn from_ref<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(item: &TokenVecItem<T, CB>) -> Self {
        Self(item as *const TokenVecItem<T, CB> as usize)
    }

    pub fn new_null() -> Self {
        Self(0)
    }

    pub fn is_null(&self) -> bool {
        self.0 == 0
    }

    pub fn as_ref<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar>(&self) -> &'a TokenVecItem<T, CB> {
        unsafe {
            (self.0 as *const TokenVecItem<T, CB>).as_ref().expect("should not happend")
        }
    }

    /*
    pub fn take<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(self) -> TokenVecItem<T, CB> {
        unsafe {
            Box::from_raw(self.0 as *mut dyn token::Token<T, CB>)
        }
    }
    */

    pub fn clone(&self) -> Self {
        Self(self.0)
    }
}

pub struct LexicalParser<T: FnMut() -> CallbackReturnStatus, CB: Grammar> {
    file: String,
    line: u64,
    col: u64,
    content: VecU8,
    cb: T,
    tokens_buffer: Vec<TokenVecItem<T, CB>>
}

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
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

    pub fn skip_next_n(&mut self, n: usize) {
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

    pub fn skip_next_one(&mut self) {
        self.skip_next_n(1);
    }

    pub fn take_next_one(&mut self) -> TokenVecItem<T, CB> {
        if self.tokens_buffer.len() == 0 {
            panic!("take_next_one, tokens_buffer len == 0");
        }
        self.tokens_buffer.remove(0)
    }

    pub fn lookup_next_n(&mut self, n: usize) -> Option<&TokenVecItem<T, CB>> {
        match self.lookup_next_n_index(n) {
            Some(index) => {
                return self.tokens_buffer.get(index);
            },
            None => {
                return None;
            }
        }
    }

    pub fn lookup_next_n_ptr(&mut self, n: usize) -> Option<TokenPointer> {
        match self.lookup_next_n_index(n) {
            Some(index) => {
                match self.tokens_buffer.get(index) {
                    Some(token) => {
                        Some(TokenPointer::from_ref(token))
                    },
                    None => {
                        None
                    }
                }
            },
            None => {
                None
            }
        }
    }

    // pub fn lookup_next_n(&mut self, n: usize) -> Option<Token>

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

    pub fn lookup_next_one_ptr(&mut self) -> Option<TokenPointer> {
        self.lookup_next_n_ptr(1)
    }

    pub fn lookup_next_one_index(&mut self) -> Option<usize> {
        self.lookup_next_n_index(1)
    }

    pub fn token_by_index(&self, index: usize) -> &TokenVecItem<T, CB> {
        match self.tokens_buffer.get(index) {
            Some(token) => {
                token
            },
            None => {
                panic!("call token_by_index must be after lookup_next ...");
            }
        }
    }

    pub fn lookup_next_one(&mut self) -> Option<&TokenVecItem<T, CB>> {
        return self.lookup_next_n(1);
    }

    fn content_assign(&mut self, content: VecU8) {
        if self.content.index > 0 {
            self.content.append(content);
        } else {
            *(&mut self.content) = content;
        }
    }


    fn push_to_token_buffer(&mut self, item: TokenVecItem<T, CB>) {
        self.tokens_buffer.push(item);
    }

    fn push_nooperate_token_to_token_buffer(&mut self, token_type: TokenType) {
        let context = self.build_token_context(token_type);
        self.push_to_token_buffer(NoOperateToken::new(context));
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
    fn is_number_start(&self, c: char) -> bool {
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
            '\t' => self.backslash_t(),
            '+' => self.plus_process(),
            '-' => self.minus_process(),
            '*' => self.start_process(),
            '=' => self.equal_process(),
            '`' => self.backticks_process(),
            '"' => self.double_quotes_process(),
            '(' => self.parenthese_left_process(),
            ')' => self.parenthese_right_process(),
            '{' => self.big_parenthese_left_process(),
            '}' => self.big_parenthese_right_process(),
            '[' => self.square_brackets_left_process(),
            ']' => self.square_brackets_right_process(),
            '/' => self.slash_process(),
            ';' => self.semicolon_process(),
            ' ' => self.space(),
            _ => {
                if self.is_id_start(c) {
                    self.id_process(c);
                } else if self.is_number_start(c) {
                    self.number(c);
                } else {
                    self.panic(&format!("not support char: {}", c));
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

    pub fn panic(&self, msg: &str) {
        // panic!("{}: {} => {}", &self.file, self.line, msg);
        println!("{}: {} => {}", &self.file, self.line, msg);
        std::process::exit(0);
    }

}

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    pub fn get_file(&self) -> &String {
        &self.file
    }

    pub fn new(file: String, cb: T) -> LexicalParser<T, CB> {
        let parser = LexicalParser{
            file: file,
            line: 1,
            col: 0,
            content: VecU8::new(),
            cb: cb,
            tokens_buffer: Vec::new()
        };
        parser
    }
}

mod common;
mod plus;
mod minus;
mod equal;
mod space;
mod backslash_r;
mod backslash_n;
mod backslash_t;
mod backticks;
mod double_quotes;
mod number;
mod id;
mod parenthese;
mod square_brackets;
mod big_parenthese;
mod slash;
mod start;
mod operand;
mod semicolon;

mod test {
    use super::*;

    #[test]
    #[ignore]
    fn lookup_next_one_with_cb_wrap_test() {
        impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
            fn test(&mut self) {
                self.lookup_next_one_with_cb_wrap(|parser, _| {
                    parser.panic("error");
                }, |_| {
                });
            }
        }
    }
}
