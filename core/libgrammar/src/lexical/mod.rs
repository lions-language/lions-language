use libcommon::token;

/// store Vec<u8> struct
struct VecU8(Vec<u8>);
impl VecU8 {
    fn lookup_next_n(&mut self, n: usize) -> Option<char> {
        None
    }
    
    fn lookup_next_one(&mut self) -> Option<char> {
        None
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
    End(VecU8)
}

pub type TokenVecItem = Box<dyn token::Token>;

pub struct LexicalParser<T: FnMut() -> CallbackReturnStatus> {
    // content: std::str::Chars<'a>,
    // cb: Callback<'a>
    content: VecU8,
    cb: T
}

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    fn parser(&self) {
    }

    // 查看下n个token
    fn lookup_next_n(&mut self, n: usize) -> Option<Vec<TokenVecItem>> {
        /*
        let mut tokens = Vec::new();
        for _ in 0..n {
            match self.content.next() {
                Some(c) => {
                    self.select(c, &mut tokens);
                },
                None => {
                    return None;
                }
            }
        }
        Some(tokens)
        */
        let mut tokens = Vec::new();
        while true {
            match self.content.lookup_next_one() {
                Some(c) => {
                    self.select(c as char, &mut tokens);
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
                            // 不存在待解析的字符串
                        }
                    }
                }
            }
        }
        None
    }

    fn lookup_next_one(&mut self) -> Option<TokenVecItem> {
        None
    }

    fn lookup_next_n_with_vec(&mut self) {
    }

    fn select(&mut self, c: char, tokens: &mut Vec<TokenVecItem>) {
        match c {
            '+' => self.start_with_plus(tokens),
            _ => {}
        }
    }
}

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    pub fn new(cb: T) -> LexicalParser<T> {
        let parser = LexicalParser{
            content: VecU8::new(),
            cb: cb
            // content: content.chars(),
        };
        parser
    }
}

mod plus;

mod test {
    use super::*;

    #[test]
    fn leical_parser() {
        let vs = vec![String::from("a ="), String::from(" 1;")];
        let obj = LexicalParser::new(|| -> CallbackReturnStatus {
            CallbackReturnStatus::Continue(VecU8::new())
        });
    }
}
