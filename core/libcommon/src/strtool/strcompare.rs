pub struct U8ArrayIsEqual<'a> {
    src: &'a [u8],
    index: usize,
    length: usize
}

pub enum U8ArrayIsEqualResult {
    // 到了 输入序列的长度, 但是还没有匹配
    NoMatchArriveLength(usize),
    // 没有达到输入序列的长度, 就不匹配了
    NoMatchLessLength(usize),
    Continue,
    Match(usize)
}

impl<'a> U8ArrayIsEqual<'a> {
    pub fn dynamic_match(&mut self, c: char) -> U8ArrayIsEqualResult {
        /*
         * 动态匹配 与输入的数组相等的数组
         * */
        match self.src.get(self.index) {
            Some(ch) => {
                if ch.clone() as char == c {
                    self.index += 1;
                    // 在 ch == c 后每次都判断是否等于输入序列的长度
                    if self.index == self.length {
                        self.index = 0;
                        return U8ArrayIsEqualResult::Match(self.length);
                    } else {
                        return U8ArrayIsEqualResult::Continue;
                    }
                } else {
                    if self.index == self.length {
                        self.index = 0;
                        return U8ArrayIsEqualResult::NoMatchArriveLength(self.length);
                    } else {
                        let r = U8ArrayIsEqualResult::NoMatchLessLength(self.index);
                        self.index = 0;
                        return r;
                    }
                }
            },
            None => {
                // 如果到达这个分支, 说明 index > length
                // 这是不可能发生的, 因为只要和输入的序列匹配了 (index == length) 的时候,
                // 就会直接返回, 如果中间遇到了不匹配的, 也直接返回了
                panic!("should not happend");
            }
        }
    }

    pub fn reset(&mut self) {
        self.index = 0;
    }

    pub fn new(src: &'a [u8]) -> Self {
        Self{
            src: src,
            index: 0,
            length: src.len()
        }
    }
}

mod test {
    use super::*;

    #[ignore]
    #[test]
    fn u8_array_is_equal_dynamic_match_test() {
        let s = "123";
        let d = ['1', '2', '4', '3'];
        let mut obj = U8ArrayIsEqual::new(s.as_bytes());
        for item in d.iter() {
            match obj.dynamic_match(*item) {
                U8ArrayIsEqualResult::Match(_) => {
                    println!("match ...");
                    break;
                },
                _ => {
                }
            }
        }
    }
}
