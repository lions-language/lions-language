/*
 * 当前版本支持的数值: 正/负十六进制整数, 正/负八进制整数, 正/负十进制整数, 正/负十进制小数
 * (随着 lions-language 的更新, 将支持更多的数值)
 * */
use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType, TokenData};
use number_token::NumberToken;
use crate::grammar::Grammar;
use libtype::primeval::{PrimevalType, PrimevalData};
use libtype::primeval::number;

// #![feature(assoc_int_consts)]

enum BeforeChange {
    Integer(u64),
    Float(f64)
}

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone> LexicalParser<T, CB> {
    fn number_is_8(&self, c: char) -> Option<u8> {
        if c >= '0' && c <= '7' {
            return Some(c as u8 - '0' as u8);
        }
        None
    }

    fn number_8(&mut self) {
        // 八进制
        let mut value: u64 = 0;
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    match self.number_is_8(c) {
                        Some(v) => {
                            self.content.skip_next_one();
                            value = value * 8 + v as u64;
                        },
                        None => {
                            break;
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
                            break;
                        }
                    }
                }
            }
        }
        self.push_number_token_to_token_buffer(self.number_range_change(BeforeChange::Integer(value)));
    }

    fn number_is_10(&self, c: char) -> Option<u8> {
        if c >= '0' && c <= '9' {
            return Some(c as u8 - '0' as u8);
        }
        None
    }

    fn number_10(&mut self, start_c: char) {
        // 十进制
        let mut value: u64 = (start_c as u8 - '0' as u8) as u64;
        let mut f_value: f64 = 0.0;
        enum Type {
            // 解析整数部分
            Integer,
            // 解析小数部分
            Decimal
        }
        let mut status = Type::Integer;
        let mut result_type = Type::Integer;
        let mut f_index = 1;
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    match status {
                        Type::Integer => {
                            if c == '.' {
                                /*
                                 * 在整数状态下, 遇到了点号:
                                 * 1. 点后面是数值 => 浮点数
                                 * 2. 点后面是非数值 => 整数 break(可能是.运算符)
                                 * */
                                // 获取 . 号后面的字符
                                let mut after_point_c: char = ' ';
                                match self.content.lookup_next_n(2) {
                                    Some(ch) => {
                                        after_point_c = ch;
                                    },
                                    None => {
                                        match (self.cb)() {
                                            CallbackReturnStatus::Continue(content) => {
                                                *(&mut self.content) = content;
                                                if let Some(ch) = self.content.lookup_next_n(2) {
                                                    after_point_c = ch;
                                                } else {
                                                    // cb 返回 continue => 说明 . 号后面一定有字符,
                                                    // 所以这里是肯定不会发生的, 如果发生了,
                                                    // 说明 cb 中返回的 content 是空的
                                                    // (代码逻辑错误)
                                                    panic!("should not happend");
                                                }
                                            },
                                            CallbackReturnStatus::End => {
                                                // 源码遇到这种情况: xxx. EOF
                                                // 也就是说点号后面是结尾 => 语法错误
                                                self.panic("expect number after or method after point, but found a EOF");
                                            }
                                        }
                                    }
                                }
                                if let None = self.number_is_10(after_point_c) {
                                    // . 后面是非数值
                                    break;
                                } else {
                                    // . 后面是数值 => 跳过 点
                                    self.content.skip_next_one();
                                }
                                status = Type::Decimal;
                                continue;
                            }
                            if let Some(v) = self.number_is_10(c) {
                                value = value * 10 + v as u64;
                                self.content.skip_next_one();
                            } else {
                                // 在整数状态下, 后面既不是 . 也不是数值 => 退出解析
                                result_type = Type::Integer;
                                break;
                            }
                        },
                        Type::Decimal => {
                            if let Some(v) = self.number_is_10(c) {
                                // 小数部分: 原数值 * 0.1 + v.pow()
                                f_value += v as f64 * 0.1_f64.powi(f_index);
                                f_index += 1;
                                self.content.skip_next_one();
                            } else {
                                // 在小数状态下, 后面不是数值 => 退出解析
                                result_type = Type::Decimal;
                                break;
                            }
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
                            break;
                        }
                    }
                }
            }
        }
        match result_type {
            Type::Integer => {
                self.push_number_token_to_token_buffer(self.number_range_change(BeforeChange::Integer(value)));
            },
            Type::Decimal => {
                let result = value as f64 + f_value;
                self.push_number_token_to_token_buffer(self.number_range_change(BeforeChange::Float(result)));
            }
        }
    }

    fn number_is_16(&self, c: char) -> Option<u8> {
        if c >= 'A' && c <= 'F' {
            return Some(c as u8 - 'A' as u8 + 10);
        } else if c >= 'a' && c <= 'f' {
            return Some(c as u8 - 'a' as u8 + 10);
        } else if let Some(_) = self.number_is_10(c) {
            return Some(c as u8 - '0' as u8);
        }
        None
    }

    fn number_16(&mut self, c: char) {
        // 十六进制, c: x|X
        // 跳过 x|X
        self.content.skip_next_one();
        let mut is = false;
        let mut value: u64 = 0;
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    match self.number_is_16(c) {
                        Some(v) => {
                            is = true;
                            self.content.skip_next_one();
                            value = value * 16 + v as u64;
                        },
                        None => {
                            break;
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
                            break;
                        }
                    }
                }
            }
        }
        if !is {
            // 只有 0x => 语法错误
            self.panic("expect 0-9 / a(A)-f(F) after 0x");
        }
        self.push_number_token_to_token_buffer(self.number_range_change(BeforeChange::Integer(value)));
    }

    fn number_is_mid(&mut self, c: char) -> bool {
        // 在第一位是数值的情况下, 剩余几位是否是合法数值组成部分
        if let Some(_) = self.number_is_10(c) {
            // 是 0-9
            return true;
        } else if c == 'x' || c == 'X' || c == '.' {
            // 是 x | X | .
            return true;
        }
        false
    }

    pub fn number(&mut self, start_c: char) {
        // 跳过第一个字符
        self.content.skip_next_one();
        match start_c {
            '0' => {
                // 0x | 0X => 十六进制
                // 0 => 八进制(0后面存在数值) / 0值(0后面不是数值)
                /*
                 * 判断是否为0, 满足以下条件的就是0
                 * 1. content中有下一个字符, 但是下一个字符是非数字
                 * 2. content中没有下一个字符, 调用cb, 更新content后, content中存在下一个字符,
                 *    但是该字符不是数字; 或者 更新content后, content中不存在下一个字符(说明到达了尾部)
                 * 3. content中，没有下一个字符, 并且调用cb后, 返回的是End, 说明0后面是输入尾部
                 */
                let mut is_zero = false;
                match self.content.lookup_next_one() {
                    Some(c) => {
                        if !self.number_is_mid(c) {
                            // println!("{}", c);
                            is_zero = true;
                        }
                    },
                    None => {
                        match (self.cb)() {
                            CallbackReturnStatus::Continue(content) => {
                                *(&mut self.content) = content;
                                match self.content.lookup_next_one() {
                                    Some(c) => {
                                        if !self.number_is_mid(c) {
                                            is_zero = true;
                                        }
                                    },
                                    None => {
                                        // 到达尾部
                                        is_zero = true;
                                    }
                                }
                            },
                            CallbackReturnStatus::End => {
                                // 到达输入源尾部
                                is_zero = true;
                            }
                        }
                    }
                }
                if is_zero {
                    self.push_number_token_to_token_buffer((PrimevalType::Uint8, PrimevalData::Uint8(
                            Some(number::uint8::Uint8::new(0)))));
                    return;
                }
                // 下面的 loop 是防止读取content的next时没有数据的情况, 此时需要读取 cb 的返回值,
                // 在需要的情况下更新 content
                /*
                 * 比如: 源码是 0x01
                 * 因为可以分批读取, 从读取到的第一个content中读取了一个 0, 然后就结束了
                 * 当再一次调用 cb 后, 获取到了新的 content, 此时应该要从新的content中处理紧接着的 x, 那么应该继续处理 0x 的分支
                 * */
                loop {
                    match self.content.lookup_next_one() {
                        Some(c) => {
                            match c {
                                'x'|'X' => {
                                    // 十六进制
                                    self.number_16(c);
                                    return;
                                },
                                '.' => {
                                    self.number_10(start_c);
                                    return;
                                },
                                _ => {
                                    if let Some(_) = self.number_is_10(c) {
                                        // 八进制
                                        if let None = self.number_is_8(c) {
                                            // 0 后面是数字, 但是不是 八进制的数值 => 报错
                                            self.panic("expect 0-7 after 0");
                                        }
                                        self.number_8();
                                        return;
                                    } else {
                                        // 0 后面不是 x|X 也不是 数字, 这种情况下只有是0的时候才会发生,
                                        //   但是上面已经处理过0的情况了
                                        panic!("should not happend");
                                    }
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
                                    // 检测是否为 0 时已经处理过了
                                    panic!("should not happend");
                                }
                            }
                        }
                    }
                }
            },
            _ => {
                // 十进制 (需要考虑存在小数点的情况)
                self.number_10(start_c);
                return;
            }
        }
    }

    fn number_unsigned_int_change(&self, value: u64) -> (PrimevalType, PrimevalData) {
        if value >= u8::min_value() as u64 && value <= u8::max_value() as u64 {
            return (PrimevalType::Uint8, PrimevalData::Uint8(Some(number::uint8::Uint8::new(value as u8))));
        } else if value > u8::max_value() as u64 && value <= u16::max_value() as u64 {
            return (PrimevalType::Uint16, PrimevalData::Uint16(Some(number::uint16::Uint16::new(value as u16))));
        } else if value > u16::max_value() as u64 && value <= u32::max_value() as u64 {
            return (PrimevalType::Uint32, PrimevalData::Uint32(Some(number::uint32::Uint32::new(value as u32))));
        } else {
            return (PrimevalType::Uint64, PrimevalData::Uint64(Some(number::uint64::Uint64::new(value))));
        }
    }

    fn number_signed_int_change(&self, value: u64) -> (PrimevalType, PrimevalData) {
        let v = value as i64 * -1;
        if v >= i8::min_value() as i64 && v <= i8::max_value() as i64 {
            return (PrimevalType::Int8, PrimevalData::Int8(Some(number::int8::Int8::new(v as i8))));
        } else if v > i8::max_value() as i64 && v <= i16::max_value() as i64 {
            return (PrimevalType::Int16, PrimevalData::Int16(Some(number::int16::Int16::new(v as i16))));
        } else if v > i16::max_value() as i64 && v <= i32::max_value() as i64 {
            return (PrimevalType::Int32, PrimevalData::Int32(Some(number::int32::Int32::new(v as i32))));
        } else {
            return (PrimevalType::Int64, PrimevalData::Int64(Some(number::int64::Int64::new(v))));
        }
    }

    fn number_float_change(&self, value: f64) -> (PrimevalType, PrimevalData) {
        let val: f64 = value;
        if val >= f32::MIN as f64 && val <= f32::MAX as f64 {
            return (PrimevalType::Float32, PrimevalData::Float32(Some(number::float32::Float32::new(val as f32))));
        } else {
            return (PrimevalType::Float64, PrimevalData::Float64(Some(number::float64::Float64::new(val))));
        }
    }

    // 转换合适的数值类型
    fn number_range_change(&self, before: BeforeChange) -> (PrimevalType, PrimevalData) {
        match before {
            BeforeChange::Integer(value) => {
                return self.number_unsigned_int_change(value);
            },
            BeforeChange::Float(value) => {
                // float和integer不同, float
                return self.number_float_change(value);
            }
        }
    }

    pub fn push_number_token_to_token_buffer(&mut self, value: (PrimevalType, PrimevalData)) {
        let context = self.build_token_context(TokenType::Const(value.0), TokenData::Const(value.1));
        self.push_to_token_buffer(NumberToken::new(context));
    }
}

mod number_token;

