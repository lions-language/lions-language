use libtype::Data;
use std::collections::VecDeque;

pub struct RandStack<T> {
    datas: VecDeque<T>,
    recycles: Vec<usize>
}

pub struct TopStack<T> {
    datas: VecDeque<T>
}

mod rand;
mod top;
