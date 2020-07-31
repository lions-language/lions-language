use libtype::Data;
use std::collections::VecDeque;

pub struct RandStack {
    datas: VecDeque<Data>,
    recycles: Vec<usize>
}

pub struct TopStack<T> {
    datas: VecDeque<T>
}

mod rand;
mod top;
