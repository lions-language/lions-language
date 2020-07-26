 #[derive(Debug)]
pub struct FunctionAddrValue {
    start_pos: usize,
    length: usize
}

impl FunctionAddrValue {
    pub fn new(start_pos: usize, length: usize) -> Self {
        Self {
            start_pos: start_pos,
            length: length
        }
    }
}

 #[derive(Debug)]
pub enum FunctionAddress {
    ReferencesDefine(FunctionAddrValue),
    Define(FunctionAddrValue)
}

