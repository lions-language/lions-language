pub struct Uint32PlusUint32 {
    pub lvalue: u32,
    pub rvalue: u32
}

impl Uint32PlusUint32 {
    pub fn new(lvalue: u32, rvalue: u32) -> Self {
        Self {
            lvalue: lvalue,
            rvalue: rvalue
        }
    }
}
