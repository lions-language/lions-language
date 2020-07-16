use libcommon::optcode;

#[derive(Debug)]
pub struct CallPrimevalFunction {
    pub opt: optcode::OptCode,
    pub return_addr: u64
}

#[derive(Debug)]
pub enum AddressValue {
    Static(u64),
    Stack(u64)
}

#[derive(Debug)]
pub struct VariantValue {
    pub addr: u64,
    pub direction: AddressValue
}

impl VariantValue {
    pub fn new(addr: u64, direction: AddressValue) -> Self {
        Self {
            addr: addr,
            direction: direction
        }
    }
}

#[derive(Debug)]
pub struct Uint8Static {
    pub addr: u64,
    pub value: u8
}

/*
 * 指令
 * */
#[derive(Debug)]
pub enum Instruction {
    LoadUint8Const(Uint8Static),
    LoadUint16Const(u16),
    LoadVariant(VariantValue),
    CallPrimevalFunction(CallPrimevalFunction)
}
