use libcommon::optcode;

/*
 * 指令
 * */
#[derive(Debug)]
pub enum Instruction {
    LoadUint8Const(u8),
    LoadUint16Const(u16),
    CallPrimevalFunction(optcode::OptCode)
}
