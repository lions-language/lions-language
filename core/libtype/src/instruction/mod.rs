use libcommon::optcode;

/*
 * 指令
 * */
pub enum Instruction {
    LoadUint8(u8),
    CallPrimevalFunction(optcode::OptCode)
}
