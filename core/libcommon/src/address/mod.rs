 #[derive(Debug)]
pub struct FunctionAddrValue {
}

 #[derive(Debug)]
pub enum FunctionAddress {
    ReferencesDefine(FunctionAddrValue),
    Define(FunctionAddrValue)
}

