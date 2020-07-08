use libobject::function::Function;

pub enum FindFuncPanic {
    Undefine(Option<&'static str>),
}

pub struct FindFuncSuccess<'a> {
    pub func: &'a Function
}

pub enum FindFunctionResult<'a> {
    Success(FindFuncSuccess<'a>),
    Panic(FindFuncPanic)
}

pub enum AddFuncPanic {
    AlreadyDefine
}

pub enum AddFunctionResult {
    Success,
    Panic(AddFuncPanic)
}

