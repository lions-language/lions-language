pub type NullResult = Result<(), &'static str>;
pub static NULLOK: Result<(), &'static str> = Ok(());

pub mod function;
