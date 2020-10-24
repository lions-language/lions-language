#![feature(entry_insert)]

#[macro_use(extract_token_data)]
extern crate libgrammar;

macro_rules! take_value_top {
    ($this:expr, $name:ident) => {
        /*
        let (format!("{}_tye, {}_addr, {}_typ_addr, {}_package_type, {}_package_str, {}_context"
                , stringify!($name), stringify!($name)
                , stringify!($name), stringify!($name)
                , stringify!($name), stringify!($name)))
        */
        match $this.scope_context.take_top_from_value_buffer() {
            Ok(v) => v,
            Err(err) => {
                return err;
            }
        }
    }
}

pub mod compile;
pub mod bytecode;
pub mod address;
pub mod status;
pub mod define;
pub mod define_dispatch;
pub mod define_stream;
pub mod static_dispatch;
pub mod static_stream;
pub mod module;
