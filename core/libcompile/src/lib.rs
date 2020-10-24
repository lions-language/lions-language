#![feature(entry_insert)]

#[macro_use(extract_token_data)]
extern crate libgrammar;

macro_rules! take_value_top {
    ($this:expr) => {
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
