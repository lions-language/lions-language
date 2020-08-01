use crate::compile::{StaticContext};
use libtype::{AddressKey, AddressValue};
use libtype::package::PackageStr;

impl StaticContext {
    pub fn from_token_value(package_str: PackageStr, addr: AddressValue
        , static_addr: AddressKey) -> Self {
        Self {
            package_str: package_str,
            addr: addr,
            static_addr: static_addr
        }
    }
}
