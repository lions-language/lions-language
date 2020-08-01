use crate::compile::{StaticContext};
use libtype::{AddressKey};
use libtype::package::PackageStr;

impl StaticContext {
    pub fn from_token_value(package_str: PackageStr, addr: AddressKey
        , static_addr: AddressKey) -> Self {
        Self {
            package_str: package_str,
            addr: addr,
            static_addr: static_addr
        }
    }
}
