use crate::compile::{StaticContext};
use libtype::{AddressKey};
use libtype::Type;
use libtype::package::PackageStr;

impl StaticContext {
    pub fn from_token_value(package_str: PackageStr, typ: Type, addr: AddressKey) -> Self {
        Self {
            package_str: package_str,
            typ: typ,
            addr: addr
        }
    }
}
