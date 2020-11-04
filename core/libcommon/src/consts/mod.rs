pub const IMPORT_LOCAL: &'static str = "local";
pub const IMPORT_PATH: &'static str = "path";
pub const IMPORT_PACKAGE: &'static str = "package";
pub const IMPORT_SYSTEM: &'static str = "system";

pub const MOD_LIONS_NAME: &'static str = "mod.lions";
pub const LIONS_EXT: &'static str = ".lions";

pub const STAR: &'static str = "*";

#[derive(Debug)]
pub enum ImportPrefixType {
    Local,
    Package,
    System
}

impl Default for ImportPrefixType {
    fn default() -> Self {
        ImportPrefixType::Local
    }
}
