pub const IMPORT_LOCAL: &'static str = "local";
pub const IMPORT_PATH: &'static str = "path";
pub const IMPORT_PACKAGE: &'static str = "package";
pub const IMPORT_SYSTEM: &'static str = "system";

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
