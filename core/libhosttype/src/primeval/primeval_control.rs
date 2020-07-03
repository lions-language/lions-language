use super::{PrimevalControl, FinderMap, PrimevalMethod, CompileResult};

impl<M> PrimevalControl<M>
    where M: FinderMap {
    pub fn compile(&self, method: PrimevalMethod) -> CompileResult {
        CompileResult::SingleOptCode()
    }
}

