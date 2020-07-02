use primeval_method_struct::*;

pub enum PrimevalMethod {
    Uint32PlusUint32(Uint32PlusUint32)
}

pub trait PrimevalSet {
    fn find(&self);
}

pub trait OverrideMap {
    fn find(&self);
}

pub trait DefineMap {
    fn find(&self);
}

struct PrimevalContext<PS, OM, DM>
    where PS: PrimevalSet,
          OM: OverrideMap,
          DM: DefineMap {
    primeval_set: PS,
    override_map: OM,
    define_map: DM
}

pub struct PrimevalControl<PS, OM, DM>
    where PS: PrimevalSet,
          OM: OverrideMap,
          DM: DefineMap {
    context: PrimevalContext<PS, OM, DM>
}

mod primeval_set;
mod override_map;
mod define_map;
mod primeval_control;
mod primeval_method;
mod primeval_method_struct;

