use proc_macro;

use proc_macro::TokenStream;
use quote::{quote};
use syn::{DeriveInput};

#[proc_macro_derive(NumberToStd)]
pub fn number_to_std_macro(input: TokenStream) -> TokenStream {
    let derive: DeriveInput = syn::parse(input).unwrap();
    let ident = &derive.ident;
    let s = match derive.data {
        syn::Data::Struct(s) => {
            s
        },
        _ => {
            panic!("must be struct");
        }
    };  
    let n = match s.fields {
        syn::Fields::Named(n) => {
            n
        },
        _ => {
            panic!("not named");
        }
    };  
    let named = n.named;
    if named.is_empty() {
        panic!("field must len more than 1");
    }
    let field = named.first().expect("should not happend");
    let typ = &field.ty;

    let expanded = quote! {
        impl #ident {
            pub fn to_std(self) -> #typ {
                self.value
            }

            pub fn to_std_ref(&self) -> &#typ {
                &self.value
            }
        }
    };  
    expanded.into()
}

#[proc_macro_derive(FieldGet)]
pub fn field_get(input: TokenStream) -> TokenStream {
    field::get::ref_move(input)
}

#[proc_macro_derive(FieldGetClone)]
pub fn field_get_clone(input: TokenStream) -> TokenStream {
    field::get::clone(input)
}

#[proc_macro_derive(FieldGetMove)]
pub fn field_get_move(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    TokenStream::from(field::get_move::get_move(proc_macro2::TokenStream::from(input)))
}

#[proc_macro_derive(NewWithAll)]
pub fn new_with_all(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    TokenStream::from(field::new::new_with_all(proc_macro2::TokenStream::from(input)))
}

mod field;

