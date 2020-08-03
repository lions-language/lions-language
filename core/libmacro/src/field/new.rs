use proc_macro2;

use proc_macro2::{TokenStream};
use quote::{quote
    , ToTokens};
use syn::{DeriveInput};
use core::str::FromStr;

pub fn new_with_all(input: TokenStream) -> TokenStream {
    let derive: DeriveInput = syn::parse2(input).unwrap();
    let ident = &derive.ident;
    let s = match derive.data {
        syn::Data::Struct(s) => {
            s
        },
        _ => {
            unimplemented!("not struct");
        }
    };  
    let n = match s.fields {
        syn::Fields::Named(n) => {
            n
        },
        _ => {
            unimplemented!("not named struct");
        }
    };
    let fields = n.named;
    let mut ts = TokenStream::new();
    let mut fs = TokenStream::new();
    let mut index = 0;
    let len = fields.len();
    for field in fields.iter() {
        if index > 0 {
            ts.extend::<TokenStream>(TokenStream::from_str(",").expect("should not happend"));
        }
        let typ = &field.ty;
        let field_ident = match &field.ident {
            Some(id) => id,
            None => {
                /*
                 * tuple struct
                 * */
                unimplemented!("tuple struct");
            }
        };
        field_ident.to_tokens(&mut ts);
        ts.extend::<TokenStream>(TokenStream::from_str(":").expect("should not happend"));
        typ.to_tokens(&mut ts);
        // ts.extend::<TokenStream>(field_ident.into());
        index += 1;

        field_ident.to_tokens(&mut fs);
        fs.extend::<TokenStream>(TokenStream::from_str(":").expect("should not happend"));
        field_ident.to_tokens(&mut fs);
        fs.extend::<TokenStream>(TokenStream::from_str(",").expect("should not happend"));
        if index == len - 1 {
            fs.extend::<TokenStream>(TokenStream::from_str("\n").expect("should not happend"));
        }
    }
    let expanded = quote! {
        impl #ident {
            pub fn new(#ts) -> Self {
                Self {
                    #fs
                }
            }
        }
    };
    expanded.into()
}

/*
fn ref_move_cb(struct_ident: &Ident, field_ident: &Ident, typ: &Type) -> TokenStream {
    let ref_id = format_ident!("{}_ref", &field_ident);
    let mut_id = format_ident!("{}_mut", &field_ident);
    let expanded = quote! {
        impl #struct_ident {
            pub fn #ref_id(&self) -> &#typ {
                &self.#field_ident
            }

            pub fn #mut_id(&mut self) -> &mut #typ {
                &mut self.#field_ident
            }

            pub fn #field_ident(self) -> #typ {
                self.#field_ident
            }
        }
    };
    expanded.into()
}

pub fn ref_move(input: TokenStream) -> TokenStream {
    iter(input, ref_move_cb)
}

fn clone_cb(struct_ident: &Ident, field_ident: &Ident, typ: &Type) -> TokenStream {
    let clone_id = format_ident!("{}_clone", &field_ident);
    let expanded = quote! {
        impl #struct_ident {
            pub fn #clone_id(&self) -> #typ {
                self.#field_ident.clone()
            }
        }
    };
    expanded.into()
}

pub fn clone(input: TokenStream) -> TokenStream {
    iter(input, clone_cb)
}
*/

