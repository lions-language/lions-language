use proc_macro2;

use proc_macro2::{TokenStream};
use quote::{quote
    , ToTokens};
use syn::{DeriveInput};
use core::str::FromStr;

pub fn get_move(input: TokenStream) -> TokenStream {
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
    let mut rs = TokenStream::new();
    let mut fs = TokenStream::new();
    let mut index = 0;
    for field in fields.iter() {
        if index > 0 {
            rs.extend::<TokenStream>(TokenStream::from_str(",").expect("should not happend"));
            fs.extend::<TokenStream>(TokenStream::from_str(",").expect("should not happend"));
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
        typ.to_tokens(&mut rs);

        fs.extend::<TokenStream>(TokenStream::from_str("self.").expect("should not happend"));
        field_ident.to_tokens(&mut fs);
        index += 1;
    }
    let expanded = quote! {
        impl #ident {
            pub fn fields_move(self) -> (#rs) {
                (#fs)
            }
        }
    };
    expanded.into()
}

