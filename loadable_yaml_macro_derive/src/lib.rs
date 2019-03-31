#![recursion_limit = "128"]
extern crate proc_macro;

use crate::proc_macro::TokenStream;
use quote::quote;
use syn;

#[proc_macro_derive(LoadableYaml)]
pub fn loadable_yaml_macro_derive(input: TokenStream) -> TokenStream {
    // Construct a representation of Rust code as a syntax tree
    // that we can manipulate
    let ast = syn::parse(input).unwrap();

    // Build the trait implementation
    impl_loadable_yaml_macro(&ast)
}

fn impl_loadable_yaml_macro(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let gen = quote! {
        impl warmy::Load<Context> for #name {
            type Key = warmy::LogicalKey;
            type Error = compat_error::CompatError;
            fn load(
                key: Self::Key,
                _store: &mut warmy::Storage<Context>,
                ctx: &mut ggez::Context,
            ) -> Result<warmy::Loaded<Self>, Self::Error> {
                let file = ggez::filesystem::open(ctx, key.as_str()).map_err(compat_error::err_from)?;
                let yaml: serde_yaml::Value = serde_yaml::from_reader(file).map_err(compat_error::err_from)?;
                let name: #name = serde_yaml::from_value(yaml).map_err(compat_error::err_from)?;
                Ok(warmy::Loaded::from(name))
            }
        }
    };
    gen.into()
}
