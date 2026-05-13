//! Procedural macros for `fatah-*` crates.
//!
//! The flagship macro is [`fatah_proto`] — an attribute placed on a
//! protocol struct that auto-registers it with the global protocol
//! registry at link time via the `inventory` crate.

use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, parse_macro_input};

/// Attribute macro registering a [`Protocol`] implementation with the
/// global registry. The annotated type must implement `Default` (used by
/// the generated factory closure) and `fatah_core::Protocol`.
///
/// ```ignore
/// use fatah_macros::fatah_proto;
///
/// #[fatah_proto]
/// #[derive(Default)]
/// pub struct FtpProtocol;
///
/// #[async_trait::async_trait]
/// impl fatah_core::Protocol for FtpProtocol { /* ... */ }
/// ```
#[proc_macro_attribute]
pub fn fatah_proto(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let name = &input.ident;

    let expanded = quote! {
        #input

        ::fatah_proto::__private::inventory::submit! {
            ::fatah_proto::ProtoEntry {
                factory: || ::std::boxed::Box::new(<#name as ::core::default::Default>::default()),
            }
        }
    };

    TokenStream::from(expanded)
}
