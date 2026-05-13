use fatah_core::Protocol;

/// Registry entry submitted by every protocol module at link time. The
/// factory closure returns a fresh boxed instance so the engine can hand
/// each worker its own (cheap, mostly stateless) protocol object.
pub struct ProtoEntry {
    pub factory: fn() -> Box<dyn Protocol>,
}

inventory::collect!(ProtoEntry);

/// Static lookup over every protocol compiled into the binary.
pub struct Registry;

impl Registry {
    /// Construct a protocol instance by its identifier (e.g. `"ftp"`).
    pub fn create(id: &str) -> Option<Box<dyn Protocol>> {
        for entry in inventory::iter::<ProtoEntry> {
            let proto = (entry.factory)();
            if proto.descriptor().id == id {
                return Some(proto);
            }
        }
        None
    }

    /// List every registered protocol's static descriptor. Used by the
    /// CLI for `fatah list-protocols`.
    pub fn descriptors() -> Vec<fatah_core::ProtocolDescriptor> {
        inventory::iter::<ProtoEntry>
            .into_iter()
            .map(|e| (e.factory)().descriptor())
            .collect()
    }
}
