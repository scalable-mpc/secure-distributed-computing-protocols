use common::Options;

/// Maximum size of a single protocol frame on the wire.
///
/// The previous forked networking crate hardcoded this to 400 GiB in its codec,
/// which was effectively "no limit" -- the length-delimited codec uses a 4-byte
/// length prefix, so frames are capped at 4 GiB by the wire format regardless.
/// Upstream `libnet-rs` defaults to 8 MB, which Reed-Solomon shard messages
/// exceed, so we raise it deliberately here rather than inherit the default.
///
/// 1 GiB sits well above any realistic shard while still bounding the amount a
/// peer can make us buffer for a single frame.
pub const MAX_FRAME_LENGTH: usize = 1024 * 1024 * 1024;

/// Networking options shared by every protocol's sender and receiver.
///
/// Both ends of a connection must agree on `max_frame_length`, so all call
/// sites build their options from here instead of using `Options::default()`.
pub fn net_options() -> Options {
    Options {
        max_frame_length: MAX_FRAME_LENGTH,
        ..Options::default()
    }
}
