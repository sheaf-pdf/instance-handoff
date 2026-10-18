//! How names on disk are made from strings. These are part of the contract
//! between builds of an app (see the crate docs), so the bytes and the hash
//! are written out here and pinned by tests, never left to std's internal
//! encodings or hashers.

use std::ffi::OsStr;

/// FNV-1a, 64 bits.
pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// 16 lowercase hex digits.
pub(crate) fn hex16(h: u64) -> String {
    format!("{h:016x}")
}

/// The bytes a scope is hashed from: the OS string's own bytes on Unix, and
/// on Windows the WTF-8 encoding of its UTF-16 (the same as UTF-8 for valid
/// Unicode).
pub(crate) fn os_key(s: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        s.as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        wtf8(&s.encode_wide().collect::<Vec<u16>>())
    }
    #[cfg(not(any(unix, windows)))]
    {
        s.to_string_lossy().into_owned().into_bytes()
    }
}

/// WTF-8: UTF-8, where a lone surrogate takes the three bytes UTF-8 would
/// give its code point.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn wtf8(units: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(units.len());
    for unit in char::decode_utf16(units.iter().copied()) {
        let c = match unit {
            Ok(c) => u32::from(c),
            Err(e) => u32::from(e.unpaired_surrogate()),
        };
        match c {
            0..=0x7f => out.push(c as u8),
            0x80..=0x7ff => out.extend([0xc0 | (c >> 6) as u8, 0x80 | (c & 0x3f) as u8]),
            0x800..=0xffff => out.extend([
                0xe0 | (c >> 12) as u8,
                0x80 | ((c >> 6) & 0x3f) as u8,
                0x80 | (c & 0x3f) as u8,
            ]),
            _ => out.extend([
                0xf0 | (c >> 18) as u8,
                0x80 | ((c >> 12) & 0x3f) as u8,
                0x80 | ((c >> 6) & 0x3f) as u8,
                0x80 | (c & 0x3f) as u8,
            ]),
        }
    }
    out
}

/// The subfolder a scope names.
pub(crate) fn scope_folder(scope: &OsStr) -> String {
    hex16(fnv1a64(&os_key(scope)))
}

/// The Windows runtime folder for an integrity level, the last RID of its
/// mandatory label: `run` at medium, the normal level, and one of its own
/// at every other, so that each level has its own owner.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn level_folder(level: u32) -> String {
    match level {
        0x1000 => "run-low".into(),
        0x2000 => "run".into(),
        0x3000 => "run-high".into(),
        0x4000 => "run-system".into(),
        other => format!("run-{other:x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Published FNV-1a 64 test vectors.
    #[test]
    fn fnv1a64_matches_the_reference() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    // These names are on disk: changing one splits old and new builds of an
    // app into two owners. Only a major release may change them.
    #[test]
    fn scope_folders_are_frozen() {
        assert_eq!(scope_folder(OsStr::new("")), "cbf29ce484222325");
        assert_eq!(scope_folder(OsStr::new("session-2")), "1688565dcf491334");
        assert_eq!(
            scope_folder(OsStr::new("/home/u/.config/app")),
            "86cba2b7401d120e"
        );
    }

    #[test]
    fn level_folders_are_frozen() {
        assert_eq!(level_folder(0x2000), "run");
        assert_eq!(level_folder(0x3000), "run-high");
        assert_eq!(level_folder(0x4000), "run-system");
        assert_eq!(level_folder(0x1000), "run-low");
        assert_eq!(level_folder(0x2100), "run-2100");
    }

    #[test]
    fn wtf8_is_utf8_for_valid_text_and_keeps_lone_surrogates() {
        let text = "naïve 🎉";
        let units: Vec<u16> = text.encode_utf16().collect();
        assert_eq!(wtf8(&units), text.as_bytes());
        assert_eq!(wtf8(&[0xd800]), [0xed, 0xa0, 0x80]);
    }
}
