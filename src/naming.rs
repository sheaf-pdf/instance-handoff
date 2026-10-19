//! How names on disk are made from strings. These are part of the contract
//! between builds of an app (see the crate docs), so the bytes and the hash
//! are written out here and pinned by tests, never left to std's internal
//! encodings or hashers.

use std::ffi::OsStr;
use std::path::Path;

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

/// The bytes a state folder or a scope is hashed from: the OS string's own
/// bytes on Unix, and on Windows the WTF-8 encoding of its UTF-16 (the same
/// as UTF-8 for valid Unicode).
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

/// The instance folder: `i-` and 16 hex digits of the hash of
/// [`instance_key`]. Launches that name one state folder and scope meet in
/// it.
pub(crate) fn instance_folder(state: Option<&Path>, scope: Option<&OsStr>) -> String {
    format!("i-{}", hex16(fnv1a64(&instance_key(state, scope))))
}

/// The bytes the instance folder's name is hashed from: the canonical state
/// folder, then the scope, each as `tag u8 | length u32 LE | bytes` (tag 1
/// for the state, 2 for the scope), and left out when there is none. So
/// `State::none()` differs from an empty path, and no scope from an empty
/// one. The owner sends these bytes in HELLO's STATE record.
pub(crate) fn instance_key(state: Option<&Path>, scope: Option<&OsStr>) -> Vec<u8> {
    let mut key = Vec::new();
    for (tag, part) in [(1u8, state.map(Path::as_os_str)), (2, scope)] {
        if let Some(part) = part {
            let bytes = os_key(part);
            key.push(tag);
            key.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            key.extend_from_slice(&bytes);
        }
    }
    key
}

/// Root's base on Linux: the same for every root launch, whether or not
/// root is logged in.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) const ROOT_BASE_RUN: &str = "/run/instance-handoff";

/// Root's base on the BSDs and illumos.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) const ROOT_BASE_VAR_RUN: &str = "/var/run/instance-handoff";

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
    fn instance_folders_are_frozen() {
        let app = Some(Path::new("/home/u/.config/app"));
        let work = Some(OsStr::new("work"));
        let empty = Some(OsStr::new(""));
        assert_eq!(instance_folder(None, None), "i-cbf29ce484222325");
        assert_eq!(instance_folder(None, empty), "i-fe1a162e1fcabe15");
        assert_eq!(instance_folder(None, work), "i-4f92fd6cb30d130c");
        assert_eq!(instance_folder(app, None), "i-917fa4ee44254388");
        assert_eq!(instance_folder(app, empty), "i-f4411c7a01f6425e");
        assert_eq!(instance_folder(app, work), "i-4381e053b18e505f");
        let windows = Path::new(r"C:\Users\u\AppData\Roaming\app");
        assert_eq!(instance_folder(Some(windows), None), "i-1f3feb8cd03e4a8b");
    }

    // What the names above are hashed from, frozen with them.
    #[test]
    fn the_instance_key_frames_each_part() {
        assert_eq!(instance_key(None, None), b"");
        assert_eq!(instance_key(Some(Path::new("")), None), b"\x01\0\0\0\0");
        assert_eq!(
            instance_key(Some(Path::new("/s")), Some(OsStr::new("k"))),
            b"\x01\x02\0\0\0/s\x02\x01\0\0\0k"
        );
    }

    // A path that isn't valid Unicode: the bytes `ed a0 80` on Unix, and on
    // Windows the lone surrogate whose WTF-8 they are. Both name one folder.
    #[cfg(any(unix, windows))]
    #[test]
    fn a_path_that_isnt_unicode_has_a_frozen_folder_too() {
        #[cfg(unix)]
        let name = {
            use std::os::unix::ffi::OsStrExt;
            OsStr::from_bytes(b"caf\xed\xa0\x80").to_os_string()
        };
        #[cfg(windows)]
        let name = {
            use std::os::windows::ffi::OsStringExt;
            std::ffi::OsString::from_wide(&[0x63, 0x61, 0x66, 0xd800])
        };
        // Not `join`, which puts `\` before it on Windows.
        let mut path = std::ffi::OsString::from("/home/u/");
        path.push(name);
        assert_eq!(
            instance_folder(Some(Path::new(&path)), None),
            "i-39a3cd28239e735c"
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
    fn root_bases_are_frozen() {
        assert_eq!(ROOT_BASE_RUN, "/run/instance-handoff");
        assert_eq!(ROOT_BASE_VAR_RUN, "/var/run/instance-handoff");
    }

    #[test]
    fn wtf8_is_utf8_for_valid_text_and_keeps_lone_surrogates() {
        let text = "naïve 🎉";
        let units: Vec<u16> = text.encode_utf16().collect();
        assert_eq!(wtf8(&units), text.as_bytes());
        assert_eq!(wtf8(&[0xd800]), [0xed, 0xa0, 0x80]);
    }
}
