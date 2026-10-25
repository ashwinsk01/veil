//! Byte layout of shares, keycards and masks. See `SPEC.md` for the authoritative tables.

use crate::{Error, MAX_SHARES, SECRET_LEN};

pub const MAGIC: [u8; 4] = *b"VEIL";
pub const KEYCARD_MAGIC: [u8; 4] = *b"VKEY";
pub const MASK_MAGIC: [u8; 4] = *b"VMSK";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 28;
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

/// Each pairwise key is a POLYVAL hash key followed by a one-time pad.
pub(crate) const HASH_KEY_LEN: usize = 16;
pub(crate) const PAD_LEN: usize = KEY_LEN - HASH_KEY_LEN;

/// Random identifier shared by every share of one split.
pub type SetId = [u8; 16];

pub(crate) const Y_OFFSET: usize = HEADER_LEN;
pub(crate) const KEYS_OFFSET: usize = HEADER_LEN + SECRET_LEN;

/// Total length of each share in a split of `n`.
pub const fn share_len(n: u8) -> usize {
    KEYS_OFFSET + n.saturating_sub(1) as usize * (KEY_LEN + TAG_LEN)
}

/// Length of a keycard: a header and the hash half of each of a share's keys.
pub const fn keycard_len(n: u8) -> usize {
    HEADER_LEN + n.saturating_sub(1) as usize * HASH_KEY_LEN
}

/// Length of a refresh mask file: a header naming its share, then a share-sized XOR mask.
pub const fn mask_len(n: u8) -> usize {
    HEADER_LEN + share_len(n)
}

/// Length of the authenticated part of a share: everything before the tags.
pub(crate) const fn body_len(n: u8) -> usize {
    KEYS_OFFSET + n.saturating_sub(1) as usize * KEY_LEN
}

/// Position of `other` in the ascending list 1..=n with `own` left out.
pub(crate) const fn slot(own: u8, other: u8) -> usize {
    if other < own {
        other as usize - 1
    } else {
        other as usize - 2
    }
}

/// Checks that a threshold `k` and share count `n` are usable.
pub fn check_params(k: u8, n: u8) -> Result<(), Error> {
    if 2 <= k && k <= n && n as usize <= MAX_SHARES {
        Ok(())
    } else {
        Err(Error::BadParams)
    }
}

/// What every veil file records after its magic: which split, which epoch, which share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub(crate) k: u8,
    pub(crate) n: u8,
    pub(crate) x: u8,
    pub(crate) epoch: u32,
    pub(crate) set_id: SetId,
}

impl Header {
    /// Validates the header of a file that must start with `magic` and be `len(n)` bytes long.
    pub(crate) fn parse(bytes: &[u8], magic: [u8; 4], len: fn(u8) -> usize) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::BadLength);
        }
        if bytes[0..4] != magic {
            return Err(Error::BadMagic);
        }
        if bytes[4] != VERSION {
            return Err(Error::UnsupportedVersion(bytes[4]));
        }
        let (k, n, x) = (bytes[5], bytes[6], bytes[7]);
        check_params(k, n)?;
        if x == 0 || x > n {
            return Err(Error::BadIndex);
        }
        if bytes.len() != len(n) {
            return Err(Error::BadLength);
        }
        let mut set_id = [0; 16];
        set_id.copy_from_slice(&bytes[12..28]);
        Ok(Self {
            k,
            n,
            x,
            epoch: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            set_id,
        })
    }

    pub(crate) fn write(&self, out: &mut [u8], magic: [u8; 4]) {
        out[0..4].copy_from_slice(&magic);
        out[4] = VERSION;
        out[5] = self.k;
        out[6] = self.n;
        out[7] = self.x;
        out[8..12].copy_from_slice(&self.epoch.to_be_bytes());
        out[12..28].copy_from_slice(&self.set_id);
    }
}

/// A validated, zero-copy view of one encoded share.
#[derive(Clone, Copy, Debug)]
pub struct ShareView<'a> {
    header: Header,
    bytes: &'a [u8],
}

impl<'a> ShareView<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let header = Header::parse(bytes, MAGIC, share_len)?;
        Ok(Self { header, bytes })
    }

    pub fn threshold(&self) -> u8 {
        self.header.k
    }

    pub fn total(&self) -> u8 {
        self.header.n
    }

    pub fn index(&self) -> u8 {
        self.header.x
    }

    pub fn epoch(&self) -> u32 {
        self.header.epoch
    }

    pub fn set_id(&self) -> SetId {
        self.header.set_id
    }

    pub(crate) fn header(&self) -> Header {
        self.header
    }

    pub(crate) fn y(&self) -> &'a [u8] {
        &self.bytes[Y_OFFSET..KEYS_OFFSET]
    }

    pub(crate) fn body(&self) -> &'a [u8] {
        &self.bytes[..body_len(self.header.n)]
    }

    /// The key this share holds for verifying share `other`.
    pub(crate) fn key_for(&self, other: u8) -> &'a [u8] {
        let at = KEYS_OFFSET + slot(self.header.x, other) * KEY_LEN;
        &self.bytes[at..at + KEY_LEN]
    }

    /// The tag on this share's body that share `verifier` checks.
    pub(crate) fn tag_from(&self, verifier: u8) -> &'a [u8] {
        let at = body_len(self.header.n) + slot(self.header.x, verifier) * TAG_LEN;
        &self.bytes[at..at + TAG_LEN]
    }
}

/// A validated, zero-copy view of one keycard.
#[derive(Clone, Copy, Debug)]
pub struct KeycardView<'a> {
    header: Header,
    bytes: &'a [u8],
}

impl<'a> KeycardView<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let header = Header::parse(bytes, KEYCARD_MAGIC, keycard_len)?;
        Ok(Self { header, bytes })
    }

    pub fn threshold(&self) -> u8 {
        self.header.k
    }

    pub fn total(&self) -> u8 {
        self.header.n
    }

    pub fn index(&self) -> u8 {
        self.header.x
    }

    pub fn epoch(&self) -> u32 {
        self.header.epoch
    }

    pub fn set_id(&self) -> SetId {
        self.header.set_id
    }

    pub(crate) fn header(&self) -> Header {
        self.header
    }

    /// The hash key this card's share uses to check share `other`.
    pub(crate) fn hash_key_for(&self, other: u8) -> &'a [u8] {
        let at = HEADER_LEN + slot(self.header.x, other) * HASH_KEY_LEN;
        &self.bytes[at..at + HASH_KEY_LEN]
    }
}
