# Veil share format, version 1

One file of at most 10,240 bytes is split into *n* shares. Any *k* shares rebuild it. Any *k* − 1 shares
carry no information about it, against any adversary, whatever its computing power. Tampering is
detected with the same unconditional guarantee, up to the probability stated below.

## Parameters

- 2 ≤ *k* ≤ *n* ≤ 16. Share indices *x* = 1 … *n*.
- Field: GF(2⁸) with reduction polynomial x⁸ + x⁴ + x³ + x + 1 (0x11B, as in AES). Addition and
  subtraction are both XOR. Check value: 0x57 · 0x83 = 0xC1.
- Randomness: every random byte below must be uniform, independent and never reused. This is the only
  assumption the guarantees rest on.

## Secret block *S* (10,242 bytes)

*S* = *L* (2 bytes, big-endian, *L* ≤ 10,240) ‖ file (*L* bytes) ‖ zero bytes up to 10,242.

## Splitting

1. Draw a 16-byte set ID.
2. For each byte position *b* of *S*, draw *k* − 1 random bytes *a*₁ … *a*ₖ₋₁. Share *x* gets
   *yₓ*[*b*] = *S*[*b*] + *a*₁*x* + *a*₂*x*² + … + *a*ₖ₋₁*x*ᵏ⁻¹.
3. For every ordered pair (*i*, *j*) with *i* ≠ *j*, draw a 32-byte key *K*(*i*, *j*): a hash key
   *h*(*i*, *j*) (16 bytes) followed by a pad *p*(*i*, *j*) (16 bytes). Share *i* stores it.
4. For every *i* ≠ *j*, share *j* stores the tag *T*(*i*, *j*) = MAC(*K*(*i*, *j*), body*ⱼ*).

## Tags

MAC(*h* ‖ *p*, *m*) = POLYVAL(*h*, *m* ‖ *len*) ⊕ *p*, with POLYVAL as defined in RFC 8452. *m* is
zero-padded to a multiple of 16 bytes, and *len* is one 16-byte block: the bit length of *m* as a
little-endian 64-bit integer, then 8 zero bytes. POLYVAL is linear, so for equal-length *m* and *d*,
MAC(*K*, *m*) ⊕ MAC(*K*, *m* ⊕ *d*) = POLYVAL(*h*, *d* ‖ 0¹⁶). Refresh relies on this.

## Share layout

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `VEIL` |
| 4 | 1 | version = 1 |
| 5 | 1 | *k* |
| 6 | 1 | *n* |
| 7 | 1 | *x* |
| 8 | 4 | epoch, big-endian (0 at split) |
| 12 | 16 | set ID |
| 28 | 10,242 | *yₓ* |
| 10,270 | 32(*n* − 1) | keys *K*(*x*, *j*) for *j* = 1 … *n*, *j* ≠ *x*, ascending |
| 10,270 + 32(*n* − 1) | 16(*n* − 1) | tags *T*(*i*, *x*) for *i* = 1 … *n*, *i* ≠ *x*, ascending |

The body is every byte before the tags. A share is 10,270 + 48(*n* − 1) bytes: 10,462 for *n* = 5.

## Recovery

1. Reject unless every presented share has the same version, *k*, *n*, epoch and set ID, the indices
   are distinct, and there are at least *k* shares.
2. For every ordered pair (*i*, *j*) of presented shares with *i* ≠ *j*, recompute
   MAC(*K*(*i*, *j*), body*ⱼ*) and compare it with *T*(*i*, *j*) in constant time. If any
   comparison fails, stop and output nothing.
3. Take any *k* of the shares, with indices *x*₁ … *x*ₖ. For each *b*,
   *S*[*b*] = Σⱼ λⱼ · *y*ₓⱼ[*b*], where λⱼ = Πₘ≠ⱼ *x*ₘ / (*x*ₘ + *x*ⱼ).
4. Reject unless *L* ≤ 10,240 and every padding byte is zero. Output the *L* file bytes.

## Refresh

Moves a complete set from epoch *e* to *e* + 1 without rebuilding *S*. The shares never need to meet.

1. Each share *x* issues a **keycard**: its 28-byte header with magic `VKEY`, then *h*(*x*, *j*) for
   *j* = 1 … *n*, *j* ≠ *x*, ascending, for 28 + 16(*n* − 1) bytes in all. A keycard holds no share
   data and no pads.
2. The dealer takes one keycard per share (all *n*, one set and epoch). For each share *x* it writes a
   **mask file**: the share's header with magic `VMSK`, then a mask *Mₓ* the length of a share, zero
   except for:
   - the epoch field: *e* ⊕ (*e* + 1), big-endian;
   - the *y* region: for each *b*, draw *k* − 1 random bytes *c*₁ … *c*ₖ₋₁, the same for every *x*,
     and set *Mₓ*[*b*] = *c*₁*x* + … + *c*ₖ₋₁*x*ᵏ⁻¹, a fresh sharing of zero;
   - the pad half of each key *K*(*x*, *j*): 16 fresh random bytes σ(*x*, *j*). The hash half stays zero;
   - each tag *T*(*i*, *x*): POLYVAL(*h*(*i*, *x*), body of *Mₓ* ‖ 0¹⁶) ⊕ σ(*i*, *x*).
3. Each share checks that its mask file's header equals its own header (apart from the magic), then
   XORs in *Mₓ*. Then destroy every keycard, every mask file and every epoch-*e* share.

With every share in one place, cross-verify them all and read the hash keys from the shares directly.
The masks come out the same.

## Composed keys

A composed key *K* (32 bytes) opens only with the shares and 27 words, plus a device if one was
enrolled. Draw a 4-byte pad *p*, a 16-byte hash key *h* and the words' factor *X*w (36 bytes). A
device's factor *X*d comes from the fuzzy extractor below. With *C* = *K* ‖ *p*, the shares carry
this 62-byte payload as their file:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `VCMP` |
| 4 | 1 | version = 1 |
| 5 | 1 | factors: bit 0 words (always set), bit 1 device |
| 6 | 36 | *C* ⊕ *X*w, also ⊕ *X*d with a device |
| 42 | 16 | *h* |
| 58 | 4 | check: the first 4 bytes of MAC(*h* ‖ *p* ‖ 0¹², *K*) |

**Words.** *X*w's 288 bits, most significant first, then the top 9 bits of its CRC-16/CCITT-FALSE,
read as 27 indices of 11 bits each into the BIP-39 English word list.

**Recovery.** XOR the payload's *C* field with *X*w (and *X*d). Accept the first 32 bytes as *K* only
if the check matches, compared in constant time. Every wrong factor fails the same way.

**Forging.** A forged key is never computed. Draw the payload's 36-byte factor field *X*s and *X*w
at random; *C* = *X*s ⊕ *X*w is only implied. The check is the first 4 bytes of
POLYVAL(*h*, *X*s[0..32] ‖ *len*) ⊕ POLYVAL(*h*, *X*w[0..32] ‖ 0¹⁶), XORed with *X*s[32..36] and
*X*w[32..36]. By linearity it equals the check of *C*, so recovery treats forged and composed keys
alike.

## Device factor

A device turns a noisy physical response *w* of 504·*c* bits into a 36-byte factor. Its public
helper data:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `VFZX` |
| 4 | 1 | version = 1 |
| 5 | 1 | *e*: claimed min-entropy per response bit, in 1/256ths |
| 6 | 1 | *c*: chunks |
| 7 | 1 | 0 |
| 8 | 80 | extractor seed *s* |
| 88 | 63*c* | offsets, 3 bytes per block |

1. **Blocks.** Each 504-bit chunk holds 21 blocks. Block *j* takes chunk bits *j*, *j* + 21, …,
   *j* + 483, reading bits most significant first within each byte.
2. **Code.** The extended binary Golay code [24, 12, 8], with generator matrix [I | B]. The first 11
   rows of B are left rotations of 11011100010 with a 1 appended; the last row is eleven 1s, then 0.
3. **Enroll.** Each block's offset is the block XOR the codeword of a random 12-bit message.
4. **Reproduce.** Decode each fresh block XOR its offset to the nearest codeword (up to 3 errors),
   then XOR the offset back in to recover the enrolled block.
5. **Extract.** Each chunk, padded with 8 zero bits, goes through a Toeplitz extractor with seed *s*:
   output bit *i* is the XOR over *j* of seed bit *i* − *j* + 511 AND input bit *j*, both counted
   least significant first. Its output length is *m* = min(128, *k* − 128) bits, rounded down to a
   multiple of 8, where *k* = ⌊504*e* / 256⌋ − 252. The factor is the first 36 bytes of the outputs
   in order, and *c* is the fewest chunks that fill it.

## Guarantees

- **Secrecy.** For any *k* − 1 shares, the *y* bytes are a one-to-one image of the random coefficients,
  so they are uniform whatever *S* is. Keys are independent random bytes, and each tag is masked by
  its own pad. Fewer than *k* shares reveal only *k*, *n*, the epoch and the set ID.
- **Integrity.** If any byte of a share's body has been changed, each unchanged verifier rejects that
  share, except with probability at most (⌈|body| / 16⌉ + 1) / 2¹²⁸ < 2⁻¹¹⁸.
  This needs at least one unchanged share among those presented. A complete forged set of *k* shares
  can only be told apart from the real one by its set ID, so record the set ID away from the shares.
- **Refresh.** The new *y* values lie on a fresh random curve with the same constant term, independent
  of the old one. Someone who holds fewer than *k* shares of every single epoch learns nothing, even
  with shares from many epochs, as long as no mask survives. Any *k* shares of one epoch still rebuild
  *S*, so old shares must be destroyed. The dealer is trusted to destroy the masks. A doctored keycard
  or mask cannot make a forged share pass: without the right hash key it only breaks tags, which the
  next check reports.
- **Hash keys are permanent.** Refresh replaces pads, not hash keys. Someone who once read share *i*'s
  keys and later holds share *j* can forge *j*'s tag towards *i*. Recovery stays safe while at least
  one presented verifier's keys were never exposed. Combining and re-splitting replaces every key.
- **Composed keys.** Every key fits the payload for some choice of words, so the shares (all of them
  together) say nothing about *K*. The check is masked by *p*, which lives inside *C*.
- **Device factor.** If each response bit holds at least *e*/256 bits of min-entropy, each chunk's
  output is within 2^-((*k* − *m*) / 2) of uniform given the helper data. A response too noisy to
  decode gives a wrong factor, never an error, so decoding is not an oracle. Whether a whole recovery
  succeeds is still observable, so helper data must be protected from tampering wherever an attacker
  can also watch recoveries.
- **Not covered:** the device that does the recovery, and the people who hold the shares.
