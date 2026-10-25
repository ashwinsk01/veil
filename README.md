# Veil

Stage 1 of a long-term vault for one small file (up to 10,240 bytes). The file is split into *n*
shares. Any *k* of them rebuild it, and fewer reveal nothing, however much computing power an attacker
has. The byte format is in [SPEC.md](SPEC.md).

## Use

```sh
cargo build --release
B=./target/release/veil

$B split secret.txt -o e0/                 # 3-of-5 by default; -k and -n to change
$B check e0/*-2of5.veil e0/*-4of5.veil     # cross-checks shares, rebuilds nothing
$B refresh e0/*.veil -o e1/                # every share moves to epoch 1
$B combine e1/*-1of5.veil e1/*-3of5.veil e1/*-5of5.veil -o recovered.txt
```

`refresh` needs every share in one place. To refresh with the shares kept apart:

```sh
$B keycard my-share.veil                  # each vault: 92 bytes, no share data; send it to the dealer
$B deal *.veilkey                         # the dealer: one mask per vault; send each to its own vault
$B apply my-share.veil my-share.veilmask  # each vault: writes its next-epoch share
```

Record the set ID that `split` prints somewhere separate from the shares. `combine` prints it again,
so you can confirm you recovered the right set.

After a refresh, destroy the old shares. Until they're gone, any *k* of them still rebuild the file.

## Randomness

Every guarantee rests on the random bytes being uniform. By default they come from the OS generator,
which is computational. To remove that assumption, feed in a hardware noise source:

```sh
$B seed -o seed.txt < rolls.txt          # once: 272 rolls of a fair die. The seed is public
$B split secret.txt --entropy /dev/cu.usbmodem1 --min-entropy 7 --seed seed.txt
```

`split`, `refresh` and `deal` all take these flags. The raw noise goes through three layers:

1. **Health tests.** NIST SP 800-90B's repetition count and adaptive proportion tests, with a 2⁻³⁰
   false alarm rate, stop everything if the device sticks or loses its entropy.
2. **Extraction.** A Toeplitz matrix turns each 64-byte raw block into up to 16 bytes within 2⁻⁶⁴ of
   uniform or better, by the Leftover Hash Lemma. The seed fixes the matrix. It can be public and
   reused, but it must be uniform and independent of the noise, so it comes from dice.
3. **Mixing.** The result is XORed with the OS generator, so a broken source can never make things
   worse.

After each operation, `veil` prints what the randomness rested on and the bound it achieved.

Health tests catch broken devices, not clever fakes, and `--min-entropy` is a claim about the physics
of your device. Use the figure from its documentation or from NIST's SP 800-90B assessment tool on a
raw sample, and go lower when unsure: it only costs speed. `--entropy` reads raw bytes from any device,
pipe or capture file. Never feed it the same capture twice.

## What is proven and what is assumed

| Property | Basis |
|---|---|
| Fewer than *k* shares reveal nothing | Information-theoretic (Shamir). Checked by exhaustive enumeration for *k* = 2 and *k* = 3 over every index pair |
| Altered shares are caught and named | Information-theoretic one-time POLYVAL tags between every pair of shares. Forgery chance below 2⁻¹¹⁸ per check |
| Refresh never rebuilds the file | The masks are dealt from hash keys alone: `deal` never receives share data. Each share is then XORed with its own mask. Dealing from keycards gives byte-for-byte the same masks as dealing from the shares |
| Old and new shares don't combine | Each refresh puts the shares on a fresh random curve. Checked exhaustively for one old plus one new share at *k* = 2 |
| Field arithmetic is correct | All 65,536 products checked against an independent reference |
| Secrets stay out of swap and crash dumps | Memory pinned with `mlock` and zeroed after use, core dumps disabled, debugger attachment blocked |
| Randomness is uniform | With `--entropy` and a dice seed, no computational assumption remains: the output is within a stated distance of uniform. The extractor is checked exhaustively for the universal property the proof needs, and the health test cutoffs match NIST's published table |
| **The source delivers its declared min-entropy** | **Physical assumption.** Software can't verify it; it's a claim about the device. Without `--entropy`, the OS generator alone is used, and the assumption is computational instead |
| **The dealer is trusted** | **Known limit.** The dealer could keep the masks, and with them later convert stolen old shares to the current epoch. It must destroy them |
| **Hash keys never change** | **Known limit.** Refresh replaces pads but keeps hash keys, so someone who once read a share's keys can later forge tags towards it. Combining and re-splitting replaces them |

## Layout

- `veil-core/`: the scheme, the extractor and the health tests. `no_std`, no `unsafe`, builds for
  bare-metal RISC-V
  (`cargo build -p veil-core --target riscv32imac-unknown-none-elf`).
- `veil-cli/`: the `veil` command. All `unsafe` code is in `src/harden.rs`.

## Not done yet

- A run with a real hardware noise source. So far the hardware path has only seen simulated noise
- Kani proofs for the parsing code
- Stage 2 (bare-metal RISC-V on an FPGA) and stage 3 (recovery in fixed logic, no CPU)
