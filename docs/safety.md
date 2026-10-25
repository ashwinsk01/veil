# Using Veil safely

The math holds whatever an attacker can compute. What remains is the room, the paper and the people.
One rule covers most of it: **no single person, building, account, company or government should
ever be able to reach everything the secret needs**: *k* shares, plus your words for a composed key.
Everything below applies that rule to one step at a time.

## Checklist

**The machine**

- [ ] Run `split`, `combine`, `compose`, `forge`, `recover` and `write` on an offline machine you
  trust, ideally booted fresh from a live USB. Veil keeps its memory out of swap and crash dumps and
  blocks debuggers, but malware on the same machine sees whatever Veil sees.
- [ ] Build from source you have read, with the committed `Cargo.lock`:
  `cargo build --release --locked`.
- [ ] Keep secrets and shares out of synced and backed-up folders: iCloud Desktop & Documents,
  Dropbox, Time Machine, snapshots. Work on a RAM disk, which disappears at power-off:

  ```sh
  diskutil erasevolume HFS+ veil-ram $(hdiutil attach -nomount ram://65536)   # macOS, 32 MB
  ```

  On Linux, use a `tmpfs` mount on a machine whose swap is off or encrypted.

**Splitting**

- [ ] Prefer `write` or `forge`, so the secret never exists as a file. `split` needs a file, and
  deleting a file from flash storage doesn't reliably erase it, so keep that file on the RAM disk.
- [ ] `split` writes all *n* shares into one folder, which therefore holds the secret. Put that
  folder on the RAM disk, copy each share to its own medium, then power off.
- [ ] Choose *k* as the number of holders a thief must reach, and *n* − *k* as the number of shares
  you can afford to lose.
- [ ] Before any share leaves the room, run `veil check` on all of them. For a composed or forged
  key, also prove that you wrote the words down correctly: `veil recover … -o - > /dev/null` exits
  with 0 only if the shares and words combine. The key goes nowhere.
- [ ] Record the set ID that Veil prints, away from the shares.

**Your words** (`compose` and `forge`)

- [ ] Write them on paper or stamp them in metal. Never type them into a phone, a photo, a password
  manager or a cloud note.
- [ ] Words alone reveal nothing, so a second copy in another place is safe, as long as no copy ever
  sits alongside *k* shares. Losing every copy loses the key for good.
- [ ] With `--polyglot`, set up Tamil, Hindi and Russian keyboards on the machine you'll recover
  on, and practise typing there first: `recover` hides what you type.
- [ ] Let the words print only to the terminal. Veil refuses to send them to a file or pipe unless
  you pass `--words-off-screen`, but the terminal itself keeps them: clear the scrollback afterwards
  (⌘K in macOS Terminal), and don't run inside a session recorder, `script` or a logging `tmux`.

**Typing** (`write`)

- [ ] Make sure no camera can see the screen; the keys alone give nothing away. Add pad cells if the
  length of the secret matters.

**Randomness** (`--entropy`)

- [ ] `--min-entropy` is a claim about the physics of your device. Use the figure from its
  documentation or from NIST's SP 800-90B assessment tool on a raw sample, and go lower when unsure:
  it only costs speed.
- [ ] Never feed the same capture to `--entropy` twice.

**Holding shares**

- [ ] One share per holder. Choose holders who wouldn't collude, can't be pressured together, and
  ideally don't live under the same jurisdiction.
- [ ] A share file is not encrypted: whoever reads *k* of them has the secret. Store each one on its
  own medium. Email and cloud storage are acceptable only if no single provider or account ever
  holds *k* shares.
- [ ] Each holder keeps two copies on different media, and checks once a year that they still read.

**Refreshing**

- [ ] Refresh when a holder leaves, when a share may have been copied, and once a year anyway.
- [ ] A refresh only helps once every old share, keycard and mask is destroyed, everywhere. Until
  then, any *k* old shares still rebuild the file. On flash storage, destroying them means
  physically destroying the media.
- [ ] Refresh needs every share. If one is lost, rebuild and split into a new set instead: `combine`
  then `split`, or for a composed key, `recover` then `compose --key`.
- [ ] If a share file was ever read by someone else, a refresh restores secrecy but not full tamper
  protection: the hash keys inside it survive refreshes, so that reader could later forge a share
  that passes its checks. Rebuild and split into a new set to replace them.
- [ ] If *k* shares of one epoch were ever exposed together, the secret is out for good.

**Recovering**

- [ ] Use the same kind of offline machine. Write the output to the RAM disk, or with `-o -`
  straight into the program that needs it.
- [ ] Present every share you can gather, not just *k*. Any genuine share among them exposes a
  forged one. Then check that the set ID matches your record.
- [ ] Power off when done.

## What Veil can't hide

- **The length of a typed secret.** Anyone counting key presses during `write` learns how many
  characters you typed. Pad cells can disguise it.
- **Screen and keys together.** A camera that sees both, or malware on the same machine, can match
  the shuffled keypad to your key presses.
- **Human-chosen text.** If you choose the words, they may be guessable wherever they're used. When
  a secret doesn't have to be your own words, `forge` is stronger: there's nothing to type.
- **The forging machine.** `forge` never computes the key, but the machine sees both parts while it
  shows you the words, so the key is computable there. Making even that impossible needs the shares
  to be born on separate devices.
- **Clever fake noise.** Health tests catch a noise source that is stuck or broken, not one built
  to look random.
- **A device that leaks success.** The device factor never reports a decoding failure, but whether a
  recovery succeeds is still visible. Someone who can alter the helper data *and* watch recoveries
  learns about the chip a little at a time, so a device must keep its helper data inside its tamper
  boundary and limit failed attempts.
