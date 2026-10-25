// Turns curated picks into a final 2,048-word list for one language, and reports what each rule
// cost. A word survives only if it is attested in the corpora, stays distinct from every more
// common word after folding the letters people confuse, and is identified by its first `prefix`
// letters (0: typed whole). Words two edits from every other are preferred; one-edit neighbours
// only fill the list if it would otherwise fall short. The folding must match veil-core's, whose
// tests check the final lists again.
// usage: node filter.mjs <dir with pools/ and picks/> <ta | hi | ru> <prefix letters> [--report-only]
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [DIR, LANG, PREFIX_ARG, ...flags] = process.argv.slice(2);
const PREFIX = Number(PREFIX_ARG);
const TARGET = 2048;

const SCRIPT = {
  ru: /^[а-яё]+$/u,
  hi: /^[ऀ-ॣॱ-ॿ]+$/u,
  ta: /^[ஂஃஅ-஛ஞ-வா-்ௗ]+$/u,
}[LANG];
const LENGTH = { ru: [3, 8], hi: [2, 8], ta: [2, 8] }[LANG];

const DEVANAGARI_CONSONANT = /[क-ह]/u;
/** The matching key: the word with every letter people commonly confuse folded together. */
function fold(word) {
  if (LANG === 'ru') return word.replaceAll('ё', 'е');
  if (LANG === 'ta') {
    return word.replace(/[ளழ]/gu, 'ல').replace(/ற/gu, 'ர').replace(/[ணந]/gu, 'ன');
  }
  // Hindi: nukta dropped, chandrabindu as anusvara, a half nasal before a consonant as anusvara,
  // long and short i and u as one, and ष as श.
  let w = word.normalize('NFD').replaceAll('़', '').replaceAll('ँ', 'ं');
  const cps = [...w];
  const out = [];
  for (let i = 0; i < cps.length; i++) {
    const nasal = 'ङञणनम'.includes(cps[i]);
    if (nasal && cps[i + 1] === '्' && DEVANAGARI_CONSONANT.test(cps[i + 2] ?? '')) {
      out.push('ं');
      i++;
      continue;
    }
    out.push(cps[i]);
  }
  return out
    .join('')
    .replaceAll('ी', 'ि')
    .replaceAll('ू', 'ु')
    .replaceAll('ई', 'इ')
    .replaceAll('ऊ', 'उ')
    .replaceAll('ष', 'श')
    .normalize('NFC');
}

function distance(a, b) {
  const x = [...a];
  const y = [...b];
  if (Math.abs(x.length - y.length) > 1) return 2; // only "below 2" matters here
  let prev = Array.from({ length: y.length + 1 }, (_, j) => j);
  for (let i = 1; i <= x.length; i++) {
    const cur = [i];
    for (let j = 1; j <= y.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (x[i - 1] === y[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[y.length];
}

const attested = new Map();
for (const line of readFileSync(join(DIR, 'pools', `${LANG}.attested.tsv`), 'utf8').split('\n')) {
  const [w, s] = line.split('\t');
  if (w) attested.set(w, Number(s));
}
const score = (w) => Math.max(attested.get(w) ?? 0, LANG === 'ru' ? attested.get(w.replaceAll('ё', 'е')) ?? 0 : 0);

const rejects = new Map();
const reject = (why, w, detail = '') => {
  if (!rejects.has(why)) rejects.set(why, []);
  rejects.get(why).push(detail ? `${w} (${detail})` : w);
};

const readPicks = (name) => {
  try {
    return readFileSync(join(DIR, 'picks', name), 'utf8').split('\n');
  } catch {
    return [];
  }
};
const picks = [
  ...new Set(
    [...readPicks(`${LANG}.txt`), ...readPicks(`${LANG}.extra.txt`)]
      .map((l) => l.trim().normalize('NFC'))
      .filter(Boolean),
  ),
];
let words = [];
for (const w of picks) {
  const n = [...w].length;
  if (!SCRIPT.test(w)) reject('outside the script', w);
  else if (n < LENGTH[0] || n > LENGTH[1]) reject('too short or long', w);
  else if (!score(w)) reject('not attested in the corpora', w);
  else words.push({ w, key: fold(w), s: score(w) });
}
words.sort((a, b) => b.s - a.s);

// Folded twins and shared prefixes are hard rules. Two edits of distance is kept wherever the
// list stays full without it; only if it would fall short do one-edit neighbours fill the gap,
// most common first, as BIP-39 English also has (wife, wine, wire, wise).
const kept = [];
const byKey = new Map();
const byPrefix = new Map();
const near = [];
const prefixOf = (key) => (PREFIX ? [...key].slice(0, PREFIX).join('') : key);
const admit = (word, checkDistance) => {
  const twin = byKey.get(word.key);
  if (twin) return reject('same as a more common word once folded', word.w, twin.w);
  const clash = byPrefix.get(prefixOf(word.key));
  if (clash) return reject(`same first ${PREFIX} letters as a more common word`, word.w, clash.w);
  if (checkDistance) {
    const neighbour = kept.find((k) => distance(k.key, word.key) < 2);
    if (neighbour) return near.push(word);
  }
  kept.push(word);
  byKey.set(word.key, word);
  byPrefix.set(prefixOf(word.key), word);
};
for (const word of words) admit(word, true);
const strict = kept.length;
for (const word of near) {
  if (kept.length >= TARGET) {
    reject('one edit from a more common word', word.w);
    continue;
  }
  admit(word, false);
}
kept.sort((a, b) => b.s - a.s);

const entry = PREFIX ? `${PREFIX}-letter prefixes` : 'whole words';
console.log(`${LANG}: ${picks.length} picks, ${words.length} valid, ${strict} distinct by two edits, ${kept.length} with fill (${entry})`);
const top = kept.slice(0, TARGET);
const closeInTop = top.filter((a) => top.some((b) => a !== b && distance(a.key, b.key) < 2)).length;
console.log(`  in the final ${top.length}: ${closeInTop} words have a one-edit neighbour`);
for (const [why, list] of rejects) console.log(`  ${list.length.toString().padStart(5)} ${why}: ${list.slice(0, 6).join(', ')}`);
if (kept.length < TARGET) console.log(`  SHORT by ${TARGET - kept.length}`);
if (!flags.includes('--report-only')) {
  const final = kept.slice(0, TARGET).map((k) => k.w).sort();
  mkdirSync(join(DIR, 'final'), { recursive: true });
  writeFileSync(join(DIR, 'final', `${LANG}.txt`), final.join('\n') + '\n');
  writeFileSync(join(DIR, 'final', `${LANG}.rejects.txt`), [...rejects].map(([why, l]) => `# ${why}\n${l.join('\n')}`).join('\n\n') + '\n');
  console.log(`  wrote ${final.length} words; least common kept: ${kept[Math.min(TARGET, kept.length) - 1]?.w} (${kept[Math.min(TARGET, kept.length) - 1]?.s.toFixed(2)} ppm)`);
}
