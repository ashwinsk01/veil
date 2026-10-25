// Builds a ranked pool of candidate words per language from real frequency lists.
// A word's score is the geometric mean of its frequency per million across corpora, so words
// common in both speech (subtitles) and writing (Wikipedia, news) rise to the top.
// usage: node pool.mjs <data dir> <out dir>
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [DATA, OUT] = process.argv.slice(2);

const LANGS = {
  ru: {
    script: /^[а-яё]+$/u,
    corpora: [['subs_ru_50k.txt', 'subs'], ['wiki_rus_wikipedia_2021_300K.txt', 'leipzig']],
    len: [3, 9],
    pool: 10000,
  },
  hi: {
    // Devanagari letters and signs, without digits, danda or abbreviation marks.
    script: /^[ऀ-ॣॱ-ॿ]+$/u,
    corpora: [
      ['subs_hi_full.txt', 'subs'],
      ['wiki_hin_wikipedia_2021_300K.txt', 'leipzig'],
      ['wiki_hin_news_2020_300K.txt', 'leipzig'],
    ],
    len: [2, 10],
    pool: 8000,
  },
  ta: {
    // Tamil letters and signs, without Grantha letters (ஜ ஶ ஷ ஸ ஹ), whose spellings vary.
    script: /^[ஂஃஅ-஛ஞ-வா-்ௗ]+$/u,
    corpora: [['subs_ta_full.txt', 'subs'], ['wiki_tam_wikipedia_2021_300K.txt', 'leipzig']],
    len: [2, 10],
    pool: 14000,
    minSeen: 1,
  },
};

const FLOOR = 0.5; // per million, for a word missing from a corpus

mkdirSync(OUT, { recursive: true });

for (const [lang, cfg] of Object.entries(LANGS)) {
  const ppm = []; // one Map per corpus
  for (const [file, kind] of cfg.corpora) {
    const counts = new Map();
    let total = 0;
    for (const line of readFileSync(join(DATA, file), 'utf8').split('\n')) {
      if (!line) continue;
      let word, n;
      if (kind === 'subs') [word, n] = line.split(' ');
      else [, word, n] = line.split('\t');
      n = Number(n);
      if (!word || !Number.isFinite(n)) continue;
      total += n;
      word = word.normalize('NFC');
      if (!cfg.script.test(word)) continue;
      counts.set(word, (counts.get(word) ?? 0) + n);
    }
    const m = new Map();
    for (const [w, n] of counts) m.set(w, (n / total) * 1e6);
    ppm.push(m);
  }
  const words = new Set(ppm.flatMap((m) => [...m.keys()]));
  const scored = [];
  for (const w of words) {
    const cps = [...w].length;
    if (cps < cfg.len[0] || cps > cfg.len[1]) continue;
    const logs = ppm.map((m) => Math.log(Math.max(m.get(w) ?? 0, FLOOR)));
    const seen = ppm.filter((m) => m.has(w)).length;
    if (seen < (cfg.minSeen ?? 2)) continue; // attested in enough corpora
    scored.push([w, Math.exp(logs.reduce((a, b) => a + b, 0) / logs.length)]);
  }
  scored.sort((a, b) => b[1] - a[1]);
  // every attested form, for verifying dictionary forms that the pool only holds inflected
  const all = [...words].map((w) => [w, Math.exp(ppm.map((m) => Math.log(Math.max(m.get(w) ?? 0, FLOOR))).reduce((a, b) => a + b, 0) / ppm.length)]);
  writeFileSync(join(OUT, `${lang}.attested.tsv`), all.map(([w, s]) => `${w}\t${s.toFixed(3)}`).join("\n") + "\n");
  const pool = scored.slice(0, cfg.pool);
  writeFileSync(join(OUT, `${lang}.tsv`), pool.map(([w, s], i) => `${i + 1}\t${w}\t${s.toFixed(2)}`).join('\n') + '\n');
  console.log(`${lang}: ${scored.length} kept, pool ${pool.length}, last score ${pool.at(-1)[1].toFixed(2)} ppm`);
}
