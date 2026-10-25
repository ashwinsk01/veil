# Word lists

How the Tamil, Hindi and Russian lists in `veil-core/src/words/` were made, and how to make them
again. With the BIP-39 English list, unchanged, they spell a factor in 23 words (`--polyglot`).

## Rules

1. **Candidates.** `picks/` holds each language's candidates: dictionary forms that are common,
   concrete where possible, and easy to picture. No proper nouns, no rival spellings of one word,
   nothing offensive. They were drafted with a language model's help.
2. **Attested.** Every word must appear in the frequency lists below. Words are ranked by the
   geometric mean of their frequency per million across those lists, so that they are common in
   both speech (film subtitles) and writing (Wikipedia, news).
3. **Folded.** Letters people confuse count as one: Tamil ல ள ழ, ர ற and ண ந ன; Hindi with or
   without nukta, chandrabindu or anusvara, a half nasal or an anusvara, long or short i and u,
   and ष or श; Russian ё or е. Of two words that fold alike, only the more common one stays.
4. **Typed.** Russian words have unique first four letters, as BIP-39 English words do. Tamil and
   Hindi words are typed whole: a letter there is often several code points (प्र is three), so
   short prefixes don't tell words apart.
5. **Apart.** Words two edits from every other word are preferred. One-edit neighbours fill a list
   only if it would otherwise fall short, most common first.

| List | Picks | Attested | Two edits apart | Final words with a one-edit neighbour |
|---|---|---|---|---|
| Tamil | 2,201 | 2,181 | 1,498 | 988 |
| Hindi | 2,538 | 2,534 | 1,863 | 400 |
| Russian | 2,711 | 2,576 | 2,337 | 0 |
| English (BIP-39) | | | | 749 |

Each list keeps the 2,048 most common survivors, sorted by code point. A one-letter typo that lands
on another word is still caught by the checksum, except about once in 2,048.

## Sources

Only the selection of words is shipped. None of the corpora is redistributed.

- Film subtitles: [FrequencyWords](https://github.com/hermitdave/FrequencyWords) by Hermit Dave,
  built from [OpenSubtitles](https://www.opensubtitles.org) 2018: `ru/ru_50k.txt`,
  `hi/hi_full.txt` and `ta/ta_full.txt`.
- Wikipedia and news: the
  [Leipzig Corpora Collection](https://wortschatz.uni-leipzig.de/en/download) (D. Goldhahn,
  T. Eckart and U. Quasthoff, *Building Large Monolingual Dictionaries at the Leipzig Corpora
  Collection: From 100 to 200 Languages*, LREC 2012): `tam_wikipedia_2021_300K`,
  `hin_wikipedia_2021_300K`, `hin_news_2020_300K` and `rus_wikipedia_2021_300K`.

## Rebuilding

Needs Node 18 or later.

```sh
cd experiments/wordlists
mkdir data
for f in ru/ru_50k.txt hi/hi_full.txt ta/ta_full.txt; do
  curl -fL -o "data/subs_$(basename $f)" \
    "https://raw.githubusercontent.com/hermitdave/FrequencyWords/master/content/2018/$f"
done
for c in tam_wikipedia_2021_300K hin_wikipedia_2021_300K hin_news_2020_300K \
         rus_wikipedia_2021_300K; do
  curl -fL "https://downloads.wortschatz-leipzig.de/corpora/$c.tar.gz" |
    tar -xzOf - "$c/$c-words.txt" > "data/wiki_$c.txt"
done
node pool.mjs data pools
node filter.mjs . ta 0
node filter.mjs . hi 0
node filter.mjs . ru 4
```

`final/ta.txt`, `final/hi.txt` and `final/ru.txt` then match `tamil.txt`, `hindi.txt` and
`russian.txt` byte for byte. `final/*.rejects.txt` lists every word left out and why.
`cargo test -p veil-core` checks the lists again with Veil's own folding.
