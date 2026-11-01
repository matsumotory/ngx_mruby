// Keep both search dialogs on the same explicit Pagefind ranking.
// These are the Starlight 0.42.6 defaults, not Pagefind UI defaults.
export const pagefindOptions = {
  ranking: { pageLength: 0.1, termFrequency: 0.1, termSaturation: 2, termSimilarity: 9, diacriticSimilarity: 0.8 },
};
