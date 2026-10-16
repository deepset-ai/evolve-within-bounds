# Data

What is shipped here and what is fetched:

- `primevul/`: pair-id manifests only (loop train and validation, the 400-pair dev set, the test subset), with the
  upstream version and checksums. The functions themselves are fetched from the PrimeVul release by
  `scripts/data/`. Nothing from the PrimeVul test split is published beyond its pair ids.
- `synthetic-components/`: synthetic Haystack custom components with ground-truth labels, and a datasheet describing
  how they were generated. They contain no customer code.
- Knowledge base (CWE, NVD, ExploitDB): built by `scripts/data/` from the public sources, not shipped.
