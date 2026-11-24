# Behavior changes

Every change that alters a reported number or the way a run behaves, with the
old and the new definition. This file is the basis for the thesis erratum.
Entries are added in the commit that introduces the change.

## M1: True negatives exclude false negatives

- **Old**: `TN = all_domains - TP - FP`. A missed tunneling domain was counted
  as FN and as TN at the same time, so TP+FP+TN+FN exceeded the number of
  domains by the number of FNs.
- **New**: `TN = all_domains - TP - FP - FN`. Every registered domain falls into
  exactly one confusion-matrix class.
- **Affected outputs**: `tn`, `accuracy`, `fpr` (denominator FP+TN shrinks by
  |FN|). TP, FP, FN, precision and recall are unchanged.

## M2: FPR universe is the wartime window only

- **Old**: In replay (standard) mode, `main()` passed the set of domains seen
  during peacetime into the wartime evaluation, so peacetime-only domains were
  counted as TN. In DNSExfiltrator mode each config started from an empty set.
  The two modes therefore used different FPR denominators, and replay-mode FPR
  was deflated whenever peacetime was enabled.
- **New**: `run_wartime()` always builds the domain universe from the lines of
  its own window. TN, FPR, accuracy and `unique_domains` refer only to
  registered domains seen during that wartime (or that config's wartime) in
  both modes. The `alldomains` parameter of `run_wartime()` was removed.
- **Affected outputs**: `tn`, `fpr`, `accuracy`, `total_unique_domains`,
  `dataset_statistics.unique_domains` in replay mode with peacetime > 0.
