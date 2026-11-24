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
