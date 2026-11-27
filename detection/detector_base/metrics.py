"""Rate helpers for the confusion matrix; both return 0 when undefined."""


def true_positive_rate(tp, fn):
    """TP / (TP + FN), the recall."""
    if tp + fn == 0:
        return 0
    return tp / (tp + fn)


def false_positive_rate(fp, tn):
    """FP / (FP + TN)."""
    if fp + tn == 0:
        return 0
    return fp / (fp + tn)
