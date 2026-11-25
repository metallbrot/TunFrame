def true_positive_rate(tp, fn):
    if tp + fn == 0:
        return 0
    return tp / (tp + fn)


def false_positive_rate(fp, tn):
    if fp + tn == 0:
        return 0
    return fp / (fp + tn)
