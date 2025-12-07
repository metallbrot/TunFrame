def true_positive_rate(tp, fn):
    if tp == 0:
        return 0
    return tp / (tp + fn)


def false_positive_rate(fp, tn):
    if fp == 0:
        return 0
    return fp / (fp + tn)
