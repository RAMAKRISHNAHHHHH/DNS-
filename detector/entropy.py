import math
from collections import Counter

def shannon_entropy(value):
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return round(-sum((c/n) * math.log2(c/n) for c in counts.values()), 3)
