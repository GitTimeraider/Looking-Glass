"""A small Isolation Forest (Liu, Ting & Zhou 2008) in plain Python - no numpy / scikit-learn needed.

Anomalies are few and different, so random axis-aligned splits isolate them in fewer steps than normal points. The
score is 2^(-E[path length] / c(n)): about 0.5 for ordinary points, towards 1.0 for anomalies. The data sets here are
small (devices × hours), so a pure Python implementation is fast enough.
"""
from __future__ import annotations

import math
import random
from typing import Sequence

Vector = Sequence[float]


def _c(n: int) -> float:
    """Average path length of an unsuccessful search in a binary search tree of n points."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1) + 0.5772156649) - 2.0 * (n - 1) / n


class _Node:
    __slots__ = ("feature", "split", "left", "right", "size")

    def __init__(self, size: int, feature: int = -1, split: float = 0.0, left: "_Node | None" = None,
                 right: "_Node | None" = None) -> None:
        self.size, self.feature, self.split, self.left, self.right = size, feature, split, left, right


def _grow(rows: list[Vector], depth: int, limit: int, rnd: random.Random) -> _Node:
    if depth >= limit or len(rows) <= 1:
        return _Node(len(rows))
    dims = len(rows[0])
    features = [f for f in range(dims) if min(r[f] for r in rows) < max(r[f] for r in rows)]
    if not features:
        return _Node(len(rows))
    f = rnd.choice(features)
    lo, hi = min(r[f] for r in rows), max(r[f] for r in rows)
    split = rnd.uniform(lo, hi)
    left = [r for r in rows if r[f] < split]
    right = [r for r in rows if r[f] >= split]
    return _Node(len(rows), f, split, _grow(left, depth + 1, limit, rnd), _grow(right, depth + 1, limit, rnd))


def _path(node: _Node, x: Vector, depth: int = 0) -> float:
    while node.feature >= 0:
        node = node.left if x[node.feature] < node.split else node.right  # type: ignore[assignment]
        depth += 1
    return depth + _c(node.size)


class IsolationForest:
    def __init__(self, trees: int = 100, sample: int = 256, seed: int = 42) -> None:
        self.trees, self.sample, self.seed = trees, sample, seed
        self._roots: list[_Node] = []
        self._n = 0

    def fit(self, rows: list[Vector]) -> "IsolationForest":
        rnd = random.Random(self.seed)
        self._n = min(self.sample, len(rows))
        limit = math.ceil(math.log2(max(self._n, 2)))
        self._roots = [_grow(rnd.sample(rows, self._n), 0, limit, rnd) for _ in range(self.trees)] if rows else []
        return self

    def score(self, x: Vector) -> float:
        """0..1, higher = more isolated. Compare with the scores of the training data (percentile), not a fixed cut."""
        if not self._roots:
            return 0.0
        mean = sum(_path(t, x) for t in self._roots) / len(self._roots)
        return 2.0 ** (-mean / _c(self._n)) if self._n > 1 else 0.0


class SubspaceForest:
    """One small Isolation Forest per pair of features; the score of a point is the highest pair score.

    A plain Isolation Forest is weak when only one or two of many features are unusual (most random splits use the
    other features). Per feature pair, an extreme value in one feature - or an odd combination of two - is isolated
    quickly, and the maximum keeps that signal. ``explain`` names the pair that scored highest."""

    def __init__(self, trees: int = 30, sample: int = 256, seed: int = 42) -> None:
        self.trees, self.sample, self.seed = trees, sample, seed
        self._forests: list[tuple[tuple[int, int], IsolationForest]] = []

    def fit(self, rows: list[Vector]) -> "SubspaceForest":
        dims = len(rows[0]) if rows else 0
        pairs = [(a, b) for a in range(dims) for b in range(a + 1, dims)] or ([(0, 0)] if dims == 1 else [])
        self._forests = [((a, b), IsolationForest(self.trees, self.sample, self.seed + i).fit([(r[a], r[b]) for r in rows]))
                         for i, (a, b) in enumerate(pairs)]
        return self

    def score(self, x: Vector) -> float:
        return max((f.score((x[a], x[b])) for (a, b), f in self._forests), default=0.0)

    def explain(self, x: Vector) -> tuple[int, int]:
        return max(self._forests, key=lambda p: p[1].score((x[p[0][0]], x[p[0][1]])))[0] if self._forests else (0, 0)
