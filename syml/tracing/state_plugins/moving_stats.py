from collections import deque
from decimal import Decimal
from functools import reduce
from math import sqrt

import angr


class MovingStats(angr.SimStatePlugin):
    """
    for ast in _constraints[len(parent.constraints.reduced):]:
    parent.constraints.append(ast, reduce_ast(ast))
    """

    def __init__(self, clone=None, dtype=Decimal, keep=3, init=1):
        super(MovingStats, self).__init__()
        self.dtype = dtype
        self.history = deque([float(init)] * keep, keep) if clone is None else clone.history.copy()
        self.n = dtype(0) if clone is None else clone.n
        self.m = dtype(0) if clone is None else clone.m
        self.M2 = dtype(0) if clone is None else clone.M2

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return MovingStats(clone=self)

    def update(self, value):
        # Initialize.
        value = self.dtype(value)
        self.n = self.n + 1

        # Update current value
        self.history.append(float(value))

        if self.n <= 1:
            # First update.
            self.m = value
            self.M2 = self.dtype(0)
            self.n = self.dtype(1)
            return

        # No update.
        delta = value - self.m
        if delta == 0:
            return

        # Update running moments.
        self.m = self.m + delta / self.n

        if self.n > 1:
            self.M2 = self.M2 + delta * (value - self.m)
        return

    @property
    def count(self):
        return float(self.n)

    @property
    def mean(self):
        return float(self.m)

    @property
    def var(self):
        if self.n == 0:
            return 0
        elif self.n > 2:
            return self.M2 / (self.n - 1)
        return float(self.M2 / self.n)

    @property
    def std(self):
        return float(sqrt(self.var))

    @property
    def trend(self):
        return sum(self.history) / len(self.history)

    @property
    def trend_mul(self):
        return reduce((lambda x, y: x * y), self.history)
