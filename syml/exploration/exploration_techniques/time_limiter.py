import time
import math

from angr.exploration_techniques import ExplorationTechnique


class TimeLimiter(ExplorationTechnique):
    def __init__(self, timeout=math.inf, allowed_steps=math.inf):
        super(TimeLimiter, self).__init__()
        self.timeout = timeout
        self.allowed_time = time.time() + self.timeout
        self.allowed_steps = allowed_steps

    def setup(self, simgr):
        super(TimeLimiter, self).setup(simgr)
        simgr.populate('stuck', [])

    def step(self, simgr, stash="active", **kwargs):
        # un-stuck all states
        simgr.move(from_stash="stuck", to_stash='deferred')

        if len(simgr.active) == 1 and self.limit_hit:
            if len(simgr.stashes['deferred']) > 0:
                self.reset_limit()
                simgr.move(from_stash="active", to_stash='stuck')
        elif len(simgr.active) == 1:
            self.allowed_steps -= 1

        simgr = simgr.step(stash=stash, **kwargs)
        return simgr

    @property
    def limit_hit(self):
        return self.allowed_steps <= 0 or time.time() > self.allowed_time

    def reset_limit(self):
        self.allowed_steps = self.allowed_steps
        self.allowed_time = time.time() + self.timeout
