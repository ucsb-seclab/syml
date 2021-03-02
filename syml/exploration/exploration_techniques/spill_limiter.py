from angr.exploration_techniques import ExplorationTechnique


class SpillLimiter(ExplorationTechnique):
    def __init__(self, limit, spill, state_ranker):
        super(SpillLimiter, self).__init__()
        self.limit = limit
        self.spill = spill
        self.state_ranker = state_ranker

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        if len(simgr.stashes['deferred']) > self.limit:
            worst = min([self.state_ranker(s, reverse=True) for s in simgr.stashes['deferred']])
            simgr.split(from_stash="deferred", to_stash='_DROP', state_ranker=lambda s: self.state_ranker(s, reverse=True) == worst,
                        limit=self.limit - self.spill)

        # spill deadended
        simgr.move(from_stash="deadended", to_stash='_DROP')

        # clean caches
        if len(simgr.active) > 0:
            simgr.one_active.solver.downsize()

        return simgr
