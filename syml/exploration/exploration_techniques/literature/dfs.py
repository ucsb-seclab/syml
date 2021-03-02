import logging

from angr.exploration_techniques import ExplorationTechnique

l = logging.getLogger('syml')


class DFS(ExplorationTechnique):
    """
    Depth-first search.

    Will only keep one path active at a time, any others will be stashed in the 'deferred' stash.
    When we run out of active paths to step, we take the longest one from deferred and continue.
    """

    def step(self, simgr, **kwargs):
        simgr = simgr.step(stash='active', **kwargs)
        if len(simgr.active) > 1:
            simgr.split(from_stash='active', to_stash='deferred', limit=1)
            l.debug(f'{"-" * 0x10}\nStatus:\t\t{simgr} --> active: {simgr.active}')
        elif len(simgr.active) == 0 and len(simgr.deferred) > 0:
            simgr.active.append(simgr.deferred.pop())

        return simgr
