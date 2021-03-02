import logging

from angr.exploration_techniques import ExplorationTechnique

_l = logging.getLogger(__name__)


class Unsat2Missed(ExplorationTechnique):
    def setup(self, simgr):
        simgr.populate('missed', [])

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        if stash=='active':
            for s in simgr.unsat:
                s.preconstrainer.remove_preconstraints()
            simgr.move(from_stash='unsat', to_stash='missed', filter_func=lambda _s: _s.satisfiable())

        simgr.drop(stash='unsat')
        return simgr
