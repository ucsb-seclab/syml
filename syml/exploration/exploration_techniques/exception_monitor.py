import logging

from angr.exploration_techniques import ExplorationTechnique

_l = logging.getLogger('syml')


class ExceptionMonitor(ExplorationTechnique):
    def step(self, simgr, stash="active", **kwargs):
        try:
            simgr = simgr.step(stash=stash, **kwargs)
        except:  # RecursionError | Z3Exception
            #raise()
            simgr.move(from_stash="active", to_stash='_DROP')
            _l.exception('Internal Error: the state was dropped!')

        return simgr
