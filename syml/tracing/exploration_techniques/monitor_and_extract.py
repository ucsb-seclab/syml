import logging

from angr.exploration_techniques import ExplorationTechnique

from syml.tracing.state_plugins import Features, Statics

from syml.config import WINDOW_SIZE

_l = logging.getLogger(__name__)


class MonitorAndExtract(ExplorationTechnique):
    def __init__(self, write_callback):
        super(MonitorAndExtract, self).__init__()
        self.write_callback = write_callback

    def setup(self, simgr):
        simgr.populate('stepping', [])

        # register and setup state plugins
        simgr.one_active.register_plugin('statics', Statics())
        simgr.one_active.register_plugin('features', Features())
        simgr.one_active.statics.setup()
        simgr.one_active.features.setup()

        # disable setup() method as we'll occasionally remove and add techniques
        for t in simgr._techniques + [self]:
            t.setup = lambda x: x

    def step(self, simgr, stash='active', **kwargs):
        # monitor until some branch happens
        copy = simgr.one_active.copy()
        simgr = simgr.step(stash=stash, **kwargs)

        if len(simgr.missed) >= 1:
            _l.debug(f"just branched, parent: {copy}, child_taken: {simgr.active}, child_missed: {simgr.missed}")
            _l.debug(f"active:{simgr.active}, missed:{simgr.missed}")

            # 1: dump features for the old active branch (write_callback)
            self.write_callback(copy, taken=True)

            # 2: increment all branch_id counters
            [s.features.new_branch() for s in simgr.active + simgr.missed]

            # 3: backup and remove exploration techniques
            techniques = list(simgr._techniques)
            simgr.remove_technique(simgr._techniques[0])

            # 4: one by one, move from missed to stepping, step until branch, then dump features
            while len(simgr.missed) >= 1:
                simgr.populate('stepping', [simgr.missed.pop()])
                _l.debug(f"stepping {simgr.stepping[0]}")
                i = 0
                while len(simgr.stepping) == 1 and i < WINDOW_SIZE:
                    try:
                        copy = simgr.one_stepping.copy()
                        simgr.step(stash="stepping")
                        i += 1
                    except:
                        break
                _l.debug(f"finished stepping")
                self.write_callback(copy, taken=False)
                simgr.move(from_stash="stepping", to_stash="_DROP")

            # 5: restore exploration techniques, then move on (will restart on 1)
            simgr._techniques = []
            [simgr.use_technique(t) for t in techniques]
            
            #[self.write_callback(m, taken=True) for m in simgr.missed]

        if len(simgr.traced) >= 1:
            self.write_callback(simgr.one_traced, taken=True)

        return simgr
