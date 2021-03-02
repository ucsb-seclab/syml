import os
import logging

import angr
import archr

from syml.config import add_options, remove_options, DATASET
from syml.exploration.exploration_techniques import CrashMonitor, SpillLimiter, TimeLimiter, ExceptionMonitor

_l = logging.getLogger(__name__)
_l.setLevel(logging.INFO)


class Explorer(object):
    def __init__(self, filename, technique, strategy, classifier, features):
        self.filename = filename
        self.technique = technique
        self.strategy = strategy
        self.classifier = classifier
        self.features = features

    def run(self):
        if DATASET == "cgc":
            self.run_cgc()
        elif DATASET == "x86":
            self.run_x86()
        else:
            raise Exception("Not implemented, yet!")

    def run_cgc(self):
        cb_basename = os.path.basename(self.filename)
        _l.info(f"Starting to explore binary {cb_basename}..")

        folder = os.path.dirname(self.filename)
        argv = [self.filename]
        
        with archr.targets.LocalTarget(argv, target_cwd=folder, target_os='cgc', target_arch='i386') as target:
            # create project
            dsb = archr.arsenal.DataScoutBow(target)
            angr_project_bow = archr.arsenal.angrProjectBow(target, dsb)
            project = angr_project_bow.fire()

            # create initial state
            state_bow = archr.arsenal.angrStateBow(target, angr_project_bow)
            initial_state = state_bow.fire(
                add_options=add_options,
                remove_options=remove_options
            )

            # create simulation manager
            simgr = project.factory.simulation_manager(initial_state, hierarchy=False, save_unsat=False,
                                                   save_unconstrained=True)

            _t = self.technique(model=self.classifier, strategy=self.strategy, features=self.features)
            simgr.use_technique(ExceptionMonitor())
            #simgr.use_technique(TimeLimiter(timeout=10))  #, allowed_steps=500
            simgr.use_technique(SpillLimiter(limit=500, spill=50, state_ranker=_t.rank))
            simgr.use_technique(CrashMonitor())
            simgr.use_technique(_t)
            
            simgr.run()
            
    def run_x86(self):
        cb_basename = os.path.basename(self.filename)
        _l.info(f"Starting to explore binary {cb_basename}..")

        folder = os.path.dirname(self.filename)
        argv = [self.filename]
        
        with archr.targets.LocalTarget(argv, target_cwd=folder, target_os='linux', target_arch='i386') as target:
            # create project
            #dsb = archr.arsenal.DataScoutBow(target)
            angr_project_bow = archr.arsenal.angrProjectBow(target, None)#, dsb)
            project = angr_project_bow.fire(project_kwargs={'auto_load_libs': False})

            # create initial state
            state_bow = archr.arsenal.angrStateBow(target, angr_project_bow)
            initial_state = state_bow.fire(
                add_options=add_options,
                remove_options=remove_options,
                stdin=angr.SimFileStream
            )

            # create simulation manager
            simgr = project.factory.simulation_manager(initial_state, hierarchy=False, save_unsat=False,
                                                   save_unconstrained=True)

            _t = self.technique(model=self.classifier, strategy=self.strategy, features=self.features)
            simgr.use_technique(ExceptionMonitor())
            #simgr.use_technique(TimeLimiter(timeout=10))  #, allowed_steps=500
            simgr.use_technique(SpillLimiter(limit=500, spill=50, state_ranker=_t.rank))
            simgr.use_technique(CrashMonitor())
            #simgr.use_technique(_t)
            
            while len(simgr.active) < 2 and len(simgr.active) > 0:
                simgr.step()
                print(simgr.active)
                
            import IPython; IPython.embed()
