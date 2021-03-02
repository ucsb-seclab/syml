import logging
import time

import archr
from angr.exploration_techniques import ExplorationTechnique

_l = logging.getLogger('syml')


class CrashMonitor(ExplorationTechnique):
    def __init__(self):
        super(CrashMonitor, self).__init__()
        self.filename = None
        self.start_time = time.time()
        self.crash_addrs = list()

    def setup(self, simgr):
        super(CrashMonitor, self).setup(simgr)
        simgr.populate('crashed', [])
        self.filename = simgr._project.filename

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        elapsed = time.time() - self.start_time
        for s in [e.state for e in simgr.errored if (not any([e.state.solver.eval(e.state.regs.ip == addr) for addr in self.crash_addrs]))]:
            _l.info(f"{self.filename} crashed after {elapsed:.0f}s - addr: {hex(s.addr)}, stdin: {s.posix.dumps(0)}")
            _l.info(f"{self.filename} crashed after {elapsed:.0f}s - Qemu confirms: {self.QEMUCrash(s)} - addr: {hex(s.addr)}, stdin: {s.posix.dumps(0)}")
            self.crash_addrs.append(s.addr)
            simgr.crashed.append(s)
        
        for s in [d for d in simgr.unconstrained if (not any([d.solver.eval(d.regs.ip == addr) for addr in self.crash_addrs]))]:
            _l.info(f"{self.filename} crashed after {elapsed:.0f}s - addr: unconstrained, stdin: {s.posix.dumps(0)}")
            _l.info(f"{self.filename} crashed after {elapsed:.0f}s - Qemu confirms: {self.QEMUCrash(s)} - addr: unconstrained, stdin: {s.posix.dumps(0)}")
            self.crash_addrs.append(s.regs.ip)
            simgr.crashed.append(s)

        simgr._errored = []
        simgr.move(from_stash="unconstrained", to_stash='_DROP')

        return simgr

    def QEMUCrash(self, s):
        with archr.targets.LocalTarget([self.filename], target_os='cgc', target_arch='i386', use_qemu=True) as target:
            
            tracer_bow = archr.arsenal.QEMUTracerBow(target)
            r = tracer_bow.fire(testcase=s.posix.dumps(0))
        return r.crashed
