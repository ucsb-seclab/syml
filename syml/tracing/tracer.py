import logging
import os
import signal

import angr
import archr
from tracer import QEMURunner, TracerPoV

from syml.config import DATASET
from syml.config import add_options, remove_options
from syml.tracing import MonitorAndExtract, Unsat2Missed, Args, utils

_l = logging.getLogger(__name__)


class Tracer(object):
    def __init__(self, filename, povname):
        self.filename = filename
        self.dirname = os.path.dirname(self.filename)
        self.povname = povname
        
        self.cb_basename = os.path.basename(filename)
        self.pov_basename = os.path.basename(povname)

    def init_cgc(self, argv, payload):
        with archr.targets.LocalTarget(argv, target_cwd=self.dirname, target_os='cgc',
                                       target_arch='i386') as target:
            tracer_bow = archr.arsenal.QEMUTracerBow(target)
            r = tracer_bow.fire(testcase=payload, record_magic=False)
            if not (r.crashed and r.signal == signal.SIGSEGV):
                xmlpovname = self.povname.replace('.input', '.xml')
                assert os.path.isfile(xmlpovname), f"{self.cb_basename}@{self.pov_basename} did not crash -- no .xml pov {xmlpovname}"
                pov = TracerPoV(xmlpovname)
                _r = QEMURunner(binary=self.filename, input=pov, record_magic=False)
                assert _r.crash_mode and _r.returncode == -11, f"{self.cb_basename}@{self.pov_basename} did not crash"
                r.crash_address = _r.crash_addr
                r.trace = _r.trace
            return target, r

    #def init_other(self, argv, payload):
    #    with archr.targets.LocalTarget(argv, target_cwd=self.dirname, target_os='linux',
    #                                   target_arch=DATASET) as target:
    #        tracer_bow = archr.arsenal.RRTracerBow(target)
    #        r = tracer_bow.fire(testcase=payload)
    #        assert r.crashed and r.signal == signal.SIGSEGV
    #        return target, r

    def run(self, write_callback):
        _l.info(f"Starting to trace binary {self.cb_basename} with input {self.pov_basename}")
        argv, payload = Args(filename=self.filename).parse(self.povname)

        # Concretely trace
        if DATASET == "cgc":
            target, r = self.init_cgc(argv, payload)
        else:
            raise NotImplementedError
            #target, r = self.init_other(argv, payload)

        self._run(target, r, write_callback)
        _l.info(f"Good news! {self.cb_basename}@{self.pov_basename} was correctly analysed")

    def _run(self, target, r, write_callback):
        # Now we have to setup an angr project using the info we have in the archr environment.
        dscout_bow = archr.arsenal.DataScoutBow(target)
        proj_bow = archr.arsenal.angrProjectBow(target, dscout_bow)

        # RR tracing is done! Let's scrape the execve frame to get the RR mem mappings and rebase the main_object
        #base_addr = utils.get_rr_mainobj_addr(r.trace_dir.name, target.target_path) if DATASET != 'cgc' else None
        archr.arsenal.angrProjectBow.fire = utils.fire
        project = proj_bow.fire(base_addr=None)

        if project.loader.main_object.os == 'cgc':
            project.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])

        # Create an initial state
        state_bow = archr.arsenal.angrStateBow(target, proj_bow)
        state = state_bow.fire(mode='tracing', stdin=angr.SimFileStream)#, flag_page=r.magic_contents)#, add_options=add_options, remove_options=remove_options)

        # Prepare symbolic arguments and mount simfiles to fs
        state.register_plugin('args', Args(filename=self.filename))
        state.args.parse(povname=self.povname, preconstrain=False)

        # Create the simgr and use the tracer exploration technique
        simgr = project.factory.simulation_manager(state, save_unsat=False, save_unconstrained=True, hierarchy=False)

        _t = r.tracer_technique(keep_predecessors=2, mode='permissive', copy_states=True)
        monitor = MonitorAndExtract(write_callback=write_callback)

        simgr.use_technique(_t)
        #simgr.use_technique(Unsat2Missed())
        # TODO: stepping missed states is slow!
        simgr.use_technique(monitor)
        #simgr.use_technique(angr.exploration_techniques.Oppologist())

        utils.set_concretizations(simgr.one_active)

        try: simgr.run()
        except: 
            if len(_t._trace) - simgr.one_active.globals['trace_idx'] < 10:
                _l.error("something went wrong, but we're close enough to the crash_address to consider this a success")
            else: raise
