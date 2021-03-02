import angr
import cle
import logging
import os
import tempfile

#import trraces

_l = logging.getLogger(__name__)


#def get_rr_mainobj_addr(trace_dir, filename):
#    with trraces.trrace.RRTrace(trace_dir).open_trace() as t:
#        while (not t.match_syscall_enter()) or t.lookup_syscall_frame_number(t.current_frame) != 'execve':
#            t.pop_frame()
#        t.pop_syscall_enter()
#        binary_mappings = [m for m in t.current_frame.mmaps if m['fsname'].decode() == filename]
#        base_addr = min(m['start'] for m in binary_mappings)
#        _l.info("Found base address @ {}".format(hex(base_addr)))
#    return base_addr


def fire(self, return_loader=False, base_addr=None, **kwargs):  # pylint:disable=arguments-differ
    if self.project is None:
        tmpdir = tempfile.mkdtemp()
        self.target.retrieve_into(self.target.target_path, tmpdir)
        the_binary = os.path.join(tmpdir, os.path.basename(self.target.target_path))

        # preload the binary to decide if it supports setting library options or base addresses
        cle_args = dict(kwargs)
        cle_args.update(cle_args.pop('load_options', {}))
        cle_args.pop('use_sim_procedures', None)  # TODO do something less hacky than this
        preload_kwargs = dict(cle_args)
        preload_kwargs['auto_load_libs'] = False
        preloader = cle.Loader(the_binary, **preload_kwargs)

        if self.scout_bow is not None:
            _, _, _, self._mem_mapping = self.scout_bow.fire()

            target_libs = [lib for lib in self._mem_mapping if lib.startswith("/")]
            the_libs = []
            for target_lib in target_libs:
                local_lib = os.path.join(tmpdir, os.path.basename(target_lib))
                self.target.retrieve_into(target_lib, tmpdir)
                the_libs.append(local_lib)
            lib_opts = {os.path.basename(lib): {'base_addr': libaddr} for lib, libaddr in self._mem_mapping.items()}
            bin_opts = {"base_addr": base_addr or 0x555555554000} if preloader.main_object.pic else {}
        else:
            the_libs = {}
            lib_opts = {}
            bin_opts = {}
            self._mem_mapping = {}

        if return_loader:
            return cle.Loader(the_binary, preload_libs=the_libs, lib_opts=lib_opts, main_opts=bin_opts, **cle_args)
        self.project = angr.Project(the_binary, preload_libs=the_libs, lib_opts=lib_opts, main_opts=bin_opts, **kwargs)

        if self.static_simproc:
            self._apply_simprocedures()

    if return_loader:
        return self.project.loader
    return self.project


def set_concretizations(state):
    if state.project.loader.main_object.os == 'cgc':
        flag_vars = set()
        for b in state.cgc.flag_bytes:
            flag_vars.update(b.variables)

        state.unicorn.always_concretize.update(flag_vars)

    # Let's put conservative thresholds for now.
    state.unicorn.concretization_threshold_memory = 50000
    state.unicorn.concretization_threshold_registers = 50000
