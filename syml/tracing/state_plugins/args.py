import logging

import os
import angr
import claripy

_l = logging.getLogger(__name__)


class Args(angr.SimStatePlugin):
    def __init__(self, filename=None, clone=None):
        super(Args, self).__init__()
        if clone is None:  # check only the first time
            assert os.path.isabs(filename), f"{filename} is not an absolute path" 

        self.bin = filename if clone is None else clone.bin
        self.povname = None if clone is None else clone.povname
        self.bindir = os.path.dirname(self.bin) if clone is None else clone.bindir
        self.stdin = b'' if clone is None else clone.stdin
        self.stdin = b'' if clone is None else clone.stdin
        self.argv = [] if clone is None else clone.argv
        self.argv_concrete = [] if clone is None else clone.argv_concrete

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return Args(clone=self)

    def parse(self, povname, preconstrain=False):
        assert os.path.isabs(povname), f"{povname} is not an absolute path" 

        self.povname = povname
        options = [':povcontent:', ':bin:']
        #with open(f"{self.bindir}/exec_options", "r") as f:
        #    options = eval(f.read())

        for i, p in enumerate(options):
            if type(p) == bytes:
                sym = concr = p
            # binary name
            elif p == ":bin:":
                sym = concr = self.bin
            # pov name
            elif p.startswith(":povname:"):
                sym = concr = povname
                self.mount(povname)
            # pov name without extension
            #elif p.startswith(":povbasename:"):
            #    sym = concr = povname.split('.')[0]
            #    self.mount(povname)
            # pov content
            elif p.startswith(":povcontent:"):
                content = open(povname, "rb").read()
                sym_arg = claripy.BVS('sym_arg{i}', 8 * len(content))  # length is bound to the dummy pov
                if preconstrain:
                    self.state.preconstrainer.preconstrain(content, sym_arg)
                sym = sym_arg
                concr = content
            # file name
            elif p.startswith(":filename:"):
                filepath = f"{self.bindir}/{p[10:]}"
                open(filepath, 'a').close()  # create the file if it does not exist (e.g. /tmp files)
                sym = concr = filepath
                self.mount(filepath, content=open(filepath, "rb").read())
            # file content
            elif p.startswith(":filecontent:"):
                sym = concr = open(f"{self.bindir}/{p[13:]}", "rb").read()
            # stdin bytes or simple argv
            else:
                sym = concr = p

            if i == 0:
                self.stdin = concr
                if preconstrain:
                    self.state.preconstrainer.preconstrain_file(self.stdin, self.state.posix.stdin, True)
            else:
                self.argv.append(sym)
                self.argv_concrete.append(concr)

        return self.argv_concrete, self.stdin

    def mount(self, path, content=None, preconstrain=True):
        if not self.state:
            return

        simfile = angr.storage.file.SimFile(path, content)
        self.state.fs.delete(path)
        self.state.fs.insert(path, simfile)
        if preconstrain:
            self.state.preconstrainer.preconstrain_file(open(path, "rb").read(), simfile)
