import os

import angr

import pandas as pd


class Features(angr.SimStatePlugin):
    CONVERTERS = {
        # GENERAL #################################################
        "filename": lambda x: x,
        "fileID": lambda x: x,
        "taken": eval,
        "branchID": pd.to_numeric,
        "depth": pd.to_numeric,
        # WHOLE EXECUTION #########################################
        "bb_count_all": pd.to_numeric,
        "calls_all": pd.to_numeric,
        #"syscalls_all": eval,
        #"monogram_visits": pd.to_numeric,
        "bigram_visits": pd.to_numeric,
        # BRANCH ##################################################
        "communities": eval,
        "address_concretizations": pd.to_numeric,
        #"symbolic_variables": pd.to_numeric,
        "mem_reads": pd.to_numeric,
        "mem_writes": pd.to_numeric,
        "reg_reads": pd.to_numeric,
        "reg_writes": pd.to_numeric,
        #"tmp_reads": pd.to_numeric,
        #"tmp_writes": pd.to_numeric,
        "bb_count": pd.to_numeric,
        "calls": pd.to_numeric,
        #"syscalls": eval,
        "returns": pd.to_numeric,
        # STATE ###################################################
        "connectivity": pd.to_numeric,
        "centrality": pd.to_numeric,
        "function_size": pd.to_numeric,
        "function_complexity": pd.to_numeric,
        "leaving_component": eval,
        "change_community": eval
    }

    def __init__(self, clone=None):
        super(Features, self).__init__()
        self._id = 0 if clone is None else clone._id
        self.depth = 0 if clone is None else clone.depth
        #self._monogram_visits = dict() if clone is None else dict(clone._monogram_visits)
        self._bigram_visits = dict() if clone is None else dict(clone._bigram_visits)
        self.branch_bigram_visits = 0 if clone is None else clone.branch_bigram_visits

        self.address_concretizations = 0 if clone is None else clone.address_concretizations
        #self.symbolic_variables = 0 if clone is None else clone.symbolic_variables
        self.mem_reads = 0 if clone is None else clone.mem_reads
        self.mem_writes = 0 if clone is None else clone.mem_writes
        self.reg_reads = 0 if clone is None else clone.reg_reads
        self.reg_writes = 0 if clone is None else clone.reg_writes
        #self.tmp_reads = 0 if clone is None else clone.tmp_reads
        #self.tmp_writes = 0 if clone is None else clone.tmp_writes
        self.bb_count_all = 0 if clone is None else clone.bb_count_all
        self.bb_count = 0 if clone is None else clone.bb_count
        self.calls_all = 0 if clone is None else clone.calls_all
        self.calls = 0 if clone is None else clone.calls
        #self.syscalls_all = {} if clone is None else clone.syscalls_all
        #self.syscalls = {} if clone is None else clone.syscalls
        self.returns = 0 if clone is None else clone.returns

        self.leaving_component = None if clone is None else clone.leaving_component
        self.communities = [] if clone is None else clone.communities
        self._function_address = None

    def setup(self):
        # setup breakpoints for feature tracing
        self.state.inspect.b('address_concretization', action=self.log_address_concretization)
        #self.state.inspect.b('symbolic_variable', action=self.log_symbolic_variable)
        self.state.inspect.b('mem_read', action=self.log_mem_read)
        self.state.inspect.b('mem_write', action=self.log_mem_write)
        self.state.inspect.b('reg_read', action=self.log_reg_read)
        self.state.inspect.b('reg_write', action=self.log_reg_write)
        #self.state.inspect.b('tmp_read', action=self.log_tmp_read)
        #self.state.inspect.b('tmp_write', action=self.log_tmp_write)
        #self.state.inspect.b('syscall', action=self.log_syscall)
        self.state.inspect.b('call', when=angr.BP_AFTER, action=self.log_call)
        self.state.inspect.b('return', when=angr.BP_AFTER, action=self.log_return)

        self.new_branch()

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        self.increment_visits()
        self.increment_bb()
        return Features(clone=self)

    @property
    def connectivity(self):
        return self.state.statics.connectivity.get(self.state.addr, -1)

    @property
    def centrality(self):
        return self.state.statics.centrality.get(self.state.addr, -1)

    @property
    def function_address(self):
        if self._function_address is None:
            self._function_address = self.state.statics.function_address.get(self.state.addr, 0)
        return self._function_address

    @property
    def function_size(self):
        return self.state.statics.function_size.get(self.function_address, -1)

    @property
    def function_complexity(self):
        return self.state.statics.function_complexity.get(self.function_address, -1)

    @property
    def community(self):
        return self.state.statics.communities.get(self.function_address, -1)

    @property
    def community_size(self):
        return self.state.statics.community_size.get(self.function_address, 0)

    #@property
    #def monogram_visits(self):
    #    return self._monogram_visits.get(self.state.addr, 0)

    @property
    def bigram_visits(self):
        return self._bigram_visits.get((self.state.history.addr, self.state.addr), 0)

    def increment_visits(self):
        if self.state.regs.eip.symbolic: return
        #self._monogram_visits[self.state.addr] = self.monogram_visits + 1
        self._bigram_visits[(self.state.history.addr, self.state.addr)] = self.bigram_visits + 1
        self.depth += 1

    def increment_bb(self):
        self.state.features.bb_count_all += 1
        self.state.features.bb_count += 1

    def new_branch(self):
        self._id += 1
        self.branch_bigram_visits = self.bigram_visits

        self.address_concretizations = 0
        #self.symbolic_variables = 0
        self.mem_reads = 0
        self.mem_writes = 0
        self.reg_reads = 0
        self.reg_writes = 0
        #self.tmp_reads = 0
        #self.tmp_writes = 0
        self.bb_count = 0
        self.calls = 0
        #self.syscalls = {}
        self.returns = 0

        self.leaving_component = (self.state.history.addr, self.state.addr) in self.state.statics.break_edges
        self.communities = [self.state.features.community]

    @staticmethod
    def log_address_concretization(state):
        state.features.address_concretizations += 1

    #@staticmethod
    #def log_symbolic_variable(state):
    #    state.features.symbolic_variables += 1

    @staticmethod
    def log_mem_read(state):
        state.features.mem_reads += 1

    @staticmethod
    def log_mem_write(state):
        state.features.mem_writes += 1

    @staticmethod
    def log_reg_read(state):
        state.features.reg_reads += 1

    @staticmethod
    def log_reg_write(state):
        state.features.reg_writes += 1

    #@staticmethod
    #def log_tmp_read(state):
    #    state.features.tmp_reads += 1

    #@staticmethod
    #def log_tmp_write(state):
    #    state.features.tmp_writes += 1

    @staticmethod
    def log_call(state):
        state.features.communities.append(state.features.community)
        state.features.calls_all += 1
        state.features.calls += 1

    #@staticmethod
    #def log_syscall(state):
    #    syscall = state.inspect.syscall_name
    #    state.features.syscalls_all[syscall] = state.features.syscalls_all.get(syscall, 0) + 1
    #    state.features.syscalls[syscall] = state.features.syscalls.get(syscall, 0) + 1

    @staticmethod
    def log_return(state):
        state.features.communities.append(state.features.community)
        state.features.returns += 1

    def _to_list(self, taken):
        args = taken is not None
        
        filename = os.path.basename(self.state.args.bin) if args else None
        povname = os.path.basename(self.state.args.povname) if args else None
        return {
            # GENERAL #################################################
            "filename": filename if args else None,
            "fileID": f"{filename}[{povname}]" if args else None,
            "taken": taken,
            "branchID": self._id,  # branch ID
            "depth": self.depth,
            # WHOLE EXECUTION #########################################
            "bb_count_all": self.bb_count_all,
            "calls_all": self.calls_all,
            #"syscalls_all": self.syscalls_all,
            #"monogram_visits": self.monogram_visits,
            "bigram_visits": self.branch_bigram_visits,  # bigram visits for the branching nodes
            # BRANCH ##################################################
            "communities": self.communities,
            "address_concretizations": self.address_concretizations/(self.bb_count + 1),
            #"symbolic_variables": self.symbolic_variables,
            "mem_reads": self.mem_reads/(self.bb_count + 1),
            "mem_writes": self.mem_writes/(self.bb_count + 1),
            "reg_reads": self.reg_reads/(self.bb_count + 1),
            "reg_writes": self.reg_writes/(self.bb_count + 1),
            #"tmp_reads": self.tmp_reads/(self.bb_count + 1),
            #"tmp_writes": self.tmp_writes/(self.bb_count + 1),
            "bb_count": self.bb_count,
            "calls": self.calls/(self.bb_count + 1),
            #"syscalls": {k: v/(self.bb_count + 1) for k,v in self.syscalls.items()},
            "returns": self.returns/(self.bb_count + 1),
            # STATE ###################################################
            "connectivity": self.connectivity,
            "centrality": self.centrality,
            "function_size": self.function_size,
            "function_complexity": self.function_complexity,
            "leaving_component": self.leaving_component,
            "change_community": (len(self.communities) > 1) and (self.communities[0] != self.communities[-1])
        }

    def to_string(self, taken):
        return "\t".join(str(feature) for feature in self._to_list(taken=taken).values())

    # features plugins must implement a to_processed method
    def to_processed(self, dst_features, taken=None):
        features = self._to_list(taken=taken)

        Xi = []
        for f in dst_features:
            #if 'syscalls_' in f:
            #    Xi.append(features['syscalls'].get(f[9:], 0))
            if f == 'num_communities':
                Xi.append(len(features['communities']))
            else:
                Xi.append(features[f])

        return Xi
