import angr
import community
import networkx


class Statics(angr.SimStatePlugin):
    def __init__(self, clone=None):
        super(Statics, self).__init__()
        self.cfg = None if clone is None else clone.cfg
        self.centrality = None if clone is None else clone.centrality
        self.connectivity = None if clone is None else clone.connectivity
        self.function_address = None if clone is None else clone.function_address
        self.function_size = None if clone is None else clone.function_size
        self.function_complexity = None if clone is None else clone.function_complexity
        self.break_edges = None if clone is None else clone.break_edges
        self.communities = None if clone is None else clone.communities
        self.community_size = None if clone is None else clone.community_size

    def setup(self):
        # static analyses
        cfg = self.state.project.analyses.CFGFast(fail_fast=True, normalize=True, show_progressbar=False)
        kb = cfg.kb
        self.cfg = cfg.model

        self.centrality = {n.addr: centr for n, centr in networkx.katz_centrality(self.cfg.graph).items()}
        self.connectivity = {n.addr: conn for n, conn in self.cfg.graph.degree}

        functions = self.cfg.project.kb.functions
        self.function_address = {n.addr: n.function_address for n in self.cfg.nodes()}

        # compute functions size
        self.function_size = {f: functions[f].size for f in functions}

        # compute functions complexity
        self.function_complexity = dict()
        for f in functions:
            edges = len(functions[f].graph.edges())
            nodes = len(functions[f].graph.nodes())
            parts = networkx.components.number_strongly_connected_components(functions[f].graph)
            self.function_complexity[f] = edges - nodes + 2 * parts
            
        loop_finder = self.state.project.analyses.LoopFinder(kb=kb, normalize=True)
        self.break_edges = [(edge[0].addr, edge[1].addr) for loop in loop_finder.loops for edge in loop.break_edges]

        # analyse communities
        self.communities = community.best_partition(functions.callgraph.to_undirected())
        self.community_size = {comm: list(self.communities.values()).count(comm) for comm in
                               set(self.communities.values())}

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return Statics(clone=self)
