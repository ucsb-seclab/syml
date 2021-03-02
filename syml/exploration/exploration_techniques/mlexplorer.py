import time
import itertools

import numpy as np

import logging

from angr.exploration_techniques import ExplorationTechnique

from syml.tracing.state_plugins import Features, Statics, MovingStats
from syml.exploration import PoolingFast

_l = logging.getLogger('syml')


class MLExplorer(ExplorationTechnique):
    """
    An exploration technique that uses a Machine Learning model to triage and step only the most interesting states
    """

    def __init__(self, model, strategy, features, fast_timer=9*60*60, **kwargs):
        """
        :param model:           The trained machine learning model used to score interesting states
        """
        super(MLExplorer, self).__init__()
        self.model = model
        self.strategy = strategy
        self.features = features
        self.fast_timer = time.time() + fast_timer

    def setup(self, simgr):
        super(MLExplorer, self).setup(simgr)
        simgr.populate('deferred', [])
        simgr.populate('best', [])
        simgr.populate('stepping', [])

        # register and setup state plugins
        simgr.one_active.register_plugin('statics', Statics())
        simgr.one_active.register_plugin('features', Features())
        simgr.one_active.register_plugin('score', MovingStats())
        simgr.one_active.statics.setup()
        simgr.one_active.features.setup()
    
    @staticmethod
    def rank(s, reverse=False):
        k = -1 if reverse else 1
        return k * s.score.trend

    def step(self, simgr, stash="active", **kwargs):
        assert len(simgr.stashes[stash]) <= 1, "We should have at most one active state!"
        
        # take one step
        if len(simgr.active) == 1:
            simgr = simgr.step(stash=stash, **kwargs)

        # if it has no successors, pick the best one from deferred states(so called the pool)
        if len(simgr.stashes[stash]) == 0:
            next(self.strategy)(simgr, stash)
            _l.info(f'score trend: {simgr.active[0].score.trend}')
            _l.debug(f'{"-" * 0x10}\nStatus:\t\t{simgr} --> active: {simgr.stashes[stash]}')

        # if it has multiple successors
        elif len(simgr.active) > 1:
            # reset branches
            [s.features.new_branch() for s in simgr.active]

            # one by one, move from missed to stepping, step until branch, then dump features
            stepped = []
            X = []
            while len(simgr.active) >= 1:
                simgr.populate('stepping', [simgr.active.pop()])
                i = 0
                while len(simgr.stepping) == 1 and i < 20:
                    copy = simgr.one_stepping.copy()
                    try:
                        simgr.step(stash="stepping")
                        i += 1
                    except:
                        _l.error("Errored while stepping")
                        break
                X.append(copy.features.to_processed(self.features))
                stepped.append(copy)
                simgr.move(from_stash="stepping", to_stash="_DROP")
            simgr.populate('active', stepped)

            # get scores from classifier
            scores = self.model.predict_proba(np.array(X))[:, 1].tolist()
            # scores = list(map(lambda x: x / sum(scores), scores))
            [s.score.update(score) for s, score in zip(simgr.active, scores)]

            if self.fast_timer and time.time() > self.fast_timer:
                _l.info(f'switching to FastPooling only')
                self.strategy = itertools.cycle([PoolingFast])
                self.fast_timer = 0
                
            # UPDATE simgr USING THE SPECIFIED STRATEGY
            next(self.strategy)(simgr, stash)
            _l.info(f'score trend: {simgr.active[0].score.trend}')

            _l.debug(f'{"-" * 0x10}\nStatus:\t\t{simgr} --> active: {simgr.stashes[stash]}')

        return simgr
