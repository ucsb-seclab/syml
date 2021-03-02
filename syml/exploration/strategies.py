import random
import time

random.seed(time.time())


def PoolingFast(simgr, stash):
    simgr.move(from_stash=stash, to_stash='deferred')

    if len(simgr.stashes['best']) == 0:
        best = max([s.score.trend for s in simgr.stashes['deferred']]) * 1.0
        simgr.move(from_stash='deferred', to_stash='best', filter_func=lambda s: s.score.trend >= best)

    simgr.split(from_stash='best', to_stash=stash, limit=len(simgr.stashes['best']) - 1)


def PoolingBalanced(simgr, stash, threshold=0.5):
    simgr.move(from_stash=stash, to_stash='deferred')

    best_pool = len(simgr.stashes['best']) > 0
    pooling_stash = 'best' if best_pool else 'deferred'

    score_total = sum([s.score.trend for s in simgr.stashes[pooling_stash]])
    n = random.uniform(0, score_total)
    for s in simgr.stashes[pooling_stash]:
        if n < s.score.trend and s.score.mean > threshold:
            simgr.stashes[pooling_stash].remove(s)
            simgr.stashes[stash] = [s]
            break
        n = n - s.score.trend

    # if no state was picked, use PoolingFast
    if len(simgr.stashes[stash]) == 0:
        if len(simgr.stashes['stuck']) > 0:
            simgr.stashes[stash] = [simgr.stashes['stuck'].pop(0)]
        else:
            PoolingFast(simgr, stash)


def DepthFirst(simgr, stash):
    simgr.split(from_stash=stash, to_stash='deferred', state_ranker=lambda s: -s.score.trend, limit=1)
