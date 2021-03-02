#!/usr/bin/env python

import argparse
import glob
import itertools
import json
import logging
import os
import os
import pandas as pd
import pickle
from pandas.io.json import json_normalize
from xgboost import XGBClassifier

from syml.config import RAW_PATH, DATASET_PATH, PROCESSED_PATH, RESOURCES_PATH, CONFIG_PATH
from syml.exploration import Explorer, PoolingFast, PoolingBalanced
from syml.exploration.exploration_techniques import MLExplorer, KLEECoverageOptimizeSearch, KLEERandomSearch, DFS, \
    AEGLoopExhaustion, StochasticSearch
from syml.models import process
from syml.tracing import Tracer, Features

# setup logging
_l = logging.getLogger("syml")
_l.setLevel('INFO')


def setup_logging(cb, pov="explore"):
    global _l
    path = f"{DATASET_PATH}/status.{cb}.{pov}.log" if cb or pov else f"{DATASET_PATH}/status.log"
    logFormatter = logging.Formatter("%(levelname)s\t| %(asctime)s | %(name)s | %(message)s")
    fileHandler = logging.FileHandler(path)
    fileHandler.setFormatter(logFormatter)

    _l.addHandler(fileHandler)


# parse cli arguments
parser = argparse.ArgumentParser()
parser.add_argument('--debug', action='store_true')

parser.add_argument('--filename')
parser.add_argument('--pov')

parser.add_argument('--analyse', action='store_true')
parser.add_argument('--concatenate', action='store_true')
parser.add_argument('--train', action='store_true')
parser.add_argument('--explore', type=str, choices=['ml', 'klee-random', 'klee-cov', 'aeg-loop', 'random', 'dfs'])

args = parser.parse_args()

if args.debug:
    logging.getLogger("syml").setLevel('DEBUG')
    logging.getLogger('archr').setLevel('DEBUG')
    #logging.getLogger('angr').setLevel('INFO')
    logging.getLogger("angr.state_plugins.preconstrainer").setLevel("DEBUG")
    logging.getLogger("angr.simos").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.tracer").setLevel("DEBUG")
    logging.getLogger("angr.exploration_techniques.crash_monitor").setLevel("DEBUG")

if args.analyse:
    cb_basename = os.path.basename(args.filename)
    pov_basename = os.path.basename(args.pov)
    rawpath = RAW_PATH.format(cb=cb_basename, pov=pov_basename.split('.')[0])
    
    setup_logging(cb=cb_basename, pov=pov_basename)
    
    try:
        with open(f"{rawpath}.tmp.csv", "w+", buffering=1) as f:
            def write_callback(state, taken):
                f.writelines([state.features.to_string(taken=taken) + "\n"])
            f.writelines(["\t".join(Features.CONVERTERS) + "\n"])
            tracer = Tracer(args.filename, args.pov)
            tracer.run(write_callback=write_callback)
        _l.info(f"{pov_basename}@{cb_basename} executed correctly")
        os.rename(f"{rawpath}.tmp.csv",
                  f"{rawpath}.csv")
    except KeyboardInterrupt:
        _l.error(f"{pov_basename}@{cb_basename} terminated with KeyboardInterrupt")
        os.remove(f"{rawpath}.tmp.csv")
    except Exception as e:
        _l.exception(f"{pov_basename}@{cb_basename} terminated with exception '{type(e).__name__}' - {e.args}")
        os.rename(f"{rawpath}.tmp.csv",
                  f"{rawpath}.failed.csv")
        if args.debug:
            raise

if args.concatenate:
    setup_logging(cb=None, pov=None)
    
    _l.info(f"Concatenating..")
    globrawpath = RAW_PATH.format(cb='*', pov='*')+".csv"
    raw = glob.glob(globrawpath)  # [!tmp][!killed][!failed]
    df = pd.concat((pd.read_csv(f, sep='\t', converters=Features.CONVERTERS) for f in raw), sort=False)
    df.to_csv(f"{PROCESSED_PATH}.all.csv", sep="\t", index=False,
              chunksize=100000, compression='gzip', encoding='utf-8')

if args.train:
    setup_logging(cb=None, pov=None)
    
    _l.info(f"Loading dataframe..")
    df = pd.read_csv(f"{PROCESSED_PATH}.all.csv", sep='\t', compression='gzip', converters=Features.CONVERTERS)
    
    _l.info(f"Preparing dataframe..")

    procdf = df
    procdf['num_communities'] = df['communities'].apply(lambda x: len(x))#/(df['bb_count']+1)

    process.drop_constant_columns(procdf)
    procdf = procdf.drop(['fileID', 'branchID', 'depth', 'bb_count', 'bb_count_all', 'calls_all', 'syscalls_all', 'syscalls', 'communities'], axis=1)
    procdf = process.drop_duplicates(procdf, target='taken')

    cb_basename = args.filename
    cb_df = procdf[procdf["filename"] != cb_basename]

    y = cb_df['taken'].values
    groups = cb_df['filename'].tolist()
    Xi = cb_df.drop(['taken', 'filename'], axis=1).values

    _l.info(f"Training..(excluded {cb_basename})")
    clf = XGBClassifier(n_jobs=30, random_state=0, 
                        num_estimators=20,
                        min_child_weight=6,
                        max_depth=2,
                        subsample=1.0,
                        colsample_bytree=1.0,
                        reg_alpha=1e-6)
    clf.fit(Xi, y)

    _l.info(f"Saving model and features.txt..")
    name = type(clf).__name__.replace('/[^a-z]/g', '')
    with open(f"{RESOURCES_PATH}/model.{name}.{cb_basename or 'all'}.pkl", "wb+") as f:
        pickle.dump(clf, f, protocol=pickle.HIGHEST_PROTOCOL)
    with open(f"{CONFIG_PATH}/features.txt", 'w') as f:
        f.write(json.dumps(list(cb_df.drop(['taken', 'filename'], axis=1)), indent=4, sort_keys=False))

if args.explore:
    cb_basename = os.path.basename(args.filename)
    
    setup_logging(cb=cb_basename)
    
    technique = {"ml": MLExplorer, "klee-random": KLEERandomSearch, "klee-cov": KLEECoverageOptimizeSearch,
                 "aeg-loop": AEGLoopExhaustion, "random": StochasticSearch, "dfs": DFS}[args.explore]
    strategy = itertools.cycle([PoolingFast, PoolingBalanced])
    with open(f"{RESOURCES_PATH}/model.XGBClassifier.{cb_basename}.pkl", 'rb') as f:
        classifier = pickle.load(f)
    with open(f"{CONFIG_PATH}/features.txt", "r") as f:
        features = json.loads(f.read())

    try:
        explorer = Explorer(filename=args.filename, technique=technique, strategy=strategy,
                            classifier=classifier, features=features)
        explorer.run()
    except Exception as e:
        _l.exception(f"Exploration of {cb_basename} terminated with exception '{type(e).__name__}' - {e.args}")
