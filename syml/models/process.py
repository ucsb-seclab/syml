import numpy as np


def drop_constant_columns(df):
    for col in df:
        if len(df[col].astype(np.str).unique()) == 1:
            df.drop(col, inplace=True, axis=1)
    return df


def drop_duplicates(df, target, volatile=None):
    # do not simply drop duplicates (we would indeed ignore different values of visits, trace_depth, etc..),
    # try to squeeze numerical and ignore just the categorical
    volatile = volatile or {}

    # squeeze numvolatile features
    for f in volatile:
        if np.issubdtype(df[f].dtype, np.number):
            df[f] = np.round(np.log1p(df[f]), 0)

    # drop duplicates
    catvolatile = [f for f in volatile if not np.issubdtype(df[f].dtype, np.number)]
    subset = set(df) - set(catvolatile)  # - {target}
    index = df.astype(str).sort_values(target).drop_duplicates(subset=subset, keep='last').sort_index().index

    # sort by cumulative count, taken first
    return df.reindex(index=index).reset_index(drop=True)
