import numpy as np

from sklearn.preprocessing import MinMaxScaler


def repeating_value_counts(df):
    for col in df:
        print("-"*30)
        count = df[[col]].astype(np.str).groupby(col)[[col]].count()
        count.columns = [""]
        print(count)


def correlation_with_target(df, target, threshold=0.0, method='spearman'):
    # Correlation with decision variable
    corr_target = corr(df, method=method)[target]
    # Selecting and sorting features with correlation over threshold
    return corr_target[abs(corr_target) > threshold].sort_values().to_frame()


def std(df, threshold=0.0):
    # minmax normalize and return sorted variance per column
    tmp = df.select_dtypes(np.number)
    tmp.loc[:, :] = MinMaxScaler().fit_transform(tmp)

    std = tmp.std()
    return std[abs(std) > threshold].sort_values().to_frame()


def max_corr(df):
    return np.maximum(
        np.maximum(df.corr(method='pearson').abs(), df.corr(method='spearman').abs()),
        df.corr(method='kendall').abs()
    )


def corr(df, method='spearman'):
    if method == 'max':
        return max_corr(df)
    else:
        return df.corr(method=method)
