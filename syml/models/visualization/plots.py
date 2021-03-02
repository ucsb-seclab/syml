import math
import pandas as pd
import numpy as np

from plotly.offline import init_notebook_mode, iplot
import plotly.graph_objs as go
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.stats import skew

from syml.models.visualization import stats


def incidence_bar_plot(col, df, hue=None, barmode='stack', width=800, height=600):
    hue = hue or {'name': 'taken',
                        'values': [
                            {'val': 'True', 'label': 'Taken', 'color': 'green'},
                            {'val': 'False', 'label': 'Non Taken', 'color': 'red'},
                        ]}

    values = list(df[col].value_counts().keys())
    values.sort()

    data = [go.Bar(y=[df[df[col]==v][hue['name']].value_counts().to_dict().get(h['val'], 0) for v in values],
                   name=h['label'], x=values, marker=dict(color=h['color'])) for h in hue['values']]
    layout = go.Layout(barmode=barmode, xaxis=dict(title=col), yaxis=dict(title='Count'), width=width, height=height)
    fig = go.Figure(data=data, layout=layout)
    iplot(fig)


def taken_incidence_kde_plot(df, col):
    df[df['taken'] == True][col].plot.kde()
    df[df['taken'] == False][col].plot.kde()
    plt.show()


def pair_plot(df, hue=None, diag_kind='kde', height=10):
    sns.pairplot(df, hue=hue, diag_kind=diag_kind, plot_kws={'alpha': 0.6, 's': 40}, height=height)


def skewness(df):
    # keep only the numerical features
    numdf = df.select_dtypes(include=np.number)

    # compute the skewness but only for non missing variables (we already imputed them but just in case ...)
    skewed_feats = numdf.apply(lambda x: skew(x.dropna()))

    skewness = pd.DataFrame({"Variable": skewed_feats.index, "Skewness": skewed_feats.data})
    # select the variables with a skewness above a certain threshold

    skewness = skewness.sort_values('Skewness', ascending=[0])

    f, ax = plt.subplots(figsize=(10, 8))
    plt.xticks(rotation='90')
    sns.barplot(x=skewness['Variable'], y=skewness['Skewness'])
    plt.ylim(0, 4)
    plt.xlabel('', fontsize=15)
    plt.ylabel('Skewness', fontsize=15)
    plt.title('', fontsize=15)

    # log skewness
    skewed_feats = skewed_feats[skewed_feats > 0.75]
    numdf[skewed_feats.index] = np.log1p(numdf[skewed_feats.index])

    # compute the skewness but only for non missing variables (we already imputed them but just in case ...)
    skewed_feats = numdf.apply(lambda x: skew(x.dropna()))
    skewness_new = pd.DataFrame({"Variable": skewed_feats.index, "Skewness": skewed_feats.data})
    # select the variables with a skewness above a certain threshold

    logskewness = skewness_new.sort_values('Skewness', ascending=[0])

    f, ax = plt.subplots(figsize=(10, 8))
    plt.xticks(rotation='90')
    sns.barplot(x=logskewness['Variable'], y=logskewness['Skewness'])
    plt.ylim(0, 4)
    plt.xlabel('', fontsize=15)
    plt.ylabel('Skewness', fontsize=15)
    plt.title('', fontsize=15)


def heatmap(data, cmap='coolwarm', center=0.0, vmin=-1.0, vmax=1.0):
    sns.heatmap(data, cmap=cmap, center=center, vmin=vmin, vmax=vmax, fmt='.2f', annot=True,
                cbar=True, robust=True)


def clustermap(df, method='spearman', size=None, cmap='coolwarm'):
    size = size or math.floor(len(list(df))/1.5)
    corr = stats.corr(df, method=method)

    sns.clustermap(corr, vmin=-1.0, vmax=1.0, center=0, fmt='.2f',
                   square=True, annot=True, cbar_kws={'shrink': 0.7},
                   cmap=cmap, figsize=(size, size), robust=True)


def compare_kde(df, targets):
    for t in targets:
        sns.kdeplot(df[t], label=t)
    plt.legend()
    plt.show()
