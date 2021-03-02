from sklearn import svm
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, precision_score, recall_score, f1_score, make_scorer, accuracy_score, \
    roc_auc_score
from sklearn.model_selection import cross_validate, LeaveOneGroupOut
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier


def _general(X, y, groups, model):
    strategy = LeaveOneGroupOut()
    scoring = {"accuracy": make_scorer(accuracy_score),
               "precision": make_scorer(precision_score),
               "f1": make_scorer(f1_score),
               "recall": make_scorer(recall_score),
               "brier": make_scorer(brier_score_loss),
               #"roc_auc": make_scorer(roc_auc_score)
               }
    cv_results = cross_validate(model, X, y, cv=strategy, n_jobs=30, groups=groups, scoring=scoring,
                                return_train_score=True)
    model.fit(X, y)
    return model, cv_results


def logregr(X, y, groups):
    """
    :param X:       data.drop(['taken'], axis=1).values
    :param y:       df['taken'].values
    :param groups:  df['filename'].tolist()
    :return:        accuracy, precision
    """
    model = LogisticRegression(C=1., solver='lbfgs', n_jobs=30, random_state=0)
    return _general(X, y, groups, model)


def lindiscr(X, y, groups):
    """
    :param X:       data.drop(['taken'], axis=1).values
    :param y:       df['taken'].values
    :param groups:  df['filename'].tolist()
    :return:        accuracy, precision
    """
    model = LinearDiscriminantAnalysis()
    return _general(X, y, groups, model)


def svm1(X, y, groups):
    """
    :param X:       data.drop(['taken'], axis=1).values
    :param y:       df['taken'].values
    :param groups:  df['filename'].tolist()
    :return:        accuracy, precision
    """
    model = svm.SVC(kernel="linear", C=0.025, random_state=0)
    return _general(X, y, groups, model)


def svm2(X, y, groups):
    """
    :param X:       data.drop(['taken'], axis=1).values
    :param y:       df['taken'].values
    :param groups:  df['filename'].tolist()
    :return:        accuracy, precision
    """
    model = svm.SVC(gamma=2, C=1, random_state=0)
    return _general(X, y, groups, model)


def decision_tree(X, y, groups):
    """
    :param X:       data.drop(['taken'], axis=1).values
    :param y:       df['taken'].values
    :param groups:  df['filename'].tolist()
    :return:        accuracy, precision
    """
    model = DecisionTreeClassifier(max_depth=6, max_features='sqrt', criterion='entropy', random_state=0)
    return _general(X, y, groups, model)


def random_forest(X, y, groups):
    """
    :param X:       data.drop(['taken'], axis=1).values
    :param y:       df['taken'].values
    :param groups:  df['filename'].tolist()
    :return:        accuracy, precision
    """
    model = RandomForestClassifier(bootstrap=True, max_depth=6, max_features='sqrt', n_estimators=400, n_jobs=30,
                                   random_state=0)
    return _general(X, y, groups, model)


def xgboost(X, y, groups, **kwargs):
    """
    :param X:       data.drop(['taken'], axis=1).values
    :param y:       df['taken'].values
    :param groups:  df['filename'].tolist()
    :return:        accuracy, precision
    """
    model = XGBClassifier(bootstrap=True, n_jobs=30, random_state=0, **kwargs)
    return _general(X, y, groups, model)
