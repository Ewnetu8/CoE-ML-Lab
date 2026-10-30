"""AI & Robotics Center of Excellence - ML examples (Python).
Install:  pip install numpy matplotlib scikit-learn torch
Run:      python ml_examples.py
"""
import numpy as np
import matplotlib.pyplot as plt
from sklearn.datasets import make_blobs, make_moons
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# 1. Probability: law of large numbers
def coin_demo(p=0.5, n=2000, seed=0):
    rng = np.random.default_rng(seed)
    tosses = rng.random(n) < p
    running = np.cumsum(tosses) / np.arange(1, n + 1)
    plt.plot(running, label="experimental")
    plt.axhline(p, color="green", label="true probability")
    plt.xlabel("number of tosses"); plt.ylabel("proportion of heads"); plt.legend()
    plt.title("Law of Large Numbers"); plt.show()

# 2. K-Means clustering
def kmeans_demo(k=3):
    X, _ = make_blobs(300, centers=3, random_state=0)
    km = KMeans(n_clusters=k, n_init=10, random_state=0).fit(X)
    plt.scatter(X[:, 0], X[:, 1], c=km.labels_)
    plt.scatter(*km.cluster_centers_.T, c="k", marker="s", s=120)
    plt.title(f"K-Means (k={k}), inertia={km.inertia_:.1f}"); plt.show()

# 3-4. Random Forest and SVM on the same data
def classifiers_demo():
    X, y = make_moons(400, noise=0.25, random_state=0)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=0)
    rf = RandomForestClassifier(n_estimators=50, max_depth=4, random_state=0).fit(Xtr, ytr)
    svm = make_pipeline(StandardScaler(), SVC(kernel="rbf", C=1)).fit(Xtr, ytr)
    print("Random Forest test accuracy:", rf.score(Xte, yte))
    print("SVM test accuracy:", svm.score(Xte, yte))
    print(classification_report(yte, rf.predict(Xte)))

# 5. Neural network in PyTorch
def nn_demo(epochs=300, hidden=8, lr=0.05):
    import torch, torch.nn as nn
    X, y = make_moons(300, noise=0.2, random_state=0)
    X = torch.tensor(X, dtype=torch.float32)
    Y = torch.tensor(y, dtype=torch.float32).view(-1, 1)
    net = nn.Sequential(nn.Linear(2, hidden), nn.Tanh(), nn.Linear(hidden, 1), nn.Sigmoid())
    opt = torch.optim.SGD(net.parameters(), lr=lr)
    for e in range(epochs):
        loss = nn.BCELoss()(net(X), Y)
        opt.zero_grad(); loss.backward(); opt.step()
        if e % 50 == 0: print(f"epoch {e}  loss {loss.item():.3f}")
    acc = ((net(X) > 0.5).float() == Y).float().mean().item()
    print("training accuracy:", acc)

if __name__ == "__main__":
    coin_demo(); kmeans_demo(); classifiers_demo(); nn_demo()
