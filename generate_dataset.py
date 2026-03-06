import pandas as pd
import numpy as np

N = 1000  # nombre de lignes

total_requests = np.random.randint(5, 50, N)
error_count = np.random.randint(1, 20, N)
unique_paths = np.random.randint(1, 10, N)
error_ratio = error_count / total_requests
ftp_ratio = np.random.rand(N)
weblogin_ratio = np.random.rand(N)
label = (error_ratio + ftp_ratio + weblogin_ratio > 1.2).astype(int)  # simple règle pour label

df = pd.DataFrame({
    "total_requests": total_requests,
    "error_count": error_count,
    "unique_paths": unique_paths,
    "error_ratio": error_ratio,
    "ftp_ratio": ftp_ratio,
    "weblogin_ratio": weblogin_ratio,
    "label": label
})

df.to_csv("training/dataset.csv", index=False)
print("✅ Dataset généré avec 6 features : training/dataset.csv")
