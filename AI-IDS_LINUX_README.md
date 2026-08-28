# AI-Based Network Intrusion Detection System (AI-IDS)

An end-to-end machine-learning Network Intrusion Detection System built with the **CIC-IDS2017** dataset and **XGBoost**.

The project supports:

- Binary intrusion detection: **BENIGN vs ATTACK**
- Multiclass attack identification
- Model comparison with Logistic Regression, Decision Tree, Random Forest, and XGBoost
- PCAP/PCAPNG → flow extraction → 78-feature inference
- Streamlit security dashboard
- Batch CSV analysis
- Model evaluation, confusion matrix, ROC/PR curves, and feature importance

> **Linux deployment guide:** This README is written primarily for Ubuntu/Debian-based systems.

---

## 1. Project Architecture

```text
                     Network Traffic
                           |
              +------------+------------+
              |                         |
          CSV Flow Data            PCAP / PCAPNG
              |                         |
              |                  CICFlowMeter
              |                         |
              +------------+------------+
                           |
                    78 Flow Features
                           |
                    Feature Validation
                           |
                    Binary XGBoost
                     /          \
                BENIGN          ATTACK
                                  |
                         Multiclass XGBoost
                                  |
                         Attack Type + Confidence
                                  |
                         Streamlit Dashboard
```

---

# 2. Requirements

## Hardware

Recommended for reproducing the full experiments:

- Modern 64-bit CPU
- 16 GB RAM minimum
- 32 GB+ RAM recommended for large-dataset experiments
- At least 20–30 GB free storage for the processed datasets
- Internet connection for downloading dependencies and the dataset

The full CIC-IDS2017 CSV package is large. Training can also use substantial RAM.

## Software

For Ubuntu/Debian:

- Python 3
- pip
- Python virtual environments
- Git
- tcpdump
- libpcap development libraries

For PCAP processing:

- Scapy
- CICFlowMeter Python implementation
- tcpdump/libpcap

---

# 3. Clone the Project

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd AI-IDS
```

Check:

```bash
pwd
ls
```

You should have a structure similar to:

```text
AI-IDS/
├── data/
├── models/
├── notebooks/
├── src/
├── dashboard/
├── README.md
└── requirements.txt
```

---

# 4. Install Linux System Dependencies

For Ubuntu/Debian:

```bash
sudo apt update

sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    tcpdump \
    libpcap-dev
```

Verify:

```bash
python3 --version
pip3 --version
tcpdump --version
git --version
```

---

# 5. Create the Python Virtual Environment

From the project root:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

You should see:

```text
(venv) user@linux:~/AI-IDS$
```

Upgrade pip:

```bash
python -m pip install --upgrade pip
```

---

# 6. Install Python Dependencies

Use the project requirements file:

```bash
pip install -r requirements.txt
```

The direct project dependencies include:

```text
pandas
numpy
scikit-learn
xgboost
imbalanced-learn
matplotlib
seaborn
streamlit
jupyter
joblib
scapy
cicflowmeter==0.4.2
geoip2
```

Verify the environment:

```bash
python -c "import pandas, numpy, sklearn, xgboost, imblearn, matplotlib, seaborn, streamlit, joblib, scapy, cicflowmeter; print('AI-IDS environment READY')"
```

Expected:

```text
AI-IDS environment READY
```

---

# 7. Download CIC-IDS2017

Use the official CIC/UNB dataset source and obtain the **MachineLearningCSV** package.

The project expects the eight CSV files inside:

```text
data/raw/
```

Expected files are approximately:

```text
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
Friday-WorkingHours-Morning.pcap_ISCX.csv
Monday-WorkingHours.pcap_ISCX.csv
Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
Tuesday-WorkingHours.pcap_ISCX.csv
Wednesday-workingHours.pcap_ISCX.csv
```

Check:

```bash
ls -lh data/raw
```

---

# 8. Initial Data Analysis

The project can inspect the dataset before training.

Start Jupyter:

```bash
jupyter notebook
```

or:

```bash
jupyter lab
```

Create/use:

```text
notebooks/01_data_analysis.ipynb
```

The analysis should verify:

- Number of features
- `Label` column
- Class distribution
- Missing values
- Infinite values
- Duplicate rows
- Data types

The original CIC-IDS2017 data contains:

```text
2,830,743 total flows
79 columns
78 numerical traffic features
1 Label column
```

Observed original class distribution:

```text
BENIGN                       2,273,097
DoS Hulk                       231,073
PortScan                       158,930
DDoS                           128,027
DoS GoldenEye                   10,293
FTP-Patator                      7,938
SSH-Patator                      5,897
DoS slowloris                    5,796
DoS Slowhttptest                 5,499
Bot                              1,966
Web Attack - Brute Force         1,507
Web Attack - XSS                   652
Infiltration                        36
Web Attack - SQL Injection         21
Heartbleed                         11
```

---

# 9. Preprocess the Dataset

Run:

```bash
python src/preprocessing.py
```

The preprocessing pipeline:

1. Reads the raw CSVs in chunks.
2. Strips whitespace from column names.
3. Replaces `inf` and `-inf` with missing values.
4. Removes rows containing missing values.
5. Removes duplicate rows within chunks.
6. Creates `BinaryLabel`.

Binary target:

```text
BENIGN → 0
ATTACK → 1
```

Output:

```text
data/processed/cicids2017_clean.csv
```

Observed run:

```text
Rows before cleaning: 2,830,743
Rows after cleaning:  2,634,984
Rows removed:           195,759
Rows retained:           93.08%
```

---

# 10. Global Duplicate Removal and Binary Splits

Run:

```bash
python src/prepare_data.py
```

This creates:

```text
data/processed/splits/
├── train.csv
├── validation.csv
└── test.csv
```

Observed result:

```text
Rows processed:       2,634,984
Global duplicates:      114,186

Training rows:        1,764,549
Validation rows:        378,108
Test rows:              378,141
```

The binary training distribution was:

```text
BENIGN: 1,466,627
ATTACK:   297,922

scale_pos_weight: 4.9229
```

---

# 11. Binary XGBoost Model

Train the main binary IDS:

```bash
python src/train.py
```

The model uses:

- XGBoost
- `binary:logistic`
- 300 estimators
- max depth 8
- learning rate 0.10
- histogram tree method
- class imbalance handling with `scale_pos_weight`

The trained model is saved as:

```text
models/xgboost_binary_ids.joblib
```

Observed held-out test results:

```text
Accuracy : 99.92%
Precision: 99.57%
Recall   : 99.95%
F1       : 99.76%
ROC-AUC  : 1.0000
PR-AUC   : 0.9999
```

Test confusion matrix:

```text
                 Predicted
                 BENIGN  ATTACK

Actual BENIGN    313987     277
Actual ATTACK        34   63843
```

Interpretation:

```text
False positives: 277
Missed attacks:   34
```

---

# 12. Binary Model Comparison

Compare multiple ML models:

```bash
python src/train_models.py
```

Models:

1. Logistic Regression
2. Decision Tree
3. Random Forest
4. XGBoost

Observed results:

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | Training Time |
|---|---:|---:|---:|---:|---:|---:|---:|
| **XGBoost** | **99.918%** | **99.568%** | **99.947%** | **99.757%** | **99.997%** | **99.988%** | **50.7 s** |
| Decision Tree | 99.901% | 99.532% | 99.886% | 99.709% | 99.940% | 99.834% | 81.5 s |
| Random Forest | 99.883% | 99.536% | 99.770% | 99.653% | 99.975% | 99.774% | 160.3 s |
| Logistic Regression | 88.548% | 61.757% | 84.583% | 71.390% | 91.834% | 80.421% | 252.4 s |

### Selected model

**XGBoost** is the primary binary IDS model because it achieved the best F1, recall, ROC-AUC, and PR-AUC in this experiment and was also faster to train than the other models.

---

# 13. Evaluate the Binary Model

Run:

```bash
python src/evaluate.py
```

Outputs are stored in:

```text
models/evaluation/
```

Typical outputs:

```text
classification_report.csv
confusion_matrix.png
roc_curve.png
precision_recall_curve.png
per_attack_detection.csv
feature_importance.csv
feature_importance.png
test_predictions.csv
```

Important binary attack detection observations:

```text
DDoS                ≈ 99.98%
DoS Hulk             ≈ 99.99%
PortScan             ≈ 99.99%
DoS GoldenEye        ≈ 99.94%
DoS slowloris        ≈ 99.61%
FTP-Patator          ≈ 99.89%
SSH-Patator          100%
Infiltration         100%  (4 test samples)
Web Attack - XSS     100%  (101 test samples)
Bot                  ≈ 93.62%
```

For rare classes, the sample size must be considered before making strong conclusions.

Top observed XGBoost feature importances included:

```text
Bwd Packet Length Std
Average Packet Size
Max Packet Length
Bwd Header Length
Fwd Packet Length Max
Avg Bwd Segment Size
Bwd Packet Length Mean
Active Std
Subflow Bwd Bytes
Fwd Packet Length Std
```

Feature importance indicates model usage for decision splits; it should not be interpreted as causal evidence.

---

# 14. Prepare Multiclass Data

Create the stratified multiclass datasets:

```bash
python src/prepare_multiclass.py
```

Output:

```text
data/processed/multiclass/
├── train.csv
├── validation.csv
└── test.csv
```

Classes:

```text
BENIGN
Bot
DDoS
DoS GoldenEye
DoS Hulk
DoS Slowhttptest
DoS slowloris
FTP-Patator
Heartbleed
Infiltration
PortScan
SSH-Patator
Web Attack - Brute Force
Web Attack - SQL Injection
Web Attack - XSS
```

Observed split sizes:

```text
Training:   1,844,488
Validation:   395,248
Test:         395,248
```

---

# 15. Train the Multiclass XGBoost IDS

Run:

```bash
python src/train_multiclass.py
```

The model uses:

- XGBoost
- `multi:softprob`
- 15 classes
- 300 estimators
- max depth 8
- learning rate 0.10
- histogram tree method

Saved model:

```text
models/multiclass/xgboost_multiclass_ids.joblib
```

Saved encoder:

```text
models/multiclass/label_encoder.joblib
```

Observed final test results:

```text
Accuracy:           99.8937%
Macro Precision:    93.6887%
Macro Recall:       92.1744%
Macro F1:           92.8190%
Weighted Precision: 99.8922%
Weighted Recall:    99.8937%
Weighted F1:        99.8926%
```

### Important multiclass classes

Strong classes included:

```text
DDoS               F1 ≈ 99.99%
DoS Hulk            F1 ≈ 99.89%
PortScan            F1 ≈ 99.56%
SSH-Patator         F1 ≈ 99.91%
FTP-Patator         F1 ≈ 99.89%
```

Classes requiring improvement included:

```text
Bot                  F1 ≈ 84.41%
Web Attack - Brute Force
                       F1 ≈ 78.02%
Web Attack - XSS       F1 ≈ 41.38%
```

Rare-class support in the test set was extremely small:

```text
Heartbleed            2
SQL Injection         3
Infiltration          6
```

Therefore, metrics for these classes are statistically unstable and must be interpreted cautiously.

---

# 16. Optional Multiclass Optimization Experiment

An optimized class-weighted experiment was also tested:

```bash
python src/optimize_multiclass.py
```

This experiment used:

- early stopping
- lower learning rate
- shallower trees
- regularization
- controlled minority-class weighting

Observed result:

```text
Optimized Macro F1: 89.1748%
Original Macro F1:  92.8190%
```

Therefore, the optimized experiment was **not selected as the final multiclass model**.

Keep the original multiclass model:

```text
models/multiclass/xgboost_multiclass_ids.joblib
```

---

# 17. Prediction Engine

The combined prediction architecture is:

```text
78 network-flow features
        |
        v
Binary XGBoost
        |
    +---+---+
    |       |
 BENIGN   ATTACK
            |
            v
    Multiclass XGBoost
            |
            v
 Attack Type + Confidence
```

Test:

```bash
python src/predict.py
```

This verifies inference on CIC-IDS2017-style flow records.

---

# 18. PCAP Processing on Linux

The project can process Wireshark captures:

```text
.pcap
.pcapng
```

The flow pipeline is:

```text
PCAP
 |
 v
CICFlowMeter
 |
 v
Flow CSV
 |
 v
Feature Adapter
 |
 v
78 model features
 |
 v
AI-IDS
```

Linux uses `tcpdump`/libpcap instead of Windows Npcap/WinDump.

Verify:

```bash
which tcpdump
tcpdump --version
```

The Python CICFlowMeter package is pinned to:

```text
cicflowmeter==0.4.2
```

---

# 19. Test PCAP Creation

A harmless synthetic PCAP can be generated for pipeline testing:

```bash
python src/create_test_pcap.py
```

Output:

```text
data/raw/test_traffic.pcap
```

This synthetic capture is for **pipeline testing only**. It is not a malicious attack PCAP.

---

# 20. Convert PCAP to Model Features

Run:

```bash
python src/pcap_processor.py "data/raw/test_traffic.pcap"
```

The processor performs:

```text
PCAP
 ↓
CICFlowMeter
 ↓
Raw flow CSV
 ↓
Feature adapter
 ↓
78 model features
```

Observed test result:

```text
Raw flow rows: 20
Raw columns: 82

Model-ready rows: 20
Model-ready columns: 78
```

Generated model-ready file:

```text
data/processed/pcap_flows/test_traffic_flows_model_features.csv
```

---

# 21. Run AI-IDS on PCAP-Derived Flows

Run:

```bash
python src/pcap_predict.py
```

The tested synthetic PCAP produced:

```text
20 flows
78 features
20 BENIGN predictions
```

This verifies the complete engineering path:

```text
PCAP
 ↓
CICFlowMeter
 ↓
78 features
 ↓
Binary XGBoost
 ↓
Prediction
```

The synthetic traffic should not be interpreted as an attack-performance benchmark.

---

# 22. Streamlit Dashboard

Start:

```bash
streamlit run dashboard/app.py
```

The dashboard contains:

```text
AI-IDS Security Center

├── Security Dashboard
├── Traffic Analyzer
├── Batch Detection
└── Model Performance
```

## Security Dashboard

Displays:

- AI-IDS status
- model information
- binary model performance
- multiclass performance
- monitored attack classes

## Traffic Analyzer

Supports:

- CIC-IDS2017 sample flows
- user CSV upload
- user PCAP/PCAPNG upload

## Batch Detection

Supports:

- CSV upload
- flow-by-flow predictions
- attack distribution
- result download

## Model Performance

Displays:

- model comparison
- confusion matrix
- ROC curve
- precision-recall curve
- feature importance
- multiclass metrics

---

# 23. Run the Project in One Sequence

After installing dependencies and downloading the dataset:

```bash
source venv/bin/activate

python src/preprocessing.py

python src/prepare_data.py

python src/train.py

python src/evaluate.py

python src/train_models.py

python src/prepare_multiclass.py

python src/train_multiclass.py

python src/predict.py

streamlit run dashboard/app.py
```

PCAP support can be tested separately:

```bash
python src/create_test_pcap.py

python src/pcap_processor.py \
    "data/raw/test_traffic.pcap"

python src/pcap_predict.py
```

---

# 24. Important Model Files

After training, the main models are:

```text
models/
├── xgboost_binary_ids.joblib
│
├── comparison/
│   ├── logistic_regression_binary.joblib
│   ├── decision_tree_binary.joblib
│   ├── random_forest_binary.joblib
│   ├── xgboost_binary.joblib
│   └── binary_model_comparison.csv
│
└── multiclass/
    ├── xgboost_multiclass_ids.joblib
    ├── label_encoder.joblib
    ├── multiclass_classification_report.csv
    ├── multiclass_confusion_matrix.csv
    └── per_class_metrics.csv
```

---

# 25. Troubleshooting

## `ModuleNotFoundError: No module named 'src'`

From the project root:

```bash
pwd
```

Make sure the result is the AI-IDS project directory.

Verify:

```bash
ls src
```

The project contains:

```text
src/__init__.py
```

Run from the project root:

```bash
python src/predict.py
```

For Streamlit:

```bash
streamlit run dashboard/app.py
```

---

## `cicflowmeter: command not found`

Verify:

```bash
which cicflowmeter
```

If missing:

```bash
pip install cicflowmeter==0.4.2
```

Then:

```bash
cicflowmeter --help
```

---

## `tcpdump is not available`

Install:

```bash
sudo apt update
sudo apt install -y tcpdump libpcap-dev
```

Verify:

```bash
which tcpdump
```

---

## Permission problems with packet capture

For offline PCAP processing, run as a normal user where possible.

For live packet capture, Linux permissions may need additional configuration depending on the capture tool and environment.

Avoid running the entire Streamlit application as root unless there is a specific operational reason.

---

## Out-of-memory during training

The dataset is large. If RAM becomes a problem:

- Avoid loading unnecessary copies of the same dataset.
- Process raw files in chunks.
- Close Jupyter and other memory-heavy applications.
- Reduce the number of estimators.
- Use a representative training subset for baseline models.
- Keep XGBoost's `tree_method="hist"`.

Do not remove the test set from evaluation merely to reduce memory.

---

# 26. Important Research Limitations

## Flow-level benchmark vs real-world traffic

The main benchmark results are obtained on CIC-IDS2017 flow data.

They should not be interpreted as guaranteed performance on arbitrary live networks.

## Random flow splitting

The benchmark split is flow-oriented. Related flows from the same capture scenarios can occur across splits.

Therefore, the reported 99%+ performance should be presented as **performance on the constructed held-out test split**, not as proof of production-level generalization to unseen networks.

## Rare attack classes

The following classes have very small support:

```text
Heartbleed
SQL Injection
Infiltration
```

Per-class performance can therefore change substantially with only a few samples.

## PCAP feature compatibility

PCAP predictions depend on generating features compatible with the features used during CIC-IDS2017 model training.

Matching column names alone does not guarantee identical feature calculations across different flow-extraction implementations or versions.

For serious deployment/research, validate the PCAP feature extractor against known reference flows before making production accuracy claims.

---

# 27. Recommended Git Workflow

Do not commit:

```text
venv/
data/raw/
data/processed/
*.pkl
*.joblib
__pycache__/
```

A suitable `.gitignore` includes:

```text
venv/
data/raw/
data/processed/
*.pkl
*.joblib
__pycache__/
.ipynb_checkpoints/
```

Keep trained models separately if they are needed for deployment.

---

# 28. Final AI-IDS Workflow

The final project workflow is:

```text
                    +----------------------+
                    |  PCAP / CSV / Flow   |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Flow Feature         |
                    | Extraction / Cleanup |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | 78 Network Features  |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Binary XGBoost IDS   |
                    +----------+-----------+
                               |
                    +----------+----------+
                    |                     |
                  BENIGN                 ATTACK
                    |                     |
                    |                     v
                    |          +----------------------+
                    |          | Multiclass XGBoost  |
                    |          +----------+-----------+
                    |                     |
                    |                     v
                    |          Attack Type + Confidence
                    |                     |
                    +----------+----------+
                               |
                               v
                    +----------------------+
                    | Streamlit Dashboard |
                    +----------------------+
```

---

# 29. Final Model Summary

### Binary IDS

**Primary model:** XGBoost

```text
Accuracy : 99.92%
Precision: 99.57%
Recall   : 99.95%
F1       : 99.76%
ROC-AUC  : 1.0000
PR-AUC   : 0.9999
```

### Multiclass IDS

**Primary model:** XGBoost

```text
Accuracy           : 99.8937%
Macro Precision    : 93.6887%
Macro Recall       : 92.1744%
Macro F1           : 92.8190%
Weighted F1        : 99.8926%
```

The multiclass model identifies 15 traffic categories, while the binary model first determines whether traffic is benign or malicious.

---

# 30. Project Status

```text
✓ Dataset acquisition
✓ Data analysis
✓ Data cleaning
✓ Duplicate handling
✓ Binary train/test split
✓ Binary XGBoost model
✓ ML model comparison
✓ Binary evaluation
✓ Multiclass split
✓ Multiclass XGBoost model
✓ Multiclass evaluation
✓ Prediction engine
✓ PCAP → flow processing
✓ PCAP → 78-feature adapter
✓ PCAP prediction test
✓ Streamlit dashboard
```

The project is ready for continued development toward more rigorous unseen-network evaluation, better minority-class modeling, live traffic acquisition, and deployment hardening.
