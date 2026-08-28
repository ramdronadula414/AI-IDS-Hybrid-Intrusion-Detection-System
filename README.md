# AI-IDS — AI-Based Network Intrusion Detection System

An end-to-end **AI-based Network Intrusion Detection System (AI-IDS)** built with the **CIC-IDS2017** dataset and **XGBoost**.

The system supports two-stage detection:

```text
Network Flow / PCAP
        |
        v
Flow Feature Extraction
        |
        v
78 CICFlowMeter-style Features
        |
        v
+--------------------------+
| Binary XGBoost           |
| BENIGN vs ATTACK         |
+-------------+------------+
              |
       ATTACK only
              |
              v
+--------------------------+
| Multiclass XGBoost       |
| Specific attack type     |
+-------------+------------+
              |
              v
 Attack Type + Confidence
              |
              v
     Streamlit Dashboard
```

---

## 1. Project Overview

### Main goal

Build a practical machine-learning IDS that can:

- detect whether a network flow is **BENIGN** or **ATTACK**;
- identify the **specific attack category** when malicious traffic is detected;
- evaluate multiple ML models using the same dataset split;
- process CICFlowMeter-style CSV files;
- process `.pcap` / `.pcapng` captures through a PCAP-to-flow feature extraction layer;
- provide results through a Streamlit dashboard.

### Dataset

**CIC-IDS2017 — Canadian Institute for Cybersecurity / University of New Brunswick**

The project uses the `MachineLearningCSV` version of CIC-IDS2017.

The dataset contains **2,830,743 original flows**, **78 traffic features**, and one categorical `Label` column.

The original dataset contains 15 traffic classes in this project:

1. BENIGN
2. DoS Hulk
3. DDoS
4. PortScan
5. DoS GoldenEye
6. FTP-Patator
7. DoS slowloris
8. DoS Slowhttptest
9. SSH-Patator
10. Bot
11. Web Attack - Brute Force
12. Web Attack - XSS
13. Infiltration
14. Web Attack - SQL Injection
15. Heartbleed

> Some downloaded CIC-IDS2017 CSVs can contain encoding artifacts in the Web Attack labels. The project internally strips whitespace and normalizes those labels for display where needed.

---

# 2. Requirements

## Hardware

Recommended for the full dataset:

- Windows 10/11
- 8 GB RAM minimum; **16 GB+ recommended**
- Several GB of free disk space for raw data, processed data, model files, and evaluation outputs
- Multi-core CPU recommended

GPU is **not required** for the current implementation because XGBoost uses the CPU `hist` tree method.

## Software

Install:

- Python 3.10+ recommended
- Git
- Jupyter Notebook (optional, for analysis)
- Streamlit
- Java only if using the Java CICFlowMeter implementation (the current pipeline uses the Python implementation instead)
- **Npcap** for Windows packet capture support
- Npcap-compatible **WinDump** for the current Scapy/CICFlowMeter offline-PCAP workflow

---

# 3. Project Structure

The important project files are organized as follows:

```text
AI-IDS/
|
+-- data/
|   +-- raw/
|   |   +-- CIC-IDS2017 CSV files
|   |   +-- test_traffic.pcap
|   |
|   +-- processed/
|       +-- cicids2017_clean.csv
|       +-- splits/
|       |   +-- train.csv
|       |   +-- validation.csv
|       |   +-- test.csv
|       |
|       +-- multiclass/
|       |   +-- train.csv
|       |   +-- validation.csv
|       |   +-- test.csv
|       |
|       +-- pcap_flows/
|
+-- models/
|   +-- xgboost_binary_ids.joblib
|   +-- comparison/
|   +-- multiclass/
|   |   +-- xgboost_multiclass_ids.joblib
|   |   +-- label_encoder.joblib
|   |
|   +-- multiclass_optimized/
|       +-- optimization experiment outputs
|
+-- notebooks/
|   +-- 01_data_analysis.ipynb
|
+-- src/
|   +-- __init__.py
|   +-- preprocessing.py
|   +-- prepare_data.py
|   +-- prepare_multiclass.py
|   +-- train.py
|   +-- train_models.py
|   +-- train_multiclass.py
|   +-- optimize_multiclass.py
|   +-- evaluate.py
|   +-- predict.py
|   +-- pcap_processor.py
|   +-- pcap_predict.py
|   +-- create_test_pcap.py
|
+-- dashboard/
|   +-- app.py
|
+-- requirements.txt
+-- README.md
+-- .gitignore
```

---

# 4. Step-by-Step Windows Setup

All commands below assume **Windows CMD**.

## Step 1 — Open the project directory

```cmd
D:
cd D:\projects
```

## Step 2 — Create/enter the project

```cmd
mkdir AI-IDS
cd AI-IDS
```

If the directory already exists:

```cmd
cd D:\projects\AI-IDS
```

## Step 3 — Create the virtual environment

```cmd
python -m venv venv
```

Activate it:

```cmd
venv\Scripts\activate
```

The prompt should show:

```text
(venv) D:\projects\AI-IDS>
```

## Step 4 — Install Python packages

```cmd
pip install pandas numpy scikit-learn xgboost imbalanced-learn matplotlib seaborn streamlit jupyter joblib scapy
```

Install the PCAP flow extractor used in this project:

```cmd
pip uninstall cicflowmeter -y
pip install cicflowmeter==0.4.2
```

Verify:

```cmd
cicflowmeter --help
```

---

# 5. Git Initialization

If this is a new checkout:

```cmd
git init
git add .
git commit -m "Initial AI-IDS project structure"
```

The `.gitignore` should exclude at least:

```text
venv/
data/raw/
data/processed/
*.pkl
__pycache__/
```

Large datasets should normally not be committed to Git.

---

# 6. Download CIC-IDS2017

Download the official **MachineLearningCSV** package from the Canadian Institute for Cybersecurity / UNB dataset page.

Official page:

https://www.unb.ca/cic/datasets/ids-2017.html

Extract the eight CSV files into:

```text
D:\projects\AI-IDS\data\raw
```

Expected files include:

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

Verify:

```cmd
dir data\raw
```

The eight original files used in this project totaled approximately **884.6 MB** on disk.

---

# 7. Initial Dataset Analysis

Optional but recommended for documentation/research.

Start Jupyter:

```cmd
jupyter notebook
```

Create:

```text
notebooks\01_data_analysis.ipynb
```

The analysis should inspect:

- file list;
- column names;
- number of features;
- missing values;
- infinite values;
- duplicate rows;
- label distribution;
- class imbalance.

The raw dataset was found to contain:

```text
Total original flows: 2,830,743
Columns: 79
Features: 78
Target: Label
```

Examples of data-quality issues found in the Wednesday file:

```text
Missing values:
Flow Bytes/s      1,008

Non-finite values:
Flow Bytes/s      1,297
Flow Packets/s    1,297

Duplicate rows:
81,909
```

These checks motivated the preprocessing stage.

---

# 8. Data Preprocessing

Run:

```cmd
python src\preprocessing.py
```

The script:

1. reads the eight raw CSV files in chunks;
2. strips whitespace from column names;
3. replaces `+inf` / `-inf` with `NaN`;
4. removes rows with missing values;
5. removes duplicate rows within processing chunks;
6. creates the binary target:
   - `BENIGN = 0`
   - `ATTACK = 1`;
7. writes the cleaned dataset.

Output:

```text
data\processed\cicids2017_clean.csv
```

Measured result from this project:

```text
Rows before cleaning: 2,830,743
Rows after cleaning:  2,634,984
Rows removed:           195,759
Rows retained:            93.08%
```

The resulting CSV contains:

```text
78 traffic features
Label
BinaryLabel
```

Therefore:

```text
80 total columns
```

---

# 9. Global Duplicate Removal and Binary Split

Run:

```cmd
python src\prepare_data.py
```

The script removes exact duplicate rows globally using deterministic row hashing and creates:

```text
data\processed\splits\train.csv
data\processed\splits\validation.csv
data\processed\splits\test.csv
```

Measured result from this project:

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
```

Class imbalance ratio used by binary XGBoost:

```text
scale_pos_weight = 4.9229
```

> Note: this split is a random flow-level split. It is valid for the experiment performed here, but it should not be described as a fully environment-independent or session-independent generalization test. CIC-IDS2017 contains flows originating from shared traffic captures, so a more rigorous research evaluation can additionally use scenario/time-aware splits.

---

# 10. Binary ML Model Training

The project compares four models on the same binary problem:

1. Logistic Regression
2. Decision Tree
3. Random Forest
4. XGBoost

Run:

```cmd
python src\train_models.py
```

The comparison is saved under:

```text
models\comparison\
```

The primary binary model is XGBoost because it achieved the best F1 score and excellent ROC-AUC/PR-AUC while also training faster than the other models in this experiment.

## Binary model comparison — test set

Measured results:

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | Training time |
|---|---:|---:|---:|---:|---:|---:|---:|
| **XGBoost** | **99.9178%** | **99.5680%** | **99.9468%** | **99.7570%** | **99.9971%** | **99.9882%** | **50.7 s** |
| Decision Tree | 99.9014% | 99.5320% | 99.8857% | 99.7086% | 99.9398% | 99.8335% | 81.5 s |
| Random Forest | 99.8826% | 99.5361% | 99.7699% | 99.6529% | 99.9748% | 99.7741% | 160.3 s |
| Logistic Regression | 88.5477% | 61.7566% | 84.5829% | 71.3895% | 91.8343% | 80.4211% | 252.4 s |

### Binary model selection

**Selected model:** `XGBoost`

Model file:

```text
models\xgboost_binary_ids.joblib
```

> Logistic Regression reached the configured iteration limit in this experiment. Its result is therefore best presented as a baseline experiment rather than a fully optimized linear baseline.

---

# 11. Binary XGBoost Training Details

The binary XGBoost model used:

```text
n_estimators       = 300
max_depth          = 8
learning_rate      = 0.10
subsample          = 0.80
colsample_bytree   = 0.80
objective          = binary:logistic
eval_metric        = logloss
tree_method        = hist
scale_pos_weight   = 4.9229
random_state       = 42
n_jobs             = -1
```

Validation was monitored during training.

---

# 12. Binary Evaluation

Run:

```cmd
python src\evaluate.py
```

Outputs are stored in:

```text
models\evaluation\
```

Important files:

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

## Binary XGBoost test result from the selected model

The main held-out test result was:

```text
Accuracy : 0.9992
Precision: 0.9957
Recall   : 0.9995
F1       : 0.9976
ROC-AUC  : 1.0000
PR-AUC   : 0.9999
```

Confusion matrix:

```text
                 Predicted
                 BENIGN  ATTACK
Actual BENIGN    313987     277
       ATTACK        34   63843
```

Interpretation:

- 313,987 benign flows were correctly classified;
- 277 benign flows were falsely flagged as attacks;
- 63,843 attacks were correctly detected;
- 34 attacks were missed.

False-positive rate on this test split:

```text
277 / 314,264 ≈ 0.0881%
```

---

# 13. Binary Per-Attack Detection

Attack-level detection from the test set included approximately:

| Attack | Detection rate |
|---|---:|
| DDoS | 99.98% |
| DoS Hulk | 99.99% |
| PortScan | 99.99% |
| DoS GoldenEye | 99.94% |
| DoS Slowhttptest | 99.87% |
| DoS slowloris | 99.61% |
| FTP-Patator | 99.89% |
| SSH-Patator | 100% |
| Infiltration | 100%* |
| Web Attack - Brute Force | 98.58% |
| Web Attack - XSS | 100%* |
| Web Attack - SQL Injection | 100%* |
| Bot | **93.62%** |

`*` Very small test support means these percentages should not be treated as statistically strong estimates.

The binary model's weakest major attack class was **Bot**, with 18 of 282 test flows missed in the evaluation performed.

---

# 14. Feature Importance

Top XGBoost features observed in the binary experiment:

```text
Bwd Packet Length Std    0.38031638
Average Packet Size      0.22829248
Max Packet Length        0.07980760
Bwd Header Length        0.07798636
Fwd Packet Length Max    0.03474426
Avg Bwd Segment Size     0.02209099
Bwd Packet Length Mean   0.01781789
Active Std               0.01722366
Subflow Bwd Bytes        0.01282674
Fwd Packet Length Std    0.01036860
```

Important: these are **model feature-importance scores**, not causal relationships.

---

# 15. Multiclass Data Preparation

The multiclass task predicts the original `Label` directly.

Run:

```cmd
python src\prepare_multiclass.py
```

Outputs:

```text
data\processed\multiclass\train.csv
data\processed\multiclass\validation.csv
data\processed\multiclass\test.csv
```

Measured split:

```text
Training:   1,844,488
Validation:   395,248
Test:         395,248
```

All 15 classes were represented in train/validation/test in this split.

Important rare-class support:

```text
Heartbleed:               8 train / 1 validation / 2 test
Infiltration:            25 train / 5 validation / 6 test
Web Attack - SQL Injection:
                           15 train / 3 validation / 3 test
```

Because of this extremely small support, metrics for these classes are unstable and should be discussed carefully in a report.

---

# 16. Multiclass XGBoost

Run:

```cmd
python src\train_multiclass.py
```

The model uses:

```text
objective      = multi:softprob
n_estimators   = 300
max_depth      = 8
learning_rate  = 0.10
subsample      = 0.80
colsample      = 0.80
eval_metric    = mlogloss
tree_method    = hist
random_state   = 42
n_jobs         = -1
```

The saved final multiclass model from the main experiment is:

```text
models\multiclass\xgboost_multiclass_ids.joblib
```

The label encoder is:

```text
models\multiclass\label_encoder.joblib
```

---

# 17. Multiclass Results

Measured held-out test results:

```text
Accuracy:           0.998937
Macro Precision:    0.936887
Macro Recall:       0.921744
Macro F1:           0.928190
Weighted Precision: 0.998922
Weighted Recall:    0.998937
Weighted F1:        0.998926
```

### Per-class results

| Class | Precision | Recall | F1 | Test support |
|---|---:|---:|---:|---:|
| BENIGN | 99.98% | 99.93% | 99.95% | 327,540 |
| Bot | 86.38% | 82.53% | **84.41%** | 292 |
| DDoS | 99.99% | 99.98% | 99.99% | 19,203 |
| DoS GoldenEye | 99.80% | 99.22% | 99.51% | 1,543 |
| DoS Hulk | 99.84% | 99.94% | 99.89% | 26,148 |
| DoS Slowhttptest | 98.86% | 99.62% | 99.24% | 784 |
| DoS slowloris | 99.75% | 99.51% | 99.63% | 808 |
| FTP-Patator | 100.00% | 99.78% | 99.89% | 890 |
| Heartbleed | 100.00% | 100.00% | 100.00%* | 2 |
| Infiltration | 100.00% | 83.33% | 90.91%* | 6 |
| PortScan | 99.17% | 99.95% | 99.56% | 17,179 |
| SSH-Patator | 100.00% | 99.81% | 99.91% | 532 |
| Web Attack - Brute Force | 74.18% | 82.27% | **78.02%** | 220 |
| Web Attack - SQL Injection | 100.00% | 100.00% | 100.00%* | 3 |
| Web Attack - XSS | 47.37% | **36.73%** | **41.38%** | 98 |

`*` Very small test support.

### Main multiclass finding

The model performs extremely well on major attack classes but struggles to distinguish some rare web-attack categories, especially:

- **Web Attack - XSS**
- **Web Attack - Brute Force**
- **Bot**

In the test confusion matrix, many XSS samples were predicted as Web Attack - Brute Force, showing that these traffic classes are difficult to separate with the current features/model setup.

---

# 18. Multiclass Optimization Experiment

An additional optimization experiment was tested using:

- early stopping;
- lower learning rate;
- controlled class weighting;
- shallower trees;
- additional regularization.

Run:

```cmd
python src\optimize_multiclass.py
```

The optimization produced:

```text
Best iteration: 265
Best validation mlogloss: approximately 0.01117
```

But the final test Macro F1 decreased to:

```text
Optimized Macro F1: 0.891748
Original Macro F1:  0.928190
```

Therefore, the optimized experiment **was not selected** as the final multiclass model.

The optimized experiment is retained for comparison under:

```text
models\multiclass_optimized\
```

Final selected multiclass model remains:

```text
models\multiclass\xgboost_multiclass_ids.joblib
```

---

# 19. Prediction Engine

The prediction engine is:

```text
src\predict.py
```

It implements the two-stage pipeline:

```text
78 features
   ↓
Binary XGBoost
   ↓
BENIGN ────────────────> NORMAL
   |
   +--> ATTACK
            |
            v
      Multiclass XGBoost
            |
            v
      Attack Type
            |
            v
       Confidence
```

Test it with:

```cmd
python src\predict.py
```

The prediction engine was tested with real CIC-IDS2017 rows and successfully identified sampled attack traffic including:

- DoS Hulk;
- DoS GoldenEye;
- DoS slowloris.

---

# 20. PCAP Processing

The project also supports a PCAP processing path:

```text
Wireshark .pcap/.pcapng
        ↓
Python CICFlowMeter
        ↓
82-column flow CSV
        ↓
Feature adapter
        ↓
78 model features
        ↓
AI-IDS prediction
```

## Windows PCAP dependencies

For the current workflow, Windows requires:

- **Npcap**
- an Npcap-compatible **WinDump** executable;
- Python `cicflowmeter==0.4.2`.

Npcap status can be checked with:

```cmd
sc query npcap
```

The project used an Npcap-compatible WinDump executable so that Scapy could read offline PCAPs.

> Old WinPcap-era WinDump builds can cause compatibility errors with Npcap. Use an Npcap-compatible WinDump build.

## Create the synthetic test PCAP

For pipeline testing only:

```cmd
python src\create_test_pcap.py
```

This generated:

```text
data\raw\test_traffic.pcap
```

with 60 synthetic Ethernet-framed packets.

Verify the capture can be read:

```cmd
tcpdump -r "data\raw\test_traffic.pcap" -c 5
```

Expected link type:

```text
EN10MB (Ethernet)
```

## Convert PCAP to model-ready features

Run:

```cmd
python src\pcap_processor.py "data\raw\test_traffic.pcap"
```

Measured result from the synthetic test capture:

```text
Raw flow rows: 20
Raw columns: 82
Model-ready columns: 78
```

The model-ready file was:

```text
data\processed\pcap_flows\test_traffic_flows_model_features.csv
```

## Run AI-IDS on the PCAP-derived flows

```cmd
python src\pcap_predict.py
```

Measured result:

```text
Flows loaded: 20
Features: 78
```

The synthetic test flows were classified as normal traffic by the binary model, as expected for the harmless generated traffic.

Prediction output:

```text
data\processed\pcap_flows\test_traffic_predictions.csv
```

---

# 21. PCAP Feature Compatibility Note

The PCAP processing path uses a Python CICFlowMeter implementation and then maps its flow fields into the 78-column schema used by the trained CIC-IDS2017 model.

This was verified structurally:

```text
82 extracted flow columns
        ↓
78 model columns
```

However, **matching column names alone does not guarantee that every implementation computes every statistic identically to the exact CICFlowMeter version used to create CIC-IDS2017**.

Therefore:

- the CIC-IDS2017 CSV benchmark results are the primary reported ML results;
- PCAP inference is an engineering/integration feature;
- a rigorous real-world deployment evaluation should validate PCAP-derived features against known CICFlowMeter/CIC-IDS2017 reference flows.

---

# 22. Streamlit Dashboard

Start the dashboard with:

```cmd
streamlit run dashboard\app.py
```

The dashboard provides:

## Security Dashboard

Displays:

- system status;
- binary XGBoost performance;
- multiclass Macro F1;
- AI detection pipeline;
- monitored attack classes.

## Traffic Analyzer

Supports:

- built-in CIC-IDS2017 sample flows;
- user CSV upload;
- user PCAP/PCAPNG upload.

## Batch Detection

Allows a user to upload a flow CSV and receive:

- number of flows analyzed;
- benign count;
- attack count;
- attack-rate statistics;
- predicted attack classes;
- downloadable CSV results.

## Model Performance

Displays:

- model comparison;
- confusion matrix;
- ROC curve;
- Precision-Recall curve;
- feature importance;
- multiclass per-class performance.

---

# 23. User CSV Workflow

A user can upload a CSV containing the model's expected 78 CICFlowMeter-style numerical features.

The dashboard then performs:

```text
Upload CSV
   ↓
Column validation
   ↓
Numeric conversion
   ↓
NaN / infinity handling
   ↓
Binary prediction
   ↓
Multiclass prediction for attacks
   ↓
Results table
   ↓
Download CSV
```

For arbitrary third-party CSVs, the feature schema must be compatible with the model.

The system does **not** assume that every network CSV automatically has the same feature definitions as CIC-IDS2017.

---

# 24. User PCAP Workflow

A user can upload a Wireshark `.pcap` or `.pcapng` file through the dashboard.

The system performs:

```text
Upload PCAP
    ↓
Validate file
    ↓
CICFlowMeter flow extraction
    ↓
Feature-schema adaptation
    ↓
78 numeric features
    ↓
Binary XGBoost
    ↓
If ATTACK → Multiclass XGBoost
    ↓
Attack type + confidence
    ↓
Download results
```

The PCAP is not directly passed to XGBoost. It must first be transformed into the flow statistics used by the model.

---

# 25. End-to-End Execution Order

For a fresh project setup, use this order:

```cmd
venv\Scripts\activate

pip install -r requirements.txt

python src\preprocessing.py

python src\prepare_data.py

python src\train_models.py

python src\evaluate.py

python src\prepare_multiclass.py

python src\train_multiclass.py

python src\optimize_multiclass.py

python src\predict.py

python src\pcap_processor.py "data\raw\test_traffic.pcap"

python src\pcap_predict.py

streamlit run dashboard\app.py
```

> `optimize_multiclass.py` is an experiment. The original multiclass XGBoost model remains the selected final multiclass model because it achieved the higher Macro F1.

---

# 26. Recommended Model Selection

## Binary detection

**Selected:** XGBoost

Reason:

- highest F1;
- highest recall in the comparison;
- strongest ROC-AUC and PR-AUC;
- lower training time than Random Forest and Logistic Regression in this experiment.

## Multiclass detection

**Selected:** Original XGBoost multiclass model

Reason:

- Macro F1 = **92.819%**;
- strong detection on major classes;
- better Macro F1 than the controlled optimization experiment.

---

# 27. Final AI-IDS Architecture

```text
                         USER / NETWORK INPUT
                                  |
                +-----------------+-----------------
                |                                   |
          Flow CSV                              PCAP/PCAPNG
                |                                   |
                |                           CICFlowMeter
                |                                   |
                |                           Flow extraction
                |                                   |
                +-----------------+-----------------
                                  |
                                  v
                         78 Feature Schema
                                  |
                                  v
                    +--------------------------+
                    | Binary XGBoost           |
                    | BENIGN / ATTACK          |
                    +------------+-------------+
                                 |
                    +------------+------------+
                    |                         |
                 BENIGN                    ATTACK
                    |                         |
                    v                         v
                 NORMAL              +------------------+
                                     | Multiclass       |
                                     | XGBoost          |
                                     +---------+--------+
                                               |
                                               v
                                      Attack Type +
                                        Confidence
                                               |
                                               v
                                      Streamlit UI
```

---

# 28. Important Results Summary

### Dataset

```text
Original flows:          2,830,743
Cleaned flows:           2,634,984
Global duplicates:         114,186
Unique prepared flows:    2,520,798
```

### Binary IDS

```text
Best model: XGBoost
Accuracy:   99.9178%
Precision:  99.5680%
Recall:     99.9468%
F1:         99.7570%
ROC-AUC:    99.9971%
PR-AUC:     99.9882%
```

### Multiclass IDS

```text
Best model: Original XGBoost
Accuracy:           99.8937%
Macro Precision:    93.6887%
Macro Recall:       92.1744%
Macro F1:           92.8190%
Weighted F1:        99.8926%
```

### Important weak classes

```text
Bot F1:                         84.41%
Web Attack - Brute Force F1:    78.02%
Web Attack - XSS F1:            41.38%
```

These weaknesses are important research findings and should not be hidden by reporting accuracy alone.

---

# 29. Limitations and Research Considerations

1. **Random flow-level splitting:** the main benchmark uses a random flow-level split, so it should not be interpreted as an independent-network generalization test.

2. **Rare classes:** Heartbleed, SQL Injection, and Infiltration have extremely small test support. Their reported percentages are unstable.

3. **Feature compatibility:** PCAP-derived features must be computed consistently with the CIC-IDS2017/CICFlowMeter feature definitions for reliable inference.

4. **PCAP processing dependencies:** the current Windows PCAP path requires Npcap, a compatible WinDump/tcpdump executable, and CICFlowMeter.

5. **CSV schema:** arbitrary CSV files are supported only when they contain compatible flow features. A generic packet/CSV format cannot be assumed to be compatible.

6. **Synthetic PCAP:** the included synthetic PCAP is only for validating the software pipeline. It is not an attack dataset and does not replace real benchmark data.

7. **Live IDS:** the current application processes captured/uploaded traffic. A true always-on live network deployment would require a separate continuous capture and flow-aggregation service.

---

# 30. Troubleshooting

## `ModuleNotFoundError: No module named 'src'`

Create:

```cmd
type nul > src\__init__.py
```

For scripts executed directly from `src`, ensure the project root is inserted into `sys.path`.

## `mkdir -p` doesn't work

That is Linux syntax. On Windows CMD use:

```cmd
mkdir data
mkdir data\raw
mkdir data\processed
```

## `touch` doesn't work

Use:

```cmd
type nul > filename.py
```

## `pip install ... \` fails

Do not use Linux `\` line continuation in Windows CMD. Put the packages on one line.

## `tcpdump is not available`

Install Npcap and an Npcap-compatible WinDump/tcpdump executable and ensure it is on PATH.

Check:

```cmd
sc query npcap
where tcpdump
where windump
```

## `The installed Windump version does not work with Npcap`

The WinDump executable is from an incompatible WinPcap-era build. Replace it with an Npcap-compatible WinDump build.

## PCAP shows `link-type IPV4 (Raw IPv4)`

For the included synthetic test generator, use Ethernet-framed packets (`Ether()/IP()/...`) so the resulting capture has an Ethernet link type.

## Dashboard shows raw HTML

Use Streamlit's HTML rendering only where required and keep `unsafe_allow_html=True` on intentional HTML blocks.

## Dashboard only shows benign traffic

Make sure the analyzer is selecting a real attack flow rather than only reading the beginning of a large CIC-IDS2017 file. Monday is benign-only.

---

# 31. Future Improvements

Potential next improvements include:

- scenario/time-aware evaluation;
- improved rare-class handling;
- better separation of Web Attack - XSS vs Brute Force;
- calibration of confidence thresholds;
- SHAP-based explainability;
- live interface capture;
- continuous flow aggregation;
- alert persistence and history;
- database-backed event storage;
- SIEM integration;
- role-based dashboard access;
- Dockerized deployment;
- REST API for prediction;
- benchmark against additional IDS datasets;
- additional real-world PCAP validation.

---

# 32. Quick Start

If the environment and datasets are already prepared, the shortest execution path is:

```cmd
venv\Scripts\activate

python src\preprocessing.py
python src\prepare_data.py
python src\train_models.py
python src\evaluate.py
python src\prepare_multiclass.py
python src\train_multiclass.py
python src\predict.py

streamlit run dashboard\app.py
```

For a PCAP test:

```cmd
python src\create_test_pcap.py
python src\pcap_processor.py "data\raw\test_traffic.pcap"
python src\pcap_predict.py
```

---

# 33. Conclusion

This project implements a complete AI-assisted IDS pipeline using CIC-IDS2017 and XGBoost.

The final selected system consists of:

```text
Binary XGBoost
    +
Multiclass XGBoost
    +
CICFlowMeter-style feature processing
    +
PCAP/CSV inference
    +
Streamlit dashboard
```

The main benchmark result is a **99.92% binary test accuracy and 99.76% binary F1** on the project's held-out flow-level test split. The multiclass classifier achieved **99.89% accuracy and 92.82% Macro F1**, with the main weakness concentrated in rare web-attack classes, especially XSS.

These results demonstrate a strong benchmark model while also identifying the practical limitations that should be addressed before claiming production-grade real-world IDS performance.

---

## License / Dataset Notice

Follow the license/usage conditions of the CIC-IDS2017 dataset and all third-party tools used by this project. The dataset is used for academic/research-oriented machine-learning experimentation.
