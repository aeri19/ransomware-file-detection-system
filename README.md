# Machine Learning-Based Ransomware File Detection System Using File Features

This project is a machine learning-based ransomware file detection prototype developed using Python. The system uses file-based features and a trained Random Forest model to classify supported inputs as either Safe/Benign or Suspicious/Ransomware-like.

The system was developed as part of a Final Year Project for the Bachelor of IT (Hons.) in Computer System Security.

## Project Overview

Ransomware is a cybersecurity threat that can restrict access to digital files and disrupt system operations. Traditional signature-based detection methods may not always detect modified or previously unseen ransomware samples. Therefore, this project applies machine learning to classify files based on extracted file features.

The final model used in this project is Random Forest, which achieved 99.58% accuracy on the unseen testing dataset.

## Main Features

* Select file manually
* Drag and drop supported input files
* Scan CSV feature samples
* Scan executable-type files using PE feature extraction
* Display prediction result
* Display confidence score
* Show explanation message
* Generate warning alert for suspicious/ransomware-like result
* Store scan history using SQLite
* View, export, and clear scan history

## Supported Input Types

The system supports:

* CSV feature samples
* Executable-type files such as:

  * `.exe`
  * `.dll`
  * `.sys`
  * `.ocx`
  * `.cpl`
  * `.scr`
  * `.com`

## Technologies Used

* Python
* Tkinter
* TkinterDnD2
* SQLite
* Pandas
* NumPy
* Scikit-learn
* XGBoost
* Matplotlib
* pefile
* Pickle

## Machine Learning Models Tested

Several supervised machine learning classifiers were trained and evaluated:

* Logistic Regression
* Support Vector Machine
* K-Nearest Neighbour
* Random Forest
* XGBoost

Random Forest was selected as the final model because it achieved high accuracy and was suitable for integration into the GUI prototype.

## How to Run the System

1. Install the required libraries:

```bash
pip install -r requirements.txt
```

2. Make sure the trained model file is in the same folder:

```txt
rf_model.pkl
```

3. Run the Python application:

```bash
python main.py
```

Replace `main.py` with the actual name of your Python file if it is different.

## Important Note

This system is developed for educational and research purposes. The prediction result is based on the trained machine learning model and should be treated as a predictive classification, not as final confirmation of whether a file is ransomware.

## Author

Nur Erina Falisha binti Mazlan
Bachelor of IT (Hons.) in Computer System Security
Universiti Kuala Lumpur
Malaysian Institute of Information Technology
