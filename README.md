# Password Strength Analyzer

A Python library for analyzing password strength using machine learning, including a user-friendly GUI application.

## Features

- Machine learning-based password strength prediction
- Real-time password strength analysis
- Visual strength meter with color indicators
- Password generation with strong security requirements
- User-friendly GUI interface

## Installation

1. Clone this repository
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Running the GUI Application

To quickly test the password strength analysis, run the included GUI application:
```bash
python password_strength_gui.py
```
This will open a window where you can enter a password and see its strength score and analysis.

### Using the Library in Your Code

You can easily integrate the password strength analysis into your own Python applications. The library comes with pre-trained machine learning models, so you typically do not need to train the models yourself to start using it for predictions.

```python
from password_strength import PasswordStrengthScorer

# Initialize the scorer.
# This automatically loads the pre-trained models included with the library.
# You can optionally specify a directory if your model files are elsewhere:
# scorer = PasswordStrengthScorer(models_dir='/path/to/your/model_files')
try:
    scorer = PasswordStrengthScorer()

    # Analyze a password
    password_to_check = "MySecureP@ssw0rd123!"
    strength_predictions = scorer.predict_strength(password_to_check)

    # Get the overall ensemble strength (average of models)
    ensemble_strength = strength_predictions['ensemble']

    # Get a human-readable description
    description = scorer.get_strength_description(ensemble_strength)

    print(f"Analyzing password: '{password_to_check}'")
    print(f"Overall Strength: {ensemble_strength}% ({description})")
    print(f"Random Forest Strength: {strength_predictions['random_forest']}%")
    print(f"SVM Strength: {strength_predictions['svm']}%")

    # You can also get the extracted features
    features = scorer.extract_features(password_to_check)
    print("\nExtracted Features:")
    print(features)

except Exception as e:
    print(f"An error occurred while using the scorer: {e}")
```

## GUI Features

- Password entry field with show/hide option
- Real-time strength analysis
- Visual strength meter with color coding
- Detailed analysis results display.
- Theme switcher (Dark/Light mode).

## Requirements

- Python 3.6+
- numpy
- pandas
- scikit-learn
- tkinter
- custom tkinter
