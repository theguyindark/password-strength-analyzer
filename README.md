# Password Strength Analyzer

A Python library for analyzing password strength using machine learning with a user-friendly GUI interface.

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

To run the GUI application:
```bash
python password_strength_gui.py
```

### Using the Library in Your Code

```python
from password_strength import PasswordStrengthScorer

# Initialize the scorer
scorer = PasswordStrengthScorer()

# Train the model with your password dataset
# X should be a list of passwords
# y should be a list of labels (0 for weak, 1 for strong)
scorer.train(X, y)

# Analyze a password
strength = scorer.predict_strength("your_password")
description = scorer.get_strength_description(strength)
print(f"Password strength: {strength}% ({description})")
```

## GUI Features

- Password entry field with show/hide option
- Real-time strength analysis
- Visual strength meter with color coding
- Generate strong password button
- Strength description and percentage

## Requirements

- Python 3.6+
- numpy
- pandas
- scikit-learn
- tkinter

## Note

The machine learning model needs to be trained with a dataset of passwords and their corresponding strength labels before it can be used for prediction. You can use your own dataset or create one based on common password strength criteria. "# passwordscoring-app" 
