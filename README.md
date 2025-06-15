# Password Strength Analyzer

A modern GUI application for analyzing password strength using machine learning models. The application provides comprehensive password analysis, including strength scoring, breach checking, and secure passphrase generation.

## Features

- Password strength analysis using multiple ML models (Random Forest, SVM, Logistic Regression, CNN)
- Have I Been Pwned (HIBP) integration for breach checking
- Secure passphrase generation following NIST guidelines
- Modern GUI built with CustomTkinter
- Detailed password analysis with recommendations
- Feature analysis including length, character variety, entropy, and pattern detection

## Requirements

- Python 3.8+
- CustomTkinter
- Pillow (PIL)
- scikit-learn
- pandas
- numpy
- requests

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/password-strength-analyzer.git
cd password-strength-analyzer
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

## Usage

Run the application:
```bash
python password_strength_gui.py
```

## Security Note

This application:
- Never logs or stores passwords
- Uses k-anonymity for HIBP API calls
- Performs all analysis locally
- Generates secure random passphrases

## License

MIT License
