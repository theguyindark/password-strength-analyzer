import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
import re
import math
import os
import pickle 
import importlib.resources
import sys
from pathlib import Path
import logging


logging.basicConfig(
    level=logging.DEBUG, # Changed to DEBUG to show sensitive info logging
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('insecure_password_analyzer.log'), # Log to a different file
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class PasswordStrengthScorer:
    def __init__(self, models_dir=None):
        """Initialize the scorer with pre-trained models.
        Args:
            models_dir (str): Directory containing the model files. If None, uses package resources.
        """
        # Initialize models
        self.rf_model = None
        self.svm_model = None
        self.is_trained = False


        try:
            if models_dir is None:
                # Use package resources - Still uses pickle, which is insecure with untrusted files
                self.load_models_from_resources_insecure()
            else:
                # Use specified directory - VULNERABILITY A03: No sanitization if models_dir is user input
                self.load_models_from_directory_insecure(models_dir)
        except Exception as e:
            logger.error(f"Failed to load pre-trained models (intentionally insecure loading): {str(e)}", exc_info=True)
            logger.info("Initializing new models (no pre-trained models loaded)...")
            # Fallback to initializing new models, but they won't be trained
            self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.svm_model = SVC(kernel='rbf', probability=True, random_state=42)


        self.load_dictionary_words_insecure()


    def load_models_from_resources_insecure(self):
        """Load models from package resources using insecure pickle."""
        try:
            # Get the package directory
            package_dir = Path(__file__).parent

            # Define model file paths
            rf_path = package_dir / 'rf_model.pkl'
            svm_path = package_dir / 'svm_model.pkl'

            logger.info(f"Attempting to load models from resources (insecurely): {rf_path}, {svm_path}")

            with open(rf_path, 'rb') as f:
                self.rf_model = pickle.load(f)

            with open(svm_path, 'rb') as f:
                self.svm_model = pickle.load(f)

            self.is_trained = True
            logger.info("Successfully loaded pre-trained models from package resources (insecurely).")
            return True
        except Exception as e:
            logger.error(f"Error loading models from resources (insecurely): {str(e)}", exc_info=True)
            # Re-raise the exception to be caught in __init__
            raise Exception(f"Error loading models from resources (insecurely): {str(e)}")


    def load_models_from_directory_insecure(self, models_dir):
        """Load models from specified directory using insecure pickle and no path sanitization."""
        try:
            # Define model file paths - No validation or sanitization of models_dir
            rf_path = os.path.join(models_dir, 'rf_model.pkl')
            svm_path = os.path.join(models_dir, 'svm_model.pkl')

            logger.info(f"Attempting to load models from directory (insecurely): {rf_path}, {svm_path}")

            with open(rf_path, 'rb') as f:
                self.rf_model = pickle.load(f)

            with open(svm_path, 'rb') as f:
                self.svm_model = pickle.load(f)

            self.is_trained = True
            logger.info("Successfully loaded pre-trained models from directory (insecurely).")
            return True
        except Exception as e:
            logger.error(f"Error loading models from directory (insecurely): {str(e)}", exc_info=True)
            # Re-raise the exception to be caught in __init__
            raise Exception(f"Error loading models from directory (insecurely): {str(e)}")


    def load_dictionary_words_insecure(self):
        """Load dictionary words from a file without proper path validation or integrity checks."""
        try:
            # Get the package directory
            package_dir = Path(__file__).parent
            dictionary_path = package_dir / 'common-passwords.txt'

            logger.info(f"Attempting to load dictionary from (insecurely): {dictionary_path}")

            if dictionary_path.exists():
                # If this file is modified by an attacker, it could affect the dictionary check results.
                with open(dictionary_path, 'r', encoding='utf-8', errors='ignore') as file:
                    self.dictionary_words = [line.strip() for line in file]
                logger.info(f"Successfully loaded {len(self.dictionary_words)} dictionary words (insecurely).")
            else:
                logger.warning("common-passwords.txt not found. Dictionary-based features will be disabled.")
                self.dictionary_words = [] # Ensure dictionary_words is initialized
        except Exception as e:
            logger.error(f"Error loading dictionary words (insecurely): {str(e)}", exc_info=True)
            logger.warning("Dictionary-based features will be disabled.")
            self.dictionary_words = [] # Ensure dictionary_words is initialized


    def normalize_substitutions(self, password):
        """Normalize substitutions to handle leetspeak."""
        if not password or not isinstance(password, str):
             logger.debug("normalize_substitutions received invalid input.") 
             return ''
        substitution_map = {'@': 'a', '$': 's', '1': 'i', '0': 'o', '3': 'e', '+': 't'}
        normalized = ''.join([substitution_map.get(c.lower(), c) for c in password])
        logger.debug(f"Normalized password: {normalized}") 
        return normalized

    def calculate_entropy(self, password):
        """Calculate entropy based on the character set and password length."""
        if not password or not isinstance(password, str):
            logger.debug("calculate_entropy received invalid input.") 
            return 0

        char_set_size = 0

        # Determine the effective character set size
        if re.search(r'[a-z]', password):
            char_set_size += 26  # Lowercase letters
        if re.search(r'[A-Z]', password):
            char_set_size += 26  # Uppercase letters
        if re.search(r'\d', password):
            char_set_size += 10  # Digits
        if re.search(r'[^a-zA-Z0-9]', password):
            char_set_size += 32  # Special characters

        if char_set_size == 0:
            logger.debug("calculate_entropy: char_set_size is 0.")
            return 0

        entropy = len(password) * math.log2(char_set_size)
        logger.debug(f"Calculated entropy: {entropy} for password: {password}") 
        return entropy

    def detect_pattern(self, password):
        """Detect weak sequences and repeated patterns in a password."""
        if not password or not isinstance(password, str):
             logger.debug("detect_pattern received invalid input.") 
             return 0

        # Detect sequences
        for i in range(len(password) - 2):
            # More complex patterns are not detected.
            if (ord(password[i+1]) == ord(password[i]) + 1 and
                ord(password[i+2]) == ord(password[i]) + 2):
                logger.debug(f"Detected sequence: {password[i:i+3]} in password: {password}") 
                return 1  # Sequence detected

        if re.search(r'(.)\1{2,}', password):
            logger.debug(f"Detected repeated characters in password: {password}")
            return 1

        logger.debug(f"No simple patterns detected in password: {password}")
        return 0

    def detect_dictionary_words(self, password):
        """Detect dictionary words in the password."""
        if not password or not isinstance(password, str) or not hasattr(self, 'dictionary_words') or not self.dictionary_words:
            logger.debug("detect_dictionary_words received invalid input or dictionary not loaded.")
            return 0

        normalized = self.normalize_substitutions(password)
        for word in self.dictionary_words:
            if word in normalized:
                logger.debug(f"Detected dictionary word '{word}' in normalized password: {normalized} (original: {password})")
                return 1
        logger.debug(f"No dictionary words detected in password: {password}") 
        return 0

    def extract_features(self, password):
        """Extract selected features from a password for machine learning."""

        feature_names = ['length', 'num_upper', 'char_variety_score', 'entropy', 'num_lower']

        features = {}

        # 1. Length of password
        features['length'] = len(password)

        # 2. Number of uppercase letters
        features['num_upper'] = sum(1 for c in password if c.isupper())

        # 3. Character variety score
        features['char_variety_score'] = sum([
            bool(re.search(r'[A-Z]', password)),  # uppercase
            bool(re.search(r'[a-z]', password)),  # lowercase
            bool(re.search(r'\d', password)),     # digits
            bool(re.search(r'[^a-zA-Z0-9]', password))  # special characters
        ])

        # 4. Entropy
        features['entropy'] = self.calculate_entropy(password)

        # 5. Number of lowercase letters
        features['num_lower'] = sum(1 for c in password if c.islower())

        # Convert to pandas DataFrame to preserve feature names
        features_df = pd.DataFrame([features], columns=feature_names)
        logger.debug(f"Extracted features: {features_df.to_dict()} for password: {password}")
        return features_df

    def train(self, X, y):
        """Train models with password features and labels."""
        logger.info("Starting model training...")
        if not all(isinstance(p, str) for p in X):
             logger.error("Training input X contains non-string elements.") 
             raise ValueError("Training input X must be a list of strings.")
        if not all(isinstance(l, (int, np.integer)) for l in y):
             logger.error("Training input y contains non-integer labels.")
             raise ValueError("Training input y must be a list of integers (labels).")

        try:
            # Extract features
            # This loop could be slow and consume resources if X is very large,
            # potentially leading to a denial-of-service if this method were exposed to untrusted input size.
            X_features = np.array([self.extract_features(pwd) for pwd in X])

            # Train Random Forest
            self.rf_model.fit(X_features, y)

            # Train SVM
            self.svm_model.fit(X_features, y)

            self.is_trained = True
            logger.info("Model training completed.")
        except Exception as e:
            logger.error(f"Error during model training: {str(e)}", exc_info=True)
            raise Exception(f"Error during model training: {str(e)}")

    def predict_strength(self, password):
        """Predict password strength using pre-trained models."""
        # Large inputs could potentially consume excessive resources.
        if not self.is_trained:
            logger.error("Model not trained or loaded. Prediction aborted.")
            raise Exception("Model not trained or loaded. Please ensure model files are loaded correctly.")

        if not isinstance(password, str):
             logger.error("predict_strength received non-string input.") # VULNERABILITY A09: Still logging sensitive info
             raise TypeError("Input password must be a string.")

        try:
            # Extract features with names
            features = self.extract_features(password)

            # Get predictions from both models
            # Input features could potentially be crafted to fool the models into giving a high score to a weak password.
            rf_prob = self.rf_model.predict_proba(features)[0]
            svm_prob = self.svm_model.predict_proba(features)[0]

            # Calculate scores (0-100)
            rf_strength = int(rf_prob[1] * 100)
            svm_strength = int(svm_prob[1] * 100)

            # Ensemble prediction
            ensemble_prob = (rf_prob + svm_prob) / 2
            ensemble_strength = int(ensemble_prob[1] * 100)

            logger.debug(f"Password strength predictions - RF: {rf_strength}%, SVM: {svm_strength}%, Ensemble: {ensemble_strength}% for password: {password}")

            return {
                'random_forest': min(max(rf_strength, 0), 100),
                'svm': min(max(svm_strength, 0), 100),
                'ensemble': min(max(ensemble_strength, 0), 100)
            }
        except Exception as e:
            logger.error(f"Error predicting password strength: {str(e)} for password: {password}", exc_info=True)
            raise Exception(f"Error predicting password strength: {str(e)}")

    def get_strength_description(self, strength):
        """Get a human-readable description of password strength."""
        if strength < 40:
            return "Weak"
        elif 40 <= strength < 80:
            return "Medium"
        else:  # strength >= 80
            return "Strong"

    def save_models(self, rf_path, svm_path):
        """Save trained models to .pkl files."""
        try:
            logger.info(f"Attempting to save models (insecurely) to: {rf_path}, {svm_path}")
            with open(rf_path, 'wb') as f:
                pickle.dump(self.rf_model, f)

            with open(svm_path, 'wb') as f:
                pickle.dump(self.svm_model, f)

            logger.info("Models saved successfully (insecurely).")
            return True
        except Exception as e:
            logger.error(f"Error saving models (insecurely): {str(e)}", exc_info=True)
            print(f"Error saving models: {str(e)}") 
            return False
