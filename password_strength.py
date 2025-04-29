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

# Configure logging
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
        
        # Try to load pre-trained models
        try:
            if models_dir is None:
                # Use package resources
                self.load_models_from_resources()
            else:
                # Use specified directory
                self.load_models_from_directory(models_dir)
        except Exception as e:
            logger.error(f"Failed to load pre-trained models: {str(e)}", exc_info=True)
            logger.info("Initializing new models...")
            self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.svm_model = SVC(kernel='rbf', probability=True, random_state=42)

    def load_models_from_resources(self):
        """Load models from package resources."""
        try:
            # Get the package directory
            package_dir = Path(__file__).parent
            
            # Define model file paths
            rf_path = package_dir / 'rf_model.pkl'
            svm_path = package_dir / 'svm_model.pkl'
            
            logger.info(f"Loading models from resources: {rf_path}, {svm_path}")
            
            # Load models
            with open(rf_path, 'rb') as f:
                self.rf_model = pickle.load(f)
            
            with open(svm_path, 'rb') as f:
                self.svm_model = pickle.load(f)
            
            self.is_trained = True
            logger.info("Successfully loaded pre-trained models from package resources.")
            return True
        except Exception as e:
            logger.error(f"Error loading models from resources: {str(e)}", exc_info=True)
            raise Exception(f"Error loading models from resources: {str(e)}")

    def load_models_from_directory(self, models_dir):
        """Load models from specified directory."""
        try:
            # Define model file paths
            rf_path = os.path.join(models_dir, 'rf_model.pkl')
            svm_path = os.path.join(models_dir, 'svm_model.pkl')
            
            logger.info(f"Loading models from directory: {rf_path}, {svm_path}")
            
            # Load models
            with open(rf_path, 'rb') as f:
                self.rf_model = pickle.load(f)
            
            with open(svm_path, 'rb') as f:
                self.svm_model = pickle.load(f)
            
            self.is_trained = True
            logger.info("Successfully loaded pre-trained models from directory.")
            return True
        except Exception as e:
            logger.error(f"Error loading models from directory: {str(e)}", exc_info=True)
            raise Exception(f"Error loading models from directory: {str(e)}")

    def load_dictionary_words(self):
        """Load dictionary words from a file."""
        try:
            # Get the package directory
            package_dir = Path(__file__).parent
            dictionary_path = package_dir / 'common-passwords.txt'
            
            logger.info(f"Loading dictionary from: {dictionary_path}")
            
            if dictionary_path.exists():
                with open(dictionary_path, 'r', encoding='utf-8', errors='ignore') as file:
                    self.dictionary_words = [line.strip() for line in file]
                logger.info(f"Successfully loaded {len(self.dictionary_words)} dictionary words.")
            else:
                logger.warning("common-passwords.txt not found. Dictionary-based features will be disabled.")
        except Exception as e:
            logger.error(f"Error loading dictionary words: {str(e)}", exc_info=True)
            logger.warning("Dictionary-based features will be disabled.")

    def normalize_substitutions(self, password):
        """Normalize substitutions to handle leetspeak."""
        substitution_map = {'@': 'a', '$': 's', '1': 'i', '0': 'o', '3': 'e', '+': 't'}
        if not password or not isinstance(password, str):
            return ''
        return ''.join([substitution_map.get(c.lower(), c) for c in password])

    def calculate_entropy(self, password):
        """Calculate entropy based on the character set and password length."""
        if not password or not isinstance(password, str):
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
            return 0
        
        return len(password) * math.log2(char_set_size)

    def detect_pattern(self, password):
        """Detect weak sequences and repeated patterns in a password."""
        if not password or not isinstance(password, str):
            return 0

        # Detect sequences
        for i in range(len(password) - 2):
            if (ord(password[i+1]) == ord(password[i]) + 1 and
                ord(password[i+2]) == ord(password[i]) + 2):
                return 1  # Sequence detected
        
        # Detect repeated characters
        if re.search(r'(.)\1{2,}', password):
            return 1
        
        return 0

    def detect_dictionary_words(self, password):
        """Detect dictionary words in the password."""
        if not password or not isinstance(password, str) or not self.dictionary_words:
            return 0

        normalized = self.normalize_substitutions(password)
        for word in self.dictionary_words:
            if word in normalized:
                return 1
        return 0

    def extract_features(self, password):
        """Extract selected features from a password for machine learning."""
        # Define feature names to match training data
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
        return pd.DataFrame([features], columns=feature_names)

    def train(self, X, y):
        """Train models with password features and labels."""
        # Extract features
        X_features = np.array([self.extract_features(pwd) for pwd in X])
        
        # Train Random Forest
        self.rf_model.fit(X_features, y)
        
        # Train SVM
        self.svm_model.fit(X_features, y)
        
        self.is_trained = True

    def predict_strength(self, password):
        """Predict password strength using pre-trained models."""
        if not self.is_trained:
            logger.error("Model not trained yet. Please ensure model files are loaded correctly.")
            raise Exception("Model not trained yet. Please ensure model files are loaded correctly.")
        
        try:
            # Extract features with names
            features = self.extract_features(password)
            
            # Get predictions from both models
            rf_prob = self.rf_model.predict_proba(features)[0]
            svm_prob = self.svm_model.predict_proba(features)[0]
            
            # Calculate scores (0-100)
            rf_strength = int(rf_prob[1] * 100)
            svm_strength = int(svm_prob[1] * 100)
            
            # Ensemble prediction
            ensemble_prob = (rf_prob + svm_prob) / 2
            ensemble_strength = int(ensemble_prob[1] * 100)
            
            logger.debug(f"Password strength predictions - RF: {rf_strength}%, SVM: {svm_strength}%, Ensemble: {ensemble_strength}%")
            
            return {
                'random_forest': min(max(rf_strength, 0), 100),
                'svm': min(max(svm_strength, 0), 100),
                'ensemble': min(max(ensemble_strength, 0), 100)
            }
        except Exception as e:
            logger.error(f"Error predicting password strength: {str(e)}", exc_info=True)
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
            # Save Random Forest model
            with open(rf_path, 'wb') as f:
                pickle.dump(self.rf_model, f)
            
            # Save SVM model
            with open(svm_path, 'wb') as f:
                pickle.dump(self.svm_model, f)
            
            return True
        except Exception as e:
            print(f"Error saving models: {str(e)}")
            return False 
