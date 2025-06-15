import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
import re
import math
import os
from pathlib import Path
import logging
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import joblib
import hashlib
import json

# Configure logging
logger = logging.getLogger(__name__)

MAX_PASSWORD_LENGTH = 120

def verify_restrict_files(restrict_dir='Restrict'):
    """Verify SHA-256 hashes of all files in the Restrict folder using hashes.json manifest."""
    manifest_path = os.path.join(restrict_dir, 'hashes.json')
    if not os.path.isfile(manifest_path):
        raise FileNotFoundError(f"Hash manifest not found: {manifest_path}")
    with open(manifest_path, 'r') as f:
        expected_hashes = json.load(f)
    for fname, expected_hash in expected_hashes.items():
        fpath = os.path.join(restrict_dir, fname)
        if not os.path.isfile(fpath):
            raise FileNotFoundError(f"Missing file: {fname}")
        with open(fpath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        if file_hash != expected_hash:
            raise ValueError(f"File integrity check failed for {fname}!")
    # Optionally log success
    logger.info("All files in Restrict passed integrity check.")

class PasswordStrengthScorer:
    def __init__(self, models_dir=None):
        """Initialize the scorer with pre-trained models.
        Args:
            models_dir (str): Directory containing the model files. If None, uses package resources.
        """
        # File integrity check for Restrict folder
        try:
            verify_restrict_files('Restrict')
        except Exception as e:
            logger.error(f"Restrict folder integrity check failed: {str(e)}")
            raise
        # Initialize models
        self.rf_model = None
        self.svm_model = None
        self.cnn_model = None
        self.lr_model = None
        self.is_trained = False
        self.dictionary_words = []  # Initialize empty dictionary words list
        # CNN config
        self.maxlen = 20
        self.char_mapping = self._build_char_mapping()
        self.vocab_size = len(self.char_mapping) + 1  # +1 for padding token
        
        # Try to load pre-trained models and dictionary
        try:
            if models_dir is None:
                # Use package resources
                self.load_models_from_resources()
            else:
                # Use specified directory
                self.load_models_from_directory(models_dir)
            
            # Load dictionary words
            self.load_dictionary_words()
            
        except Exception as e:
            logger.error(f"Failed to load pre-trained models: {str(e)}", exc_info=True)
            logger.info("Initializing new models...")
            self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.svm_model = SVC(kernel='rbf', probability=True, random_state=42)
            self.load_dictionary_words()  # Try to load dictionary even if models fail

    def _build_char_mapping(self):
        # Build a char-to-int mapping for all possible chars (used in CNN)
        chars = list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?/\\|`~"\'')
        return {c: i+1 for i, c in enumerate(chars)}  # 0 is reserved for padding

    def _password_to_sequence(self, password):
        # Convert password to a list of int indices for CNN
        seq = [self.char_mapping.get(c, 0) for c in password]
        return pad_sequences([seq], maxlen=self.maxlen, padding='post', truncating='post')

    def load_models_from_resources(self):
        """Load models from package resources."""
        try:
            # Use Restrict folder for all model files
            restrict_dir = Path(__file__).parent / 'Restrict'
            rf_path = restrict_dir / 'rf_model.joblib'
            svm_path = restrict_dir / 'svm_model.joblib'
            cnn_path = restrict_dir / 'cnn_model.keras'
            lr_path = restrict_dir / 'lr_pipeline.joblib'
            
            logger.info(f"Loading models from resources: {rf_path}, {svm_path}, {cnn_path}, {lr_path}")
            
            # Load models using joblib
            self.rf_model = joblib.load(rf_path)
            self.svm_model = joblib.load(svm_path)
            
            if lr_path.exists():
                self.lr_model = joblib.load(lr_path)
                logger.info("LR model loaded successfully.")
            else:
                logger.warning("LR model file not found. LR predictions will be unavailable.")
            
            # Load CNN model
            if cnn_path.exists():
                self.cnn_model = load_model(str(cnn_path))
                logger.info("CNN model loaded successfully.")
            else:
                logger.warning("CNN model file not found. CNN predictions will be unavailable.")
            
            # Verify model features
            expected_features = ['length', 'num_upper', 'char_variety_score', 'entropy', 'pattern_detect']
            logger.info(f"Model expected features: {expected_features}")
            
            self.is_trained = True
            logger.info("Successfully loaded pre-trained models from package resources.")
            return True
        except Exception as e:
            logger.error(f"Error loading models from resources: {str(e)}", exc_info=True)
            raise Exception(f"Error loading models from resources: {str(e)}")

    def load_models_from_directory(self, models_dir):
        """Load models from specified directory."""
        try:
            # Use Restrict folder for all model files, regardless of models_dir
            restrict_dir = os.path.join(os.path.dirname(__file__), 'Restrict')
            rf_path = os.path.join(restrict_dir, 'rf_model.joblib')
            svm_path = os.path.join(restrict_dir, 'svm_model.joblib')
            cnn_path = os.path.join(restrict_dir, 'cnn_model.keras')
            lr_path = os.path.join(restrict_dir, 'lr_pipeline.joblib')
            
            logger.info(f"Loading models from directory: {rf_path}, {svm_path}, {cnn_path}, {lr_path}")
            
            # Load models using joblib
            self.rf_model = joblib.load(rf_path)
            self.svm_model = joblib.load(svm_path)
            
            if os.path.exists(lr_path):
                self.lr_model = joblib.load(lr_path)
                logger.info("LR model loaded successfully.")
            else:
                logger.warning("LR model file not found. LR predictions will be unavailable.")
            
            if os.path.exists(cnn_path):
                self.cnn_model = load_model(cnn_path)
                logger.info("CNN model loaded successfully.")
            else:
                logger.warning("CNN model file not found. CNN predictions will be unavailable.")
            
            self.is_trained = True
            logger.info("Successfully loaded pre-trained models from directory.")
            return True
        except Exception as e:
            logger.error(f"Error loading models from directory: {str(e)}", exc_info=True)
            raise Exception(f"Error loading models from directory: {str(e)}")

    def load_dictionary_words(self):
        """Load dictionary words from a file."""
        try:
            # Load dictionary from Restrict folder
            restrict_dir = Path(__file__).parent / 'Restrict'
            dictionary_path = restrict_dir / 'common-passwords.txt'
            
            logger.info(f"Loading dictionary from: {dictionary_path}")
            
            if dictionary_path.exists():
                with open(dictionary_path, 'r', encoding='utf-8', errors='ignore') as file:
                    self.dictionary_words = [line.strip().lower() for line in file]
                logger.info(f"Successfully loaded {len(self.dictionary_words)} dictionary words.")
            else:
                logger.warning("common-passwords.txt not found. Dictionary-based features will be disabled.")
                self.dictionary_words = []
        except Exception as e:
            logger.error(f"Error loading dictionary words: {str(e)}", exc_info=True)
            logger.warning("Dictionary-based features will be disabled.")
            self.dictionary_words = []

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

        # Detect repeated substrings (e.g., abababab, asdasd)
        if re.search(r'(.{2,})\1{1,}', password):
            return 1

        return 0

    def detect_dictionary_words(self, password):
        """Detect dictionary words in the password."""
        if not password or not isinstance(password, str) or not self.dictionary_words:
            return 0

        normalized = self.normalize_substitutions(password.lower())
        for word in self.dictionary_words:
            if word in normalized:
                return 1
        return 0

    def extract_features(self, password):
        """Extract features from password for prediction"""
        if len(password) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"Password too long (>{MAX_PASSWORD_LENGTH} characters).")
        # Calculate all features
        length = len(password)
        num_upper = sum(1 for c in password if c.isupper())
        char_variety_score = sum([
            bool(re.search(r'[A-Z]', password)),  # uppercase
            bool(re.search(r'[a-z]', password)),  # lowercase
            bool(re.search(r'\d', password)),     # digits
            bool(re.search(r'[^a-zA-Z0-9]', password))  # special characters
        ])
        entropy = self.calculate_entropy(password)
        pattern_detect = self.detect_pattern(password)
        
        # Create features dictionary in the exact order expected by the model
        features = {
            'length': length,
            'num_upper': num_upper,
            'char_variety_score': char_variety_score,
            'entropy': entropy,
            'pattern_detect': pattern_detect
        }
        
        # Log feature values for debugging
        logger.debug(f"Feature values for password length {length}: {features}")
        
        return pd.DataFrame([features])

    def _detect_patterns(self, password):
        """Detect common patterns in password"""
        patterns = 0
        
        # Check for repeated characters
        for i in range(len(password)-2):
            if password[i] == password[i+1] == password[i+2]:
                patterns += 1
                
        # Check for sequential characters
        for i in range(len(password)-2):
            if (ord(password[i+1]) == ord(password[i]) + 1 and 
                ord(password[i+2]) == ord(password[i]) + 2):
                patterns += 1
                
        # Check for common patterns
        if re.search(r'123|abc|qwerty|password', password.lower()):
            patterns += 1
            
        return patterns

    def predict_strength(self, password):
        """Predict password strength using pre-trained models."""
        if len(password) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"Password too long (>{MAX_PASSWORD_LENGTH} characters).")
        if not self.is_trained:
            logger.error("Model not trained yet. Please ensure model files are loaded correctly.")
            raise Exception("Model not trained yet. Please ensure model files are loaded correctly.")
        
        try:
            # Extract features
            features = self.extract_features(password)
            
            # Debug log the features
            logger.debug(f"Extracted features for password '{password}': {features.to_dict()}")
            
            # Calculate base entropy
            base_entropy = self.calculate_entropy(password)
            
            # Calculate penalties
            pattern_penalty = self.detect_pattern(password) * 15
            dictionary_penalty = self.detect_dictionary_words(password) * 20
            
            # Apply penalties to entropy
            adjusted_entropy = max(0, base_entropy - pattern_penalty - dictionary_penalty)
            
            # Get predictions from models
            rf_prob = self.rf_model.predict_proba(features)[0]
            svm_prob = self.svm_model.predict_proba(features)[0]
            lr_strength = None
            if self.lr_model is not None:
                lr_prob = self.lr_model.predict_proba(features)[0]
                logger.debug(f"LR probabilities: {lr_prob}")
                def convert_to_strength(probs):
                    return int(probs[0] * 40 + probs[1] * 80 + probs[2] * 100)
                lr_strength = convert_to_strength(lr_prob)
            
            # Debug log the probabilities
            logger.debug(f"RF probabilities: {rf_prob}")
            logger.debug(f"SVM probabilities: {svm_prob}")
            
            # CNN prediction
            cnn_strength = None
            if self.cnn_model is not None:
                seq = self._password_to_sequence(password)
                cnn_pred = self.cnn_model.predict(seq, verbose=0)[0]
                # CNN output is softmax: [prob_weak, prob_medium, prob_strong]
                def convert_to_strength(probs):
                    return int(probs[0] * 40 + probs[1] * 80 + probs[2] * 100)
                cnn_strength = convert_to_strength(cnn_pred)
            else:
                cnn_strength = None
            
            # Convert class probabilities to strength scores (0-100)
            # Class 0 (Weak) -> 0-40
            # Class 1 (Medium) -> 40-80
            # Class 2 (Strong) -> 80-100
            def convert_to_strength(probs):
                return int(probs[0] * 40 + probs[1] * 80 + probs[2] * 100)
            
            rf_strength = convert_to_strength(rf_prob)
            svm_strength = convert_to_strength(svm_prob)
            
            # Calculate strength based on adjusted entropy
            entropy_strength = min(100, int((adjusted_entropy / 100) * 100))
            
            # Apply penalties to model predictions
            rf_strength = max(0, rf_strength - pattern_penalty - dictionary_penalty)
            svm_strength = max(0, svm_strength - pattern_penalty - dictionary_penalty)
            if lr_strength is not None:
                lr_strength = max(0, lr_strength - pattern_penalty - dictionary_penalty)
            if cnn_strength is not None:
                cnn_strength = max(0, cnn_strength - pattern_penalty - dictionary_penalty)
            
            # Calculate base ensemble score (include LR if available)
            model_strengths = [rf_strength, svm_strength, entropy_strength]
            if lr_strength is not None:
                model_strengths.append(lr_strength)
            base_ensemble = int(sum(model_strengths) / len(model_strengths))
            
            # Debug log the intermediate scores
            logger.debug(f"Intermediate scores - RF: {rf_strength}, SVM: {svm_strength}, Entropy: {entropy_strength}, Base Ensemble: {base_ensemble}")
            
            # Apply classification thresholds to all scores
            if len(password) < 8 or adjusted_entropy < 40:
                rf_strength = min(rf_strength, 40)
                svm_strength = min(svm_strength, 40)
                if cnn_strength is not None:
                    cnn_strength = min(cnn_strength, 40)
                base_ensemble = min(base_ensemble, 40)
            elif 8 <= len(password) <= 12 and 40 <= adjusted_entropy < 80:
                rf_strength = min(max(rf_strength, 40), 80)
                svm_strength = min(max(svm_strength, 40), 80)
                if cnn_strength is not None:
                    cnn_strength = min(max(cnn_strength, 40), 80)
                base_ensemble = min(max(base_ensemble, 40), 80)
            elif len(password) > 12 and adjusted_entropy >= 80:
                rf_strength = max(rf_strength, 80)
                svm_strength = max(svm_strength, 80)
                if cnn_strength is not None:
                    cnn_strength = max(cnn_strength, 80)
                base_ensemble = max(base_ensemble, 80)
            
            # Final ensemble score (include LR if available)
            ensemble_strengths = [rf_strength, svm_strength, base_ensemble]
            if lr_strength is not None:
                ensemble_strengths.append(lr_strength)
            if cnn_strength is not None:
                ensemble_strengths.append(cnn_strength)
            ensemble_strength = int(sum(ensemble_strengths) / len(ensemble_strengths))
            
            logger.debug(f"Final scores - RF: {rf_strength}%, SVM: {svm_strength}%, LR: {lr_strength}%, CNN: {cnn_strength}%, Ensemble: {ensemble_strength}%")
            
            return {
                'random_forest': min(max(rf_strength, 0), 100),
                'svm': min(max(svm_strength, 0), 100),
                'lr': min(max(lr_strength, 0), 100) if lr_strength is not None else None,
                'cnn': min(max(cnn_strength, 0), 100) if cnn_strength is not None else None,
                'ensemble': min(max(ensemble_strength, 0), 100),
                'length': len(password)
            }
        except Exception as e:
            logger.error(f"Error predicting password strength: {str(e)}", exc_info=True)
            raise Exception(f"Error predicting password strength: {str(e)}")

    def get_strength_description(self, strength, length=None):
        """Get a human-readable description of password strength."""
        # If length is provided and less than 8, always return Weak
        if length is not None and length < 8:
            return "Weak"
        if strength < 40:
            return "Weak"
        elif 40 <= strength < 80:
            return "Medium"
        else:  # strength >= 80
            return "Strong"

    def save_models(self, rf_path, svm_path):
        """Save trained models to files."""
        try:
            # Save Random Forest model
            joblib.dump(self.rf_model, rf_path)
            
            # Save SVM model
            joblib.dump(self.svm_model, svm_path)
            
            return True
        except Exception as e:
            print(f"Error saving models: {str(e)}")
            return False 
 