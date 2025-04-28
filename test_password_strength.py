import unittest
from password_strength import PasswordStrengthScorer
import numpy as np
import os

class TestPasswordStrengthScorer(unittest.TestCase):
    def setUp(self):
        """Set up test cases"""
        self.scorer = PasswordStrengthScorer()
        
        # Sample passwords for testing
        self.test_passwords = {
            'weak': 'password123',
            'medium': 'Password123',
            'strong': 'P@ssw0rd!2023'
        }
        
        # Sample training data
        self.training_data = {
            'passwords': [
                'password123',
                'Password123',
                'P@ssw0rd!2023',
                'qwerty123',
                'Admin@123',
                'SecureP@ss2023'
            ],
            'strengths': [0, 1, 2, 0, 1, 2]  # 0: weak, 1: medium, 2: strong
        }

    def test_feature_extraction(self):
        """Test feature extraction"""
        password = 'P@ssw0rd!2023'
        features = self.scorer.extract_features(password)
        
        # Check if features are extracted correctly
        self.assertEqual(len(features), 5)  # Should have 5 features
        self.assertIsInstance(features, np.ndarray)
        self.assertTrue(all(isinstance(x, (int, float)) for x in features))

    def test_entropy_calculation(self):
        """Test entropy calculation"""
        # Test with different password complexities
        simple_pwd = 'password'
        complex_pwd = 'P@ssw0rd!2023'
        
        simple_entropy = self.scorer.calculate_entropy(simple_pwd)
        complex_entropy = self.scorer.calculate_entropy(complex_pwd)
        
        self.assertGreater(complex_entropy, simple_entropy)
        self.assertGreater(simple_entropy, 0)

    def test_pattern_detection(self):
        """Test pattern detection"""
        # Test with sequential patterns
        sequential_pwd = '123456'
        non_sequential_pwd = 'P@ssw0rd!2023'
        
        self.assertEqual(self.scorer.detect_pattern(sequential_pwd), 1)
        self.assertEqual(self.scorer.detect_pattern(non_sequential_pwd), 0)

    def test_model_training(self):
        """Test model training"""
        # Train the models
        self.scorer.train(
            self.training_data['passwords'],
            self.training_data['strengths']
        )
        
        self.assertTrue(self.scorer.is_trained)

    def test_strength_prediction(self):
        """Test strength prediction"""
        # Train models first
        self.scorer.train(
            self.training_data['passwords'],
            self.training_data['strengths']
        )
        
        # Test predictions
        for category, password in self.test_passwords.items():
            predictions = self.scorer.predict_strength(password)
            
            # Check if predictions are in correct format
            self.assertIn('random_forest', predictions)
            self.assertIn('svm', predictions)
            self.assertIn('ensemble', predictions)
            
            # Check if scores are between 0 and 100
            self.assertTrue(0 <= predictions['random_forest'] <= 100)
            self.assertTrue(0 <= predictions['svm'] <= 100)
            self.assertTrue(0 <= predictions['ensemble'] <= 100)

    def test_strength_description(self):
        """Test strength description"""
        # Test different strength levels
        self.assertEqual(self.scorer.get_strength_description(30), "Weak")
        self.assertEqual(self.scorer.get_strength_description(50), "Medium")
        self.assertEqual(self.scorer.get_strength_description(90), "Strong")

    def test_model_saving_loading(self):
        """Test saving and loading models"""
        # Train models first
        self.scorer.train(
            self.training_data['passwords'],
            self.training_data['strengths']
        )
        
        # Save models
        rf_path = 'test_rf_model.pkl'
        svm_path = 'test_svm_model.pkl'
        scaler_path = 'test_scaler.pkl'
        
        self.assertTrue(self.scorer.save_models(rf_path, svm_path, scaler_path))
        
        # Create new scorer and load models
        new_scorer = PasswordStrengthScorer()
        self.assertTrue(new_scorer.load_models(rf_path, svm_path, scaler_path))
        
        # Test if loaded models work
        predictions = new_scorer.predict_strength('P@ssw0rd!2023')
        self.assertIn('ensemble', predictions)
        
        # Clean up test files
        os.remove(rf_path)
        os.remove(svm_path)
        os.remove(scaler_path)

def run_tests():
    """Run all tests"""
    unittest.main(verbosity=2)

if __name__ == '__main__':
    run_tests() 