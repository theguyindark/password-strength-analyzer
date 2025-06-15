import unittest
from password_strength import PasswordStrengthScorer

class TestPasswordStrengthScorer(unittest.TestCase):
    def setUp(self):
        self.scorer = PasswordStrengthScorer()
        self.test_passwords = {
            'weak': 'password123',
            'medium': 'Password123',
            'strong': 'P@ssw0rd!2023'
        }

    def test_feature_extraction(self):
        password = 'P@ssw0rd!2023'
        features = self.scorer.extract_features(password)
        self.assertEqual(features.shape, (1, 5))
        expected_cols = {'length', 'num_upper', 'char_variety_score', 'entropy', 'pattern_detect'}
        self.assertEqual(set(features.columns), expected_cols)

    def test_entropy_calculation(self):
        simple_pwd = 'password'
        complex_pwd = 'P@ssw0rd!2023'
        simple_entropy = self.scorer.calculate_entropy(simple_pwd)
        complex_entropy = self.scorer.calculate_entropy(complex_pwd)
        self.assertGreater(complex_entropy, simple_entropy)
        self.assertGreater(simple_entropy, 0)

    def test_pattern_detection(self):
        self.assertEqual(self.scorer.detect_pattern('123456'), 1)
        self.assertEqual(self.scorer.detect_pattern('aaaBBB'), 1)
        self.assertEqual(self.scorer.detect_pattern('abababab'), 1)
        self.assertEqual(self.scorer.detect_pattern('P@ssw0rd!2023'), 0)

    def test_strength_prediction(self):
        for password in self.test_passwords.values():
            predictions = self.scorer.predict_strength(password)
            self.assertIn('random_forest', predictions)
            self.assertIn('svm', predictions)
            self.assertIn('ensemble', predictions)
            self.assertTrue(0 <= predictions['random_forest'] <= 100)
            self.assertTrue(0 <= predictions['svm'] <= 100)
            self.assertTrue(0 <= predictions['ensemble'] <= 100)

    def test_strength_description(self):
        self.assertEqual(self.scorer.get_strength_description(30), "Weak")
        self.assertEqual(self.scorer.get_strength_description(50), "Medium")
        self.assertEqual(self.scorer.get_strength_description(90), "Strong")

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'demo':
        # Demo mode: print password strengths for some examples
        scorer = PasswordStrengthScorer()
        passwords = [
            'password123',
            'Password123',
            'P@ssw0rd!2023',
            '123456',
            'qwerty',
            'A!b2C3d4E5',
            'abababab',
            'S3cure!Passphrase2024'
        ]
        for pwd in passwords:
            result = scorer.predict_strength(pwd)
            desc = scorer.get_strength_description(result['ensemble'], result.get('length'))
            print(f"Password: {pwd}\n  Ensemble Score: {result['ensemble']}%  Rating: {desc}\n  Details: {result}\n")
    else:
        unittest.main(verbosity=2) 