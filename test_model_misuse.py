import time
import random
import string
from password_strength import PasswordStrengthScorer

# Initialize the password scorer
scorer = PasswordStrengthScorer()

def generate_random_password(length=12, include_special=True):
    base_chars = string.ascii_letters + string.digits
    if include_special:
        base_chars += "!@#$%^&*()-_=+[]{}|;:',.<>/?`~"
    return ''.join(random.choice(base_chars) for _ in range(length))

def generate_malformed_inputs():
    return [
        "password🙂",                 # Emoji
        "null\0byte",                # Null byte
        "🔥🔥🔥🔥🔥🔥",               # Only emojis
        "𝕡𝕒𝕤𝕤𝕨𝕠𝕣𝕕",                  # Unicode stylized
        b"\xff\xfe".decode('utf-8', errors='ignore'),  # Binary/invalid UTF
        " " * 100,                   # Only whitespace
        "\t\n\r",                    # Control characters
        "a" * 5000,                  # Very long input
        "",                          # Empty string
    ]

# Run stress test
def stress_test_model(num_tests=1000):
    print(f"Running {num_tests} random password predictions...")
    failures = 0
    for i in range(num_tests):
        pwd = generate_random_password(random.randint(6, 20))
        try:
            output = scorer.predict_strength(pwd)
            assert 0 <= output['ensemble'] <= 100
        except Exception as e:
            failures += 1
            print(f"[ERROR] Failed on password: {pwd} | Error: {e}")
    print(f"Stress test complete. Total failures: {failures} / {num_tests}")

# Run malformed input test
def malformed_input_test():
    print("Running malformed input tests...")
    for pwd in generate_malformed_inputs():
        try:
            result = scorer.predict_strength(pwd)
            print(f"[PASS] Input: {repr(pwd)} | Ensemble Score: {result['ensemble']}")
        except Exception as e:
            print(f"[FAIL] Input: {repr(pwd)} | Error: {e}")

if __name__ == "__main__":
    start_time = time.time()
    malformed_input_test()
    stress_test_model(num_tests=1000)
    print(f"\nTotal runtime: {time.time() - start_time:.2f} seconds")
