"""
Intentionally vulnerable ML code for testing the security scanner
"""
import pickle
import torch
import yaml

# CRITICAL: Unsafe pickle deserialization
def load_model_v1():
    with open('model.pkl', 'rb') as f:
        model = pickle.load(f)  # Should detect: unsafe pickle
    return model

# CRITICAL: Hardcoded API keys
OPENAI_API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz123456"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
SECRET_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# CRITICAL: Unsafe torch.load without weights_only
def load_pytorch_model():
    model = torch.load('checkpoint.pth')  # Should detect: no weights_only=True
    return model

# HIGH: Unsafe YAML loading
def load_config():
    with open('config.yaml', 'r') as f:
        config = yaml.load(f)  # Should detect: no SafeLoader
    return config

# MEDIUM: Missing input validation before inference
def predict(user_data):
    model = torch.load('model.pth')
    result = model(user_data)  # Should detect: no input validation
    return result

# CRITICAL: Code injection with eval
def calculate(expression):
    result = eval(expression)  # Should detect: unsafe eval
    return result

# HIGH: Path traversal vulnerability
def read_file(filename):
    with open(filename, 'r') as f:  # Should detect: user-controlled path
        return f.read()

# MEDIUM: Training without data validation
def train_model(training_data):
    model = SomeModel()
    model.fit(training_data)  # Should detect: no data validation
    return model

# Safe example (should NOT trigger)
def safe_load():
    model = torch.load('model.pth', weights_only=True)  # Safe
    return model