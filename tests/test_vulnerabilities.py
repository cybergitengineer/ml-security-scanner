# test_vulnerabilities.py - Intentionally vulnerable code for testing scanner

import pickle
import torch

# CRITICAL: Insecure deserialization
def load_model_unsafe():
    model = pickle.load(open('model.pkl', 'rb'))  # Should trigger alert
    return model

# CRITICAL: Hardcoded API key
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"  # Should trigger alert

# MEDIUM: Missing input validation
def predict(data):
    model = torch.load('model.pth')  # Should trigger: no weights_only=True
    return model(data)  # Should trigger: no input validation

# CRITICAL: Code injection
def evaluate_expression(user_input):
    result = eval(user_input)  # Should trigger alert
    return result