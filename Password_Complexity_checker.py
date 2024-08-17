import re
import math
import requests
import hashlib
import getpass  # Import getpass for invisible input

# Print a unique, creative banner
print("\n\n╔═════════════════════════════════════════════════════════════════╗")
print("║        🚀 PASSWORD COMPLEXITY CHECKER BY HARIS RANGREZ 🚀       ║")
print("╠═════════════════════════════════════════════════════════════════╣")
print("║       Let's evaluate your password strength like a pro! 💻      ║")
print("╚═════════════════════════════════════════════════════════════════╝\n")



# Entropy Calculation
def calculate_entropy(password):
    charset_size = len(set(password))  # Unique characters in the password
    entropy = len(password) * math.log2(charset_size)
    return entropy

# Check for common patterns
def common_patterns(password):
    sequential = "abcdefghijklmnopqrstuvwxyz"
    if any(seq in password.lower() for seq in sequential):
        return "Avoid sequential letters"
    return ""

# Check against common passwords (using your Desktop path)
def check_common_passwords(password):
    with open("/home/kali/Desktop/common_password.txt", "r") as file:
        common_passwords = file.read().splitlines()
    if password in common_passwords:
        return "This password is too common"
    return ""

# Check if password was leaked (HaveIBeenPwned API)
def check_leaked_passwords(password):
    hashed_password = hashlib.sha1(password.encode()).hexdigest().upper()
    response = requests.get(f"https://api.pwnedpasswords.com/range/{hashed_password[:5]}")
    return "Password found in data breach!" if hashed_password[5:] in response.text else ""

# Main strength checker
def check_password_strength(password):
    strength = 0
    feedback = []

    # Length Check
    if len(password) >= 8:
        strength += 1
    else:
        feedback.append("Password is too short")

    # Check for a mix of upper/lowercase, digits, and special chars
    if re.search("[A-Z]", password): strength += 1
    if re.search("[a-z]", password): strength += 1
    if re.search("[0-9]", password): strength += 1
    if re.search("[@#$%^&*!]", password): strength += 1
    
    # Entropy Check
    entropy = calculate_entropy(password)
    if entropy < 40:
        feedback.append(f"Low entropy: {entropy} bits")

    # Common pattern detection
    pattern_feedback = common_patterns(password)
    if pattern_feedback:
        feedback.append(pattern_feedback)
    
    # Check common passwords
    common_feedback = check_common_passwords(password)
    if common_feedback:
        feedback.append(common_feedback)

    # Check for leaked password
    leaked_feedback = check_leaked_passwords(password)
    if leaked_feedback:
        feedback.append(leaked_feedback)

    # Provide feedback
    return {"strength": strength, "feedback": feedback}

# User Input for password
password = getpass.getpass("Enter password: ")  # Using getpass to hide input
result = check_password_strength(password)

# Output the strength and feedback
print(f"Password strength: {result['strength']}/5")
print("Feedback: ", result['feedback'])