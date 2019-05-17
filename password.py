import random

def generate():
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()[]'
    password =''
    for c in range (15):
        password += random.choice(chars)
    return password

