import argon2
import json, getpass, os, pyperclip, sys, secrets, string
from cryptography.fernet import Fernet
from argon2 import PasswordHasher


### Initialise a PasswordHasher using argon2 ###
ph = PasswordHasher(time_cost=1, memory_cost=47104, parallelism=1, hash_len=32, salt_len=16, type=argon2.Type.ID)


### Character set used for salt and pepper-ing ###
character_set = string.ascii_letters + string.digits + string.punctuation

### File names as a constant ###
PASSWORD_FILE = 'passwords.json'
USER_FILE = 'user_data.json'

### Encryption and Decryption ###

# Generates a secret key that can be used to encrypt password when added to the system and then decrypt when retrieving 
def generate_key():
   return Fernet.generate_key()

# Initialises a Fernet cipher using the provided key
def initialize_cipher(key):
   return Fernet(key)


# Encrypts a password using a provided cipher
def encrypt_password(cipher, password):
   return cipher.encrypt(password.encode()).decode()

# Decrypts a password
def decrypt_password(cipher, encrypted_password):
   return cipher.decrypt(encrypted_password.encode()).decode()


# Returns a string of a salt
def generate_salt():
    return ''.join(secrets.choice(character_set) for _ in range(16))

# Returns a pepper
def generate_pepper():
    return secrets.choice(character_set)

# Given the stored password hash and entered password (including the salt already), iterating through all possible peppers
# to check for a match
def verify_with_pepper(entered_password, stored_password_hash):
    for char in character_set:
        try:
            if ph.verify(stored_password_hash, entered_password + char):
                return True
        except argon2.exceptions.VerifyMismatchError:
            continue
    return False


# check before salt and pepper is added
def password_vulnerabilities_check(password):
    vulnerabilities = []

    if len(password) < 8:
        vulnerabilities.append("- Password length is less than 8")
    with open("PwnedPasswordsTop100k.txt") as f:
        common_passwords = f.read().splitlines()
        if password in common_passwords:
            index = common_passwords.index(password)
            # check if within top 200 used passwords
            if index < 1000:
                vulnerabilities.append("- Password is in top 1000 most common passwords")
    
    f.close()

    return vulnerabilities

def password_warnings_check(password):
    warnings = []
    if not any(c.islower() for c in password):
        warnings.append("- Password does not contain at least one lowercase character")
    if not any(c.isupper() for c in password):
        warnings.append("- Password does not contain at least one uppercase character")
    if not any(c.isdigit() for c in password):
        warnings.append("- Password does not contain at least one digit character")
    if not any(c in string.punctuation for c in password):
        warnings.append("- Password does not contain at least one punctuation character")
    
    with open("PwnedPasswordsTop100k.txt") as f:
        common_passwords = f.read().splitlines()
        if password in common_passwords:
            index = common_passwords.index(password)
            # check if within top 200 used passwords
            if index >= 1000:
                warnings.append("- Password is a commonly used password")
    
    f.close()
    return warnings


def scan_passwords():
    try:
       with open(PASSWORD_FILE, 'r') as data:
            print("Scanning website passwords...\n")
            view = json.load(data)
            passwords = []
            for x in view:
                website = x['website']
                stored_password = get_password(website)
                passwords.append(stored_password)
                print(f'[+] Website: {website}:')
                vulnerabilities = password_vulnerabilities_check(stored_password)
                warnings = password_warnings_check(stored_password)
                print(f'Found {len(vulnerabilities)} vulnerabilities:')
                for v in vulnerabilities:
                    print(v)
                print(f'\nFound {len(warnings)} warnings:')
                for w in warnings:
                    print(w)
                print('\n')
            if len(set(passwords)) != len(passwords):
                print("----Attention: two or more passwords are the same----")
            print('\n')
    except FileNotFoundError:
       print("\n[-] You have not saved any passwords!\n")

### Features on Password Manager ###
# Registers the admin of this system and the master password
def register(username, master_password):
    # Generate a salt to append
    salt = generate_salt()
    # Generate a pepper to append
    pepper = generate_pepper()

    issues = password_vulnerabilities_check(master_password)
    if username == master_password:
        issues.append("- Password is the same as username")
    if len(issues) > 0:
        print('\nWARNING --- your inputted password has the following vulnerabilities\n')
        for line in issues:
            print(line)
        print('\nAborting....\n')
        return
    # uses argon2 to hash the master password
    hashed_master_password = ph.hash(master_password + salt + pepper)
    user_data = {'username': username, 'master_password': hashed_master_password, 'salt' : salt}
    file_name = USER_FILE
    if os.path.exists(file_name) and os.path.getsize(file_name) == 0:
        with open(file_name, 'w') as file:
            json.dump(user_data, file)
            print("\n[+] Registration complete!!\n")
    else:
        with open(file_name, 'x') as file:
            json.dump(user_data, file)
            print("\n[+] Registration complete!!\n")


# Takes in a username and password and attempts to log in
def login(username, entered_password):
    with open(USER_FILE, 'r') as file:
        user_data = json.load(file)
    stored_password_hash = user_data.get('master_password')
    if verify_with_pepper(entered_password + user_data.get('salt'), stored_password_hash) and username == user_data.get('username'):
        print("\n[+] Login Successful..\n")
    else:
        print("\n[-] Invalid Login credentials. Please use the credentials you used to register.\n")
        sys.exit()


# Displays al the saved websites
def view_websites():
   try:
       with open(PASSWORD_FILE, 'r') as data:
           view = json.load(data)
           print("\nWebsites you saved...\n")
           for x in view:
               print(x['website'])
           print('\n')
   except FileNotFoundError:
       print("\n[-] You have not saved any passwords!\n")


# Load or generate the encryption key - if it is the first time, we generate and save key, otherwise just loads
# the key here is the heart of program, where the vulnerability lies
key_filename = 'encryption_key.key'
if os.path.exists(key_filename):
   with open(key_filename, 'rb') as key_file:
       key = key_file.read()
else:
   key = generate_key()
   with open(key_filename, 'wb') as key_file:
       key_file.write(key)

cipher = initialize_cipher(key)

# Function to add and save passwords tied to a particular website
def add_password(website, password):
   # Check if passwords.json exists
   if not os.path.exists(PASSWORD_FILE):
       # If passwords.json doesn't exist, initialize it with an empty list
       data = []
   else:
       # Load existing data from passwords.json
       try:
           with open(PASSWORD_FILE, 'r') as file:
               data = json.load(file)
       except json.JSONDecodeError:
           # Handle the case where passwords.json is empty or invalid JSON.
           data = []
   # Encrypt the password
   encrypted_password = encrypt_password(cipher, password)
   # Create a dictionary to store the website and password
   password_entry = {'website': website, 'password': encrypted_password}
   data.append(password_entry)
   # Save the updated list back to passwords.json
   with open(PASSWORD_FILE, 'w') as file:
       json.dump(data, file, indent=4)


# Function to retrieve a saved password.
def get_password(website):
   # Check if passwords.json exists
   if not os.path.exists(PASSWORD_FILE):
       return None
   # Load existing data from passwords.json
   try:
       with open(PASSWORD_FILE, 'r') as file:
           data = json.load(file)
   except json.JSONDecodeError:
       data = []
   # Loop through all the websites and check if the requested website exists.
   for entry in data:
       if entry['website'] == website:
           # Decrypt and return the password
           decrypted_password = decrypt_password(cipher, entry['password'])
           return decrypted_password
   return None


# function body in an infinite loop to keep the program running until the user chooses to quit.
while True:
   print("1. Register")
   print("2. Login")
   print("3. Quit")
   choice = input("Enter your choice: ")
   if choice == '1':  # If a user wants to register
       file = USER_FILE
       if os.path.exists(file) and os.path.getsize(file) != 0:
           print("\n[-] Master user already exists!!")
           sys.exit()
       else:
            username = input("Enter your username: ")
            master_password = getpass.getpass("Enter your master password: ")
            password_match = getpass.getpass("Confirm your master password: ")
            if (master_password != password_match):
               print('\n[-] Passwords do not match. Please try again.\n')
            else:
                register(username, master_password)
   elif choice == '2':  # If a User wants to log in
       file = USER_FILE
       if os.path.exists(file):
           username = input("Enter your username: ")
           master_password = getpass.getpass("Enter your master password: ")
           login(username, master_password)
       else:
           print("\n[-] You have not registered. Please do that.\n")
           sys.exit()
       # Various options after a successful Login.
       while True:
            print("1. Add Password")
            print("2. Get Password")
            print("3. View Saved websites")
            print("4. Scan all passwords")
            print("5. Quit")
            password_choice = input("Enter your choice: ")
            if password_choice == '1':  # If a user wants to add a password
                website = input("Enter website: ")
                password = getpass.getpass("Enter password: ")
                # Encrypt and add the password
                add_password(website, password)
                print("\n[+] Password added!\n")
            elif password_choice == '2':  # If a User wants to retrieve a password
                website = input("Enter website: ")
                decrypted_password = get_password(website)
                if website and decrypted_password:
                    # Copy password to clipboard for convenience
                    pyperclip.copy(decrypted_password)
                    print(f"\n[+] Password for {website}: {decrypted_password}\n[+] Password copied to clipboard.\n")
                else:
                    print("\n[-] Password not found! Did you save the password?"
                            "\n[-] Use option 3 to see the websites you saved.\n")
            elif password_choice == '3':  # If a user wants to view saved websites
                view_websites()
            elif password_choice == '4': # If a user wants to scan current passwords for security
                scan_passwords()
            elif password_choice == '5':  # If a user wants to quit the password manager
                break
   elif choice == '3':  # If a user wants to quit the program
       break
   
