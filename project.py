import csv, time, pandas as pd
import os, stdiomask
from prettytable import PrettyTable
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode

def main():
    """
    Display a welcome message and provide options to store or view passwords.
    """

    # Create the table
    table = PrettyTable()
    table.field_names = ["Welcome Message"]
    table.add_row(["🔒 Hello! Welcome to Password Manager. What would you like to do? 🔒"])
    table.add_row(["🔒 Hint: Create your Master Password first and then store your account password! 🔒"])
    table.add_row(["⚠️  Remember your Master Password ⚠️"])
    table.add_row([""])
    table.add_row(["⬇️  Choose one below ⬇️"])
    table.add_row([""" 0. Master Password  1. Store  2. View  3. Update  4. Delete  5. Quit """])

    # prompt the user for an option
    while True:
        print(table)
        message = input("Type a number: ")

        if message == '5':
            print('\n👋 Thank you! Have a great day! 👋')
            break

        options = {
            '1': store,
            '2': view,
            '3': update,
            '4': delete,
            '0': create_master_password
        }

        if message in options:
            print(options[message]())

    # Exit the program
    print('Exiting...')
    time.sleep(1)
    print('✨ Goodbye! ✨\n')


def create_master_password() -> str:
    """
    Prompts the user to create a master password and stores it securely in a key file.

    Returns:
        str: A success message indicating that the master password was created successfully.
            If there was an error, an error message is returned instead.
    """

    # Check if the key file already exists
    if os.path.isfile('key.key'):
        table = PrettyTable()
        table.field_names = ["⚠️ ⚠️ ⚠️  Warning Message ⚠️ ⚠️ ⚠️"]
        table.add_row(["🔒 If you wanna change master password, your earlier stored password account can't be decrypt 🔒"])
        table.add_row([" Except using Master Password when you stored it "])
        print(table)

        # Prompt the user to confirm if they want to change the master password
        confirm = input("You want to change 'Master Password' (y/n)? ").strip().lower()

        if confirm == 'n':
            return '\n❗❗❗ Canceled...\n'
        elif confirm == 'y':
            master_password = get_master_password()
            pass
        else:
            return '\n ❗❗❗incorrect...\n'

    # Prompt the user to enter the master password
    master_password = stdiomask.getpass('New Master password: ').strip()
    re_type = stdiomask.getpass('Re-type master password: ').strip()

    # match the input user
    if not master_password == re_type:
        return '\n🚩🚩🚩 Your password mismatch, Try again!'

    # Write the key to the key file
    with open("key.key", "wb") as key_file:
        key_file.write(derive_key(master_password, re_type.encode()))


    return '\n🔐🔐🔐 Master password created successfully! 🔐🔐🔐\n'


def get_master_password() -> str:
    """
    Prompts the user for a master password and validates it against a stored key.

    Returns:
        str: The valid master password.
    """
    # Prompt the user for a master password
    while True:
        master_password = stdiomask.getpass('Master password: ').strip()

        # Read the key from the file
        with open("key.key", "rb") as file:
            key = file.read()

        if derive_key(master_password, master_password.encode()) == key:
            return master_password

        print('❌❌❌ Incorrect Master Password ❌❌❌')



def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derives a key using PBKDF2HMAC algorithm with SHA256 hash function.

    Args:
        master_password: The master password to derive the key from.
        salt: The salt value used in the key derivation process.

    Returns:
        The derived key as bytes.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=480000,
        salt=salt,
        length=32
    )
    return kdf.derive(master_password.encode())



def encrypt(master_password: str, plaintext: str) -> str:
    """
    Encrypts the plaintext using the master password.

    Args:
        master_password: The master password used for encryption.
        plaintext: The text to be encrypted.

    Returns:
        The encrypted ciphertext as a URL-safe base64 encoded string.
    """
    if plaintext is None or master_password is None:
        return None

    # Generate a random 16-byte salt
    salt = os.urandom(16)

    # Derive a key using the master password and salt
    key = derive_key(master_password, salt)

    # Generate a random 16-byte initialization vector (IV)
    iv = os.urandom(16)

    # Create an AES cipher in CFB mode with the derived key and IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    # Create an encryptor object using the cipher
    encryptor = cipher.encryptor()

    # Encrypt the plaintext and get the ciphertext
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    # Concatenate the salt, IV, and ciphertext and encode as URL-safe base64
    return urlsafe_b64encode(salt + iv + ciphertext).decode()



def decrypt(master_password: str, ciphertext: str) -> str:
    """
    Decrypts the given ciphertext using the provided master password.

    Args:
        master_password (str): The master password used to derive the decryption key.
        ciphertext (str): The encrypted data to be decrypted.

    Returns:
        str: The decrypted plaintext.

    Raises:
        ValueError: If the master password is incorrect.
    """
    try:
        # Decode the ciphertext from URL-safe base64 encoding
        data = urlsafe_b64decode(ciphertext.encode())

        # Split the data into salt, initialization vector (IV), and ciphertext
        salt, iv, ciphertext = data[:16], data[16:32], data[32:]

        # Derive the decryption key using the master password and salt
        key = derive_key(master_password, salt)

        # Create a cipher with AES algorithm in CFB mode and the derived key and IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

        # Create a decryptor object using the cipher
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext and get the plaintext
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Return the decrypted plaintext
        return plaintext.decode()

    # error handling for incorrect master password
    except UnicodeDecodeError as e:
        return ValueError("\n🚨🚨🚨 Error!!! Incorrect 'Master Password'. Remember Master Password when you store it 🚨🚨🚨\n")



def store():
    """
    Prompt the user for a master password, account details, and store the encrypted password in a CSV file.

    Returns:
        str: A success or error message indicating the result of the operation.
    """
    try:
        master_password = get_master_password()
    except FileNotFoundError:
        return ValueError("\n🚨🚨🚨 You must create your 'Master Password' first! 🚨🚨🚨\n")

    # Prompt the user for account details
    account = input('Account: ').strip()

    # Check if the password.csv file exists
    if not os.path.isfile('password.csv'):
        # Create the password.csv file if it doesn't exist
        with open('password.csv', 'w') as file:
            pass

    # Check if the account already exists in the CSV file
    with open('password.csv', 'r+') as file:
        reader = csv.DictReader(file)
        if any(row['account'].lower() == account.lower() for row in reader):
            return '\n🚨🚨🚨 Account already exists! Make an unique name if you have multiple accounts! (e.g: FB1, FB2) 🚨🚨🚨\n'

    # Prompt the user for a username and password
    username = input('Username: ').strip()
    password = stdiomask.getpass('Password: ').strip()

    # Encrypt the password using the master password
    encrypted_password = encrypt(master_password, password)

    # Store the account details in the CSV file
    with open('password.csv', 'a+', newline='') as file:
        file.seek(0)
        writer = csv.DictWriter(file, fieldnames=['account', 'username', 'password'])

        # Write the header if the file is empty
        if file.read(1) == '':
            writer.writeheader()

        writer.writerow({'account': account, 'username': username, 'password': encrypted_password})

    return '\n🔐🔐🔐 Password stored successfully! 🔐🔐🔐\n'


def view():
    """
    Retrieves the password for a given account.

    Returns:
        str: A formatted table with the account, username, and password if found.
             Returns a 'No account found!' if the account is not found.
    """
    # Prompt user for master password and account
    try:
        master_password = get_master_password()
    except FileNotFoundError:
        return ValueError("\n🚨🚨🚨 You must create your 'Master Password' first! 🚨🚨🚨\n")

    account = input('Which account do you want? ').strip()
    try:
        # Open the password file
        with open('password.csv', 'r') as file:
            reader = csv.DictReader(file)

            # Iterate over each row in the file
            for row in reader:
                # Check if the account matches and decrypt the password
                if row['account'].lower() == account.lower():
                    decrypted_password = decrypt(master_password, row['password'])

                    # Create a table with the account, username, and decrypted password
                    table = PrettyTable(['Account', 'Username', 'Password'])
                    table.add_row([row['account'], row['username'], decrypted_password])

                    # Return the formatted table
                    return str(table)

            # Return a 'No account found!' emoji message if the account is not found
            return '\n⛔⛔⛔ No account found! ⛔⛔⛔\n'

    except FileNotFoundError:
        return ValueError("\n🚨🚨🚨 You must store your 'Account Password' first! 🚨🚨🚨\n")


def update():
    """
    A function that prompts the user for a master password, account name, new username, and new password.
    It then reads a CSV file into a DataFrame, checks if the account exists, and if so, prompts the user for a new username and password. 
    The function encrypts the new password using the master password, updates the DataFrame with the new values, 
    and writes the modified DataFrame back to the CSV file. Finally, it returns a success message if the account was updated, 
    or an error message if the account does not exist or the required files are not found.

    Returns:
    - If the account exists and is successfully updated: A success message string.
    - If the account does not exist: An error message string.
    - If the required files are not found: A ValueError exception.

    Raises:
    - FileNotFoundError: If the 'Master Password' or 'Account Password' files are not found.
    """
    try:
        # Prompt user for master password, account, new username, and new password
        try:
            master_password = get_master_password()
        except FileNotFoundError:
            return ValueError("\n🚨🚨🚨 You must create your 'Master Password' first! 🚨🚨🚨\n")

        account = input('Which account do you want to update? ').strip()

        # Read the CSV file into a DataFrame
        df = pd.read_csv('password.csv')

        # Check if the account exists
        if any(df['account'].str.lower() == account.lower()):
            # Prompt user for new username and password
            new_username = input('Enter new username: ').strip()
            new_password = stdiomask.getpass('Enter new password: ').strip()

            # Encrypt the new password using the master password
            encrypted_password = encrypt(master_password, new_password)

            # Update the DataFrame with the new values
            df.loc[df['account'].str.lower() == account.lower(), 'username'] = new_username
            df.loc[df['account'].str.lower() == account.lower(), 'password'] = encrypted_password

            # Write the modified DataFrame back to the CSV file
            df.to_csv('password.csv', index=False)

            return f'\n🛠️ 🛠️ 🛠️  The account "{account}" has been updated 🛠️ 🛠️ 🛠️\n'
        else:
            return f'\n❌❌❌ The account "{account}" does not exist ❌❌❌\n'

    except FileNotFoundError:
        return ValueError("\n🚨🚨🚨 You must store your 'Account Password' first! 🚨🚨🚨\n")



def delete():
    """
    Deletes an account from the password storage.

    Parameters:
        None

    Returns:
        - If 'Master Password' file is not found: ValueError with an error message.
        - If 'Account Password' file is not found: ValueError with an error message.
        - If the specified account exists and is successfully deleted: Success message.
        - If the specified account does not exist: Error message.
        - If the user cancels the deletion: Cancel message.
    """
    try:
        # Prompt user for master password and account
        try:
            master_password = get_master_password()
        except FileNotFoundError:
            return ValueError("\n🚨🚨🚨 You must create your 'Master Password' first! 🚨🚨🚨\n")

        account = input('Which account do you want to delete? ').strip()

        df = pd.read_csv('password.csv')

        # Check if the account exists
        if any(df['account'].str.lower() == account.lower()):
            confirm = input('⚠️  Are you sure (y/n)? ').strip().lower()
            if confirm == 'y':
                # Delete the row corresponding to the specified account
                df = df[df['account'].str.lower() != account.lower()]

                # Write the modified DataFrame back to the CSV file
                df.to_csv('password.csv', index=False)
            elif confirm == 'n':
                return '\n❗❗❗ Deleted account canceled ❗❗❗\n'
            else:
                return '\n ❗❗❗incorrect...\n'

            return f'\n🗑️ 🗑️ 🗑️  The "{account}" account deleted successfully 🗑️ 🗑️ 🗑️\n'

        return f'\n❌❌❌ The "{account}" does not exist ❌❌❌\n'

    except FileNotFoundError:
        return ValueError("\n🚨🚨🚨 You must store your 'Account Password' first! 🚨🚨🚨\n")



if __name__ == "__main__":
    main()

