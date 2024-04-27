import unittest
from unittest.mock import patch
from project import *

class test_encrypt(unittest.TestCase):

    def test_encrypt(self):
        master_password = "password"
        plaintext = "Hello, world!"

        # Testing encryption with valid inputs
        encrypted_text = encrypt(master_password, plaintext)
        self.assertIsInstance(encrypted_text, str)

        # Testing encryption with empty plaintext
        encrypted_text = encrypt(master_password, "")
        self.assertIsInstance(encrypted_text, str)

        # Testing encryption with long plaintext
        long_plaintext = "a" * 1000
        encrypted_text = encrypt(master_password, long_plaintext)
        self.assertIsInstance(encrypted_text, str)

        # Testing encryption with different master password
        different_password = "different_password"
        encrypted_text = encrypt(different_password, plaintext)
        self.assertIsInstance(encrypted_text, str)

    def test_invalid_inputs(self):
        master_password = "password"
        plaintext = "Hello, world!"

        # Testing encryption with None master password
        encrypted_text = encrypt(None, plaintext)
        self.assertIsNone(encrypted_text)

        # Testing encryption with None plaintext
        encrypted_text = encrypt(master_password, None)
        self.assertIsNone(encrypted_text)

        # Testing encryption with invalid master password type
        encrypted_text = encrypt(str(12345), plaintext)
        self.assertIsInstance(encrypted_text, str)

        # Testing encryption with invalid plaintext type
        encrypted_text = encrypt(master_password, str(12345))
        self.assertIsInstance(encrypted_text, str)

class test_create_master_password(unittest.TestCase):

    @patch('builtins.input', return_value='n')
    def test_create_master_password_existing_key_file(self, mock_input):
        expected_output = '\n❗❗❗ Canceled....'
        self.assertEqual(create_master_password(), expected_output)

    @patch('builtins.input', side_effect=['y', 'password', 'password'])
    @patch('stdiomask.getpass', return_value='password')
    def test_change_master_password(self, mock_getpass, mock_input):
        expected_output = '\n🔐🔐🔐 Master password created successfully! 🔐🔐🔐'
        self.assertEqual(create_master_password(), expected_output)

    @patch('os.path.isfile', return_value=False)
    @patch('stdiomask.getpass', return_value='password')
    def test_new_key_file(self, mock_getpass, mock_input):
        expected_output = '\n🔐🔐🔐 Master password created successfully! 🔐🔐🔐'
        self.assertEqual(create_master_password(), expected_output)

class test_derive_key(unittest.TestCase):
    def test_derive_key(self):
        # Testing with a master password and salt
        master_password = "password123"
        salt = b"salt123"
        expected_key = b"*\xe6\xd2\t\x9a\xbd%\x8aLf\x96\x1f\xa4\xda\xd7D#\xf1\x1f\xd9\xdc-\xfe\x04\x81\x1f\x17\x19G\xd9\t9"
        result = derive_key(master_password, salt)
        self.assertEqual(result, expected_key)

        # Testing with an empty master password and salt
        master_password = ""
        salt = b""
        expected_key = b"+\xbd\xa6\xc9\xd8\xbb\xa9\xcb\xaeI+jw\xf0\xcbj\xf56Nb\xad=\xce\xceQ\xf7\xc2@\xec\x84z\xf9"
        result = derive_key(master_password, salt)
        self.assertEqual(result, expected_key)

        # Testing with a long master password and salt
        master_password = "this_is_a_very_long_master_password"
        salt = b"this_is_a_very_long_salt_value"
        expected_key = b'\xa3\xe1c\xf3\xfa\xea\xa53\x13%D\xd6\xdc|l\xa4\xc1"\xda\xd4\x0e g,\xdc`l`&r\xd0\xb0'
        result = derive_key(master_password, salt)
        self.assertEqual(result, expected_key)


if __name__ == '__main__':
    unittest.main()
