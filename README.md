# Password Manager
#### *Remember one password for all of your account*

This is a password manager application that securely stores and manages your passwords. It provides a convenient and secure way to store all your passwords in one place, protected by a master password. With this password manager, you no longer need to remember multiple passwords or worry about forget your password.

*Note: While this password manager application is designed to securely protect your passwords, there is no guarantee of absolute security. If you lose your master password or if your password database is hacked by other people, your passwords may be compromised. The responsibility for protecting your passwords lies with you.*


## Features

- **Secure Password Storage**: All passwords are securely encrypted and stored in a csv file database. The database is protected by a master password that only you know.

- **Master Password Creation**: When you first run the application, you will be prompted to create a master password. This master password is used to encrypt and decrypt your password account

- **Password Management**: You can add, edit, and delete passwords for different accounts. Each password entry includes fields for the account name, username, and password.

- **Search Functionality**: The password manager provides a search function that allows you to search for specific passwords by account name. This makes it easy to find the password you need when you have a large number of accounts.

- **Database Encryption**: The password is encrypted using industry-standard encryption algorithms. Algorithms like Advanced Encryption Standard (AES), as well as secure hash functions like SHA-256. This ensures that even if someone gains unauthorized access to the database file, they won't be able to read the passwords without the master password.


## Table of Contents

- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Video Demo](#video-demo)
- [Contributing](#contributing)
- [License](#license)

## Getting Started

### Prerequisites

- Recommended python 3 or higher version
- Dependencies listed in `requirements.txt`

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/ahyar002/password_manager.git

2. Navigate to the project directory

    ```bash
    cd password_manager

3. Install the depemdemcies:

    ```bash
   pip install -r requirements.txt


### Usage

1. Run the application:

    ```bash
    python project.py

2. Follow the on-screen instructions to create a master password and manage your passwords.

### Video Demo
Video Demo : <https://youtu.be/j_09GyuA-V4>

## Contribution
Contributions are welcome! If you have any improvements or bug fixes, feel free to submit a pull request.

Please make sure to update tests as appropriate.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

Feel free to customize the content to fit your specific project.



_Note: This is final project from Harvard University course CS50's Introduction to Programming with Pyhton _

https://certificates.cs50.io/a54f0d10-67f9-4904-b808-1e00216f1754.pdf?size=letter
