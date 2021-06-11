import requests
import hashlib
from sys import argv

weak= []
strong = []


def request_api_data(query_char):
    url = f'https://api.pwnedpasswords.com/range/{query_char}'
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}')
    else:
        return res


def hash_generator(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1


def leak_count(hashes, hash_to_check):
    hash = hash_to_check
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for _hash, count in hashes:
        if _hash == hash:
            return count


def pwned_api_check(password):
    sha1 = hash_generator(password)
    head, body = sha1[:5], sha1[5:]
    responce = request_api_data(head)
    count = leak_count(responce,body)
    return count


def check_passwords(iterable):
    for password in iterable:
        count = pwned_api_check(password)
        print(f'checking {password} in https://api.pwnedpasswords.com/range/')
        if count == None:
            print(f'This password hasn\'t been cracked yet, You can proceed')
            strong.append(password)

        else:
            print(f'{password} is cracked {count} times. Try changing your password.')
            weak.append(password)
        print()


def final(source):
    print(f'No of passwords : {len(source)}')
    print(f'Weak password :', ','.join(weak))
    print(f'strong password :', ','.join(strong))


option = argv[1]

if option == '-h' or option == '--help':
    print('''--------------- Welcome to password security check -------------

SYNTAX: python3 [filename] [option] [password(s) / filename]

OPTIONS:

-h / --help : display help menu

-s / --syntax : display syntax

-f / --file : open file containing password

-p / --pass : give direct password or multiple passwords   

NOTE:
* option -f requires option followed by filename
* option -p requires single or multiple passwords to check
* option -h and -s doesn\'t require any keyboard arguments

EXAMPLES:
* python3 password_check.py --file passwords.txt
* python3 password_check.py -p password123 covid19

_______________ Thank You _______________ ''')

elif option == '-s' or option == '--syntax':
    print('''SYNTAX: python3 [filename] [option] [password(s) / filename]
try option --help for more info..''')

elif option == '-p' or option == '--pass':
    password_list = argv[2:]
    check_passwords(password_list)
    final(password_list)

elif option == '-f' or option == '--file':
    filename = argv[2]
    passwords = []
    with open(filename,'r') as file:
        for password in file:
            passwords.append(password.strip())
    check_passwords(passwords)
    final(passwords)
else:
    print(f'{option} is invalid option. try --help for more info.')

