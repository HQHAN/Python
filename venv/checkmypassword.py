import requests
import hashlib

source_password_file = 'password_source.txt'


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'error fetching : {res.status_code}')
    return res


def get_password_leaked_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # check password if it exits in API response
    hashes = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    start, tail = hashes[:5], hashes[5:]
    response = request_api_data(start)
    return get_password_leaked_count(response, tail)


def main():
    try:
        with open('venv/password_source.txt', 'r') as file:
            for password in file.read().splitlines():
                count = pwned_api_check(password)
                if count:
                    print(f'{password} is leaked {count} times.. :(')
                else:
                    print(f'{password} is never leaked :D')
    except Exception as e:
        print(f'debug information : {e}')


if __name__ == '__main__':
    main()
