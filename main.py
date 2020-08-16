import requests
import hashlib

def main(args):
    for password in args:
        #Check if password has been leaked
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times. DO NOT use this password!')
        else:
            print(f'{password} was not found. You can use this password!')
    return 'done'

def pwned_api_check(password):
    #Create SHA-1 password hash
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    #Get first five characters of hash (first5_char), get remaining characters of hash (tail)
    first5_char, tail = sha1password[:5], sha1password[5:]
    #Check if hash is in api repository
    response = request_api_data(first5_char)
    # print(first5_char, tail)
    return get_password_leaks_count(response, tail)

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + str(query_char)
    #Connect to api
    response = requests.get(url)
    # print(response.text)
    #Confirm connection to api
    if response.status_code != 200:
        raise RuntimeError(f'Error: {response.status_code}, check the api and try again')
    #return all hashes that begin with (query_char)
    return response

def get_password_leaks_count(hashes, hash_to_check):
    #Example response from api - 01563085FC35165329EA1FF5C5ECBDBBEEF:1042952
    #                            tail of hashed password           : number of times password has been leaked
    #split api response into a tuple containing password and # of times leaked
    hashes = (line.split(':') for line in hashes.text.splitlines())
    #loop through hashes. if current hash equals the hash of our password, return count.
    #if our hash does not match any of the leaked hashes, return 0.
    #count is the number of times the password/hash has been leaked
    for hash, count in hashes:
        if hash == hash_to_check:
            return count
    return 0


print(main(['password123']))
