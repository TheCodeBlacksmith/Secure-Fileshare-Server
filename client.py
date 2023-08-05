import base64
from pprint import pprint
from flask import Flask, request, jsonify
import requests
import os
import json

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from six.moves import input

import shutil

username = 'user'  
server_name = 'secure_fileshare_server'

nodeCert = os.getcwd() + '/certs/' + os.getcwd().rpartition('/')[2] + '.crt'
nodeKey = os.getcwd() + '/certs/' + os.getcwd().rpartition('/')[2] + '.key'

def post_request(server_name, action, body, nodeCert, nodeKey):
    """
        nodeCert is the name of the certificate file of the client node (present inside certs).
        nodeKey is the name of the private key of the client node (present inside certs).
        body parameter should in the json format.
    """
    request_url = 'https://{}/{}'.format(server_name, action)
    request_headers = {
        'Content-Type': "application/json"
    }
    response = requests.post(
        url=request_url,
        data=json.dumps(body),
        headers=request_headers,
        cert=(nodeCert, nodeKey),
    )
    with open(username, 'wb') as f:
        f.write(response.content)

    return response


# helper methods for encryption / verification
def encrypt_statement(value, user_private_key_file):
    '''
    encrypts and return signed statement
    '''

    digest = SHA256.new()
    digest.update(value.encode("utf8"))

    with open(user_private_key_file, "r") as uKeyFile:
        user_private_key = RSA.importKey(uKeyFile.read())

    signer_var = pkcs1_15.new(user_private_key)
    signed_value = signer_var.sign(digest)
    signed_value = signed_value.hex()
    return signed_value


# helper methods for printing
def print_server_output(server_returned_output, ver=0):
    '''
    prints server output IF it's not None
    ver: tells whether to print session_token or not (if it exists) (if set to (1) else not (default:0))
    '''
    try:
        if server_returned_output is not None:
            print("\nThis is the server response")
            server_message = server_returned_output['message']
            print(server_message)
            server_status = server_returned_output['status']
            print(server_status)
            if ver == 1:
                session_token = server_returned_output['session_token']
                print(session_token)

    except:
        print("unknown error occurred while printing server output")


def login():
    """
        Generate the login statement as given in writeup and its signature.
        Send request to server with required parameters (action = 'login') using
        post_request function given.
        The request body should contain the user-id, statement and signed statement.
    """
    # zero trust
    successful_login = False

    while not successful_login:
        # get the user id from the user input or default to user1
        user_id = (input(" User Id: ") or "user1")

        # get the user private key filename or default to user1.key
        private_key_filename = (input(" Private Key Filename: ") or "user1.key")

        # complete the full path of the user private key filename
        # /home/cs6238/Desktop/Project4/client1/userkeys/{private_key_filename}
        cwd = os.getcwd()
        user_private_key_file = cwd + '/userkeys/' + private_key_filename

        # get the client id from the current working path
        client_id = cwd.rpartition('/')[2]

        # create and sign the statement
        statement = f'{client_id} as {user_id} logs into Server'  # create the statement to be signed
        signed_statement = encrypt_statement(statement,
                                             user_private_key_file)  # sign the statement using the user private key

        body = {
            'user-id': user_id,
            'statement': statement,
            'signed-statement': signed_statement
        }

        server_response = post_request(server_name, 'login', body, nodeCert, nodeKey)
        if server_response.json().get('status') == 200:
            successful_login = True
        else:
            print(server_response.json().get('message', "Try again"))

    return server_response.json()


def checkin(session_token, document_id=None, security_flag=None):
    """
        security flag (1 for confidentiality and 2 for integrity)
        Send the request to server with required parameters (action = 'checkin') using post_request().
        The request body should contain the required parameters to ensure the file is sent to the server.
    """
    if document_id is None or security_flag is None:
        document_id = input("Enter document id: ")
        security_flag = input("Enter security flag: ")
    else:
        document_id = document_id
        security_flag = security_flag

    # complete the full path of the file with document_id
    # /home/cs6238/Desktop/Project4/client1/documents/checkin/{document_id}.txt
    cwd = os.getcwd()
    full_checkin_file_path = cwd + '/documents/checkin/' + document_id + '.txt'
    full_checkout_file_path = cwd + '/documents/checkout/' + document_id + '.txt'

    try:
        file_exists_in_checkin = False
        file_exists_in_checkout = False

        # verify file with name (document-id) exists in checkin folder
        file_exists_in_checkin = os.path.exists(full_checkin_file_path)
        file_exists_in_checkout = os.path.exists(full_checkout_file_path)
    except:
        print("error while checking if file in checkin or checkout folder")

    # for edge-case - check if file is currently in checkout folder and move to checkin
    if file_exists_in_checkout:
        shutil.move(full_checkout_file_path, full_checkin_file_path)
        file_exists_in_checkin = os.path.exists(full_checkin_file_path)

    if file_exists_in_checkin:
        if security_flag in ["1", "2"]:

            with open(full_checkin_file_path, "r") as f:
                file_content = f.read()

            body = {
                'document-id': document_id,
                'security-flag': security_flag,
                'session-token': session_token,
                'file-content': file_content
            }
            server_response = post_request(server_name, 'checkin', body, nodeCert, nodeKey)
            if server_response.json().get('status') == 200:
                # delete file locally in checkin folder
                os.remove(full_checkin_file_path)

                return server_response.json()
            else:
                return server_response.json()
        else:
            print(f"Invalid security flag {security_flag}. Try Again")
    else:
        print(f"Invalid document id {document_id}. Try Again")

    return None


def checkout(session_token):
    """
        Send request to server with required parameters (action = 'checkout') using post_request()
    """
    document_id = input("Enter document id: ")

    body = {
        'document-id': document_id,
        'session-token': session_token,
    }

    server_response = post_request(server_name, 'checkout', body, nodeCert, nodeKey)

    if server_response.json().get('status') == 200:

        # get file conent and the checkout folder path
        file_content = server_response.json().get('file-content')
        cwd = os.getcwd()
        full_checkout_file_path = cwd + '/documents/checkout/' + document_id + '.txt'

        # write file to checkout
        with open(full_checkout_file_path, 'w') as f:
            f.write(file_content)

        return server_response.json()
    else:
        return server_response.json()

    return None


def grant(session_token):
    """
        Send request to server with required parameters (action = 'grant') using post_request()
    """
    document_id = input("Enter document id: ")
    target_users = input("Enter target user (0 for all user): ")
    access_right = input("Enter access type (1 - checkin, 2 - checkout, 3 - both checkin and checkout): ")
    access_time = input("Enter time duration (in seconds) for grant: ")

    if not int(access_time) <= 0:
        body = {
            'document-id': document_id,
            'target-users': target_users,
            'access-right': access_right,
            'access-time': access_time,
            'session-token': session_token,
        }

        server_response = post_request(server_name, 'grant', body, nodeCert, nodeKey)

        if server_response.json().get('status') == 200:
            return server_response.json()
        else:
            return server_response.json()
    else:
        print("Please enter a time duration (in seconds) greater then 0")

    return None


def delete(session_token):
    """
        Send request to server with required parameters (action = 'delete')
        using post_request().
    """
    document_id = input("Enter document id: ")

    body = {
        'document-id': document_id,
        'session-token': session_token,
    }

    server_response = post_request(server_name, 'delete', body, nodeCert, nodeKey)

    if server_response.json().get('status') == 200:
        return server_response.json()
    else:
        return server_response.json()

    return None


def logout(session_token):
    """
        Ensure all the modified checked out documents are checked back in.
        Send request to server with required parameters (action = 'logout') using post_request()
        The request body should contain the user-id, session-token
    """

    # get the checkin and checkout directory paths
    cwd = os.getcwd()
    full_checkin_directory = cwd + '/documents/checkin/'
    full_checkout_directory = cwd + '/documents/checkout/'

    document_id_list = []
    # loop through all files in the checkin directory and grab all files' document ids
    for filename in os.listdir(full_checkin_directory):
        f = os.path.join(full_checkin_directory, filename)
        # check if it is a file
        if os.path.isfile(f):
            document_id = os.path.splitext(filename)[0]
            document_id_list.append(document_id)

    # loop through all files in the checkout directory and grab all files' document ids
    for filename in os.listdir(full_checkout_directory):
        f = os.path.join(full_checkout_directory, filename)
        # check if it is a file
        if os.path.isfile(f):
            document_id = os.path.splitext(filename)[0]
            document_id_list.append(document_id)

    # loop through all found document ids and add all those that have been modified back to the server
    # ...with the security flag set to 2 (for Integrity)
    security_flag = "2"
    for document_id in document_id_list:
        checkin(session_token, document_id, security_flag)

    body = {
        'session-token': session_token,
    }

    server_response = post_request(server_name, 'logout', body, nodeCert, nodeKey)

    # loop through all files in the checkin directory and delete any remaining files
    for filename in os.listdir(full_checkin_directory):
        f = os.path.join(full_checkin_directory, filename)
        # check if it is a file
        if os.path.isfile(f):
            os.remove(f)

    # loop through all files in the checkout directory and delete any remaining files
    for filename in os.listdir(full_checkout_directory):
        f = os.path.join(full_checkout_directory, filename)
        # check if it is a file
        if os.path.isfile(f):
            os.remove(f)

    print_server_output(server_response.json())
    exit()  # exit the program


def print_main_menu():
    """
    print main menu
    :return: nothing
    """
    print(" Enter Option: ")
    print("    1. Checkin")
    print("    2. Checkout")
    print("    3. Grant")
    print("    4. Delete")
    print("    5. Logout")
    return


def main():
    """
        Authenticate the user by calling login.
        If the login is successful, provide the following options to the user
            1. Checkin
            2. Checkout
            3. Grant
            4. Delete
            5. Logout
        The options will be the indices as shown above. For example, if user
        enters 1, it must invoke the Checkin function. Appropriate functions
        should be invoked depending on the user input. Users should be able to
        perform these actions in a loop until they logout. This mapping should
        be maintained in your implementation for the options.
    """

    # Initialize variables to keep track of progress
    server_message = 'UNKNOWN'
    server_status = 'UNKNOWN'
    session_token = 'UNKNOWN'

    login_return = login()

    server_status = login_return['status']
    session_token = login_return['session_token']

    print_server_output(login_return, 1)

    if server_status == 200:
        request_task_num = ""
        while True:
            print_main_menu()
            request_task_num = input()

            if request_task_num == "1":
                checkin_return = checkin(session_token)
                print_server_output(checkin_return)

            elif request_task_num == "2":
                checkout_return = checkout(session_token)
                print_server_output(checkout_return)

            elif request_task_num == "3":
                grant_return = grant(session_token)
                print_server_output(grant_return)

            elif request_task_num == "4":
                delete_return = delete(session_token)
                print_server_output(delete_return)

            elif request_task_num == "5":
                logout(session_token)
            else:
                continue


if __name__ == '__main__':
    main()
