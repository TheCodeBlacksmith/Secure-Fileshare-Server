from flask import Flask, request, jsonify
from flask_restful import Resource, Api
import requests
import os
import json
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import base64

from datetime import datetime
from datetime import timedelta
import sqlite3
import secrets
import pyaes, pbkdf2
from Crypto.Cipher import PKCS1_v1_5

secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)


def verify_statement(value, signed_value, user_id) -> bool:
    '''
    attempts to verify if a statement is valid based on public key
    returns true or false for verified
    '''
    verified = True
    signed_statement = bytes.fromhex(signed_value)
    digest = SHA256.new()
    digest.update(value.encode('utf-8'))
    cwd = os.getcwd()
    user_public_key_file = cwd + '/userpublickeys/' + user_id + ".pub"
    with open(user_public_key_file, "r") as uKeyFile:
        user_public_key = RSA.importKey(uKeyFile.read())
    statement_verifier = pkcs1_15.new(user_public_key)

    try:
        statement_verifier.verify(digest, signed_statement)
        verified = True
    except:
        verified = False

    return verified


def encrypt_aes_key_ForConf(aes_key):
    '''
    used in checkin if the file is set to security_flag = Confidentiality
    '''
    server_public_key_file = '../certs/secure-shared-store.pub'
    with open(server_public_key_file, "r") as sKeyFile:
        server_public_key = RSA.importKey(sKeyFile.read())
    cipher = PKCS1_v1_5.new(server_public_key)
    aes_key_ciphertext = cipher.encrypt(aes_key)
    return aes_key_ciphertext


def decrypt_aes_key_ForConf(aes_key_ciphertext):
    '''
    used in checkin if the file is set to security_flag = Confidentiality
    '''
    server_private_key_file = '../certs/secure-shared-store.key'
    with open(server_private_key_file, "r") as uKeyFile:
        server_private_key = RSA.importKey(uKeyFile.read())
    cipher = PKCS1_v1_5.new(server_private_key)
    aes_key = cipher.decrypt(aes_key_ciphertext, None, 0)
    return aes_key


def sign_value_with_serverPrivateKey_ForInteg(value):
    '''
    used in checkin if the file is set to security_flag = Integrity
    '''
    digest = SHA256.new()
    digest.update(value.encode("utf8"))
    server_private_key_file = '../certs/secure-shared-store.key'
    with open(server_private_key_file, "r") as uKeyFile:
        server_private_key = RSA.importKey(uKeyFile.read())

    signer_var = pkcs1_15.new(server_private_key)
    signed_value = signer_var.sign(digest)
    signed_value = signed_value.hex()
    return signed_value


def compare_signed_with_unsigned_ForInteg(value, signed_value) -> bool:
    '''
    used in checkout if the file is set to security_flag = Integrity
    '''
    verified = True
    signed_value = bytes.fromhex(signed_value)
    digest = SHA256.new()
    digest.update(value.encode('utf-8'))
    server_public_key_file = '../certs/secure-shared-store.pub'
    with open(server_public_key_file, "r") as sKeyFile:
        server_public_key = RSA.importKey(sKeyFile.read())
    statement_verifier = pkcs1_15.new(server_public_key)

    try:
        statement_verifier.verify(digest, signed_value)
        verified = True
    except:
        verified = False

    return verified


# helper methods for SQLite3 database
def setup_the_database():
    '''
    attempts connection to SQLite3 database and returns the connection reference
    '''
    try:
        sqliteDB_Connection = sqlite3.connect('SQLite_S3.db')

        '''
        Active_Users stores the current active users by storing their user_id, their host_client, 
        and their respective active session's session_token
        '''
        sqlite_create_ActiveUsersTable_query = '''CREATE TABLE IF NOT EXISTS Active_Users (
                                        user_id TEXT PRIMARY KEY,
                                        host_client TEXT NOT NULL,
                                        session_token TEXT NOT NULL UNIQUE);'''

        '''
        User_Documents stores the document meta-data by storing their document_id, its current owner,
        the security_flag for teh document ( for confidentiality and 2 for integrity ) and if the 
        security_flag is 1 then the conf_enc_key stores the random AES key for the document in its
        encrypted form (otherwise is just Null) (conf_enc_iv is IV and is Null if not needed). Finally, the doc_status is a number representing if 
        the document is not-checked-out = 0 or checked-out = 1
        '''
        sqlite_create_userDocuments_query = '''CREATE TABLE IF NOT EXISTS User_Documents (
                                        document_id TEXT PRIMARY KEY,
                                        owner TEXT NOT NULL,
                                        security_flag INTEGER NOT NULL,
                                        conf_enc_key TEXT,
                                        conf_enc_iv TEXT,
                                        doc_status INTEGER NOT NULL);'''

        '''
         Documents_Access_Grants stores the access right grants for non-owners of the document by storing 
         the respective document_id , the targeted user(s) (ALL = "0", otherwise user_id), the access_right (checkin=1, checkout=2, both=3),
         and the time till the access grant is valid
         '''
        sqlite_create_documentsAccessGrants_query = '''CREATE TABLE IF NOT EXISTS Documents_Access_Grants (
                                        document_id TEXT PRIMARY KEY,
                                        target_users TEXT NOT NULL,
                                        access_right INTEGER NOT NULL,
                                        access_till_time timestamp);'''

        cursor = sqliteDB_Connection.cursor()
        # print("DEBUG: Successfully Connected to SQLite server database")

        cursor.execute(sqlite_create_ActiveUsersTable_query)
        sqliteDB_Connection.commit()

        cursor.execute(sqlite_create_userDocuments_query)
        sqliteDB_Connection.commit()

        cursor.execute(sqlite_create_documentsAccessGrants_query)
        sqliteDB_Connection.commit()
        # print("DEBUG: all SQLite server database tables created")

    except sqlite3.Error as error:
        print("Error while creating a sqlite table", error)
    except Exception as error:
        print("Unknown error occurred while creating a sqlite table", error)
    finally:
        cursor.close()
        sqliteDB_Connection.close()


def run_database_query(query: str, query_type: int, data=None):
    '''
    query: this is the SQL query
    query_type: update/insert/delete (1) , get rows (2)
    data: for query_type (1), this is the data to insert
    this takes a query and returns the result (if any, otherwise None)
    '''
    sqliteDB_Connection = sqlite3.connect('SQLite_S3.db',
                                          detect_types=sqlite3.PARSE_DECLTYPES |
                                                       sqlite3.PARSE_COLNAMES)
    cursor = sqliteDB_Connection.cursor()

    results = None
    try:
        if query_type == 1 and data is not None:
            cursor.execute(query, data)
            sqliteDB_Connection.commit()
        elif query_type == 2 and data is None:
            cursor.execute(query)
            results = cursor.fetchall()
        elif query_type == 2 and data is not None:
            cursor.execute(query, data)
            results = cursor.fetchall()

    except sqlite3.Error as error:
        print("Error occurred during SQLite query", error)
    except Exception as error:
        print("Unknown error occurred during SQLite query", error)
    finally:
        cursor.close()
        sqliteDB_Connection.close()
    return results


def interactWith_Active_Users_table(just_check: bool, user_id=None, session_token=None):
    '''
    method encapsulates all checking interactions with the Active_Users table.

    just_check: boolean that determines whether the method just returns if the user_id or session_token exists
    OR if it also deletes the existing row(s) with that value if just_check is set to False
    user_id: the user id of the user, this must be Null when session_token is not Null
    session_token: the session token of the user's current session, this must be Null when user_id is not Null
    Tip:
    (True, user_id, None) - check if user_id exists
    (False, user_id, None) - check if user_id exists, delete row if exists
    (True, None, session_token) - check if session_token exists
    (False, None, session_token) - check if session_token exists, delete row if exists
    '''

    status = False

    # check if user_id exists (and delete that row if not just_check)
    if user_id is not None and session_token is None:
        result = run_database_query("SELECT * FROM Active_Users WHERE user_id = ?", 2, (user_id,))

        if result is None or len(result) == 0:
            status = False
        else:
            if not just_check:
                run_database_query("DELETE FROM Active_Users WHERE user_id = ?", 1, (user_id,))
            status = True

    # check if session_token exists (and delete that row if not just_check)
    elif user_id is None and session_token is not None:
        result = run_database_query("SELECT * FROM Active_Users WHERE session_token = ?", 2, (session_token,))
        if result is None or len(result) == 0:
            status = False
        else:
            if not just_check:
                run_database_query("DELETE FROM Active_Users WHERE session_token = ?", 1, (session_token,))
            status = True

    return status


def interactWith_User_Documents_table(just_check: bool, document_id=None, owner=None, security_flag=None,
                                      doc_status=None):
    '''
    method encapsulates all checking interactions with the User_Documents table.

    just_check: boolean that determines whether the method just returns if the metadata with given document_id exists and deletes exisitng rows
    otherwise it just retrieves rows based on the document id
    OR possibly only those that match with the owner of document_id
    OR match the security_flag of the one for the document
    OR match the document status for the document
    document_id: the document id of the file, this cannot be null
    owner: owner of the file, this may be null
    security_flag:

    Tip:
    (False, document_id, None, None, None) - check if file metadata with document_id exists, delete if found
    (True, document_id, None, None, None) - check if file metadata with document_id exists
    (True, document_id, owner, None, None) - check if file metadata with document_id with given owner exists
    (True, document_id, None, security_flag, None) - check if file metadata with document_id with given security_flag exists
    (True, document_id, None, None, doc_status) - check if file metadata with document_id with given doc_status exists
    '''

    status = False

    if not just_check:
        # check if file with document_id exists, delete if found
        if document_id is not None:
            result = run_database_query("SELECT * FROM User_Documents WHERE document_id = ?", 2, (document_id,))
            if result is None or len(result) == 0:
                status = False
            else:
                run_database_query("DELETE FROM User_Documents WHERE document_id = ?", 1, (document_id,))
                status = True
    else:
        # check if file with document_id exists...
        if document_id is not None:
            result = run_database_query("SELECT * FROM User_Documents WHERE document_id = ?", 2, (document_id,))
            if result is None or len(result) == 0:
                status = False
            else:
                # ...and with given owner exists
                if owner is not None:
                    result = run_database_query("SELECT * FROM User_Documents WHERE document_id=? AND owner=?", 2,
                                                (document_id, owner))
                    status = False if result is None or len(result) == 0 else True
                # ...and with given security_flag exists
                elif security_flag is not None:
                    result = run_database_query("SELECT * FROM User_Documents WHERE document_id=? AND security_flag=?",
                                                2, (document_id, security_flag))
                    status = False if result is None or len(result) == 0 else True
                # ...and with given doc_status exists
                elif doc_status is not None:
                    result = run_database_query("SELECT * FROM User_Documents WHERE document_id=? AND doc_status=?", 2,
                                                (document_id, doc_status))
                    status = False if result is None or len(result) == 0 else True
                else:
                    status = True

    return status


def interactWith_Documents_Access_Grants_table(just_check: bool, document_id=None, target_users=None,
                                               access_right=None):
    '''
    method encapsulates all checking interactions with the Documents_Access_Grants table.

    just_check: boolean that determines whether the method just returns if a valid grant for file (via. document_id) exists
    OR if it also deletes the existing row(s) with that value if just_check is set to False
    document_id: the document id of the file, this cannot be null
    target_users: user(s) with the grant (ALL = "0", otherwise user_id), this may be null
    access_right: selected access right(s) (checkin=1, checkout=2, both=3), this may be null
    Tip:
    (False, document_id, None, None) - check if any grant to file exists, delete if found
    (True, document_id, None, None) - check if any grant to file exists
    (True, document_id, target_users, access_right) - check if any grant to file with given target_users AND specified access_right (or more overarching access_right) exists AND (with access_till_time > current_time)
    '''
    status = False

    if document_id is not None and target_users is None and access_right is None:
        results = run_database_query("SELECT * FROM Documents_Access_Grants WHERE document_id = ?", 2, (document_id,))
        status = False if results is None or len(results) == 0 else True
        if status is True and not just_check:
            run_database_query("DELETE FROM Documents_Access_Grants WHERE document_id = ?", 1, (document_id,))

    elif document_id is not None and target_users is not None and access_right is not None:
        results = run_database_query("SELECT * FROM Documents_Access_Grants WHERE document_id = ?", 2, (document_id,))
        final_results = interactWith_Documents_Access_Grants_table_helper(results, target_users, access_right)
        status = False if final_results is None or len(final_results) == 0 else True
    return status


def interactWith_Documents_Access_Grants_table_helper(results, target_users=None, access_right=None):
    '''
    for results acquired based only on the document_id:
    calculates current time and compares with any results acquired to see if the grant's access_till_time value
    is greater than the current time. Any result that is not so is removed from the final results returned.

    IF target_users is NOT none AND access_right is NOT none then it will further filter the results based on those that are valid for this user (explicitly OR implicitly)
    AND then it will further filter the results based on those that have the access_right or an overarching one (viz. access_right = 3 for the grant)
    '''
    valid_results = []
    current_time = datetime.now()

    # loop through and filter to only include grants that are valid past the current time
    for result in results:
        if current_time < result[3]:
            # ... and possibly further filter to only include grants that are valid past for the target_users (implicitly or explicitly)
            if target_users is not None and access_right is not None:
                if (target_users == result[1] or result[1] == "0") and (access_right == result[2] or result[2] == 3):
                    valid_results.append(result)
            else:
                valid_results.append(result)

    # sort based on timestamp all remaining grants so that the latest grant (viz. the last one in the new list) would be the effective rule
    valid_results = sorted(valid_results, key=lambda x: x[3])
    print(f"DEGUB: valid_results is returning {len(valid_results)} valid grants. valid_results = {valid_results}")
    return valid_results


# helper methods for file tasks
def checkin_file(document_id: str, owner: str, security_flag: str, file_content: str) -> bool:
    '''
    method takes care of transferring a file from client to server during checkin operation
    returns whether the procedure was completed successfully
    '''

    procedure_completed = True

    # compute full file path to server/application/documents for original file
    cwd = os.getcwd()
    full_server_documents_file_path = cwd + '/documents/' + document_id + '.txt'

    if security_flag == "1":  # security_flag is Confidentiality
        # generate random AES key
        aes_key = pbkdf2.PBKDF2(file_content, os.urandom(16)).read(32)
        iv = secrets.randbits(256)

        # encrypt with AES-256-CTR encryption
        aes = pyaes.AESModeOfOperationCTR(aes_key, pyaes.Counter(iv))
        file_content_ciphertext = aes.encrypt(file_content)

        # encrypt the aes_key
        aes_key_ciphertext = encrypt_aes_key_ForConf(aes_key)

        file_content_ciphertext_hexed = file_content_ciphertext.hex()  # ...for storage purposes
        hexlified_aes_key_ciphertext = aes_key_ciphertext.hex()  # ...for storage purposes
        iv_str = str(iv)  # ...for storage purposes

        # overwrite encrypted file_content in the file  (may or may not overwrite existing file)
        with open(full_server_documents_file_path, 'w') as f:
            f.write(file_content_ciphertext_hexed)

        # delete any found existing metadata of file in User_Documents table
        interactWith_User_Documents_table(False, document_id, None, None, None)

        # add new metadata for file
        run_database_query(
            "INSERT INTO 'User_Documents'('document_id', 'owner', 'security_flag', 'conf_enc_key', 'conf_enc_iv', 'doc_status') VALUES (?, ?, ?, ?, ?, ?);",
            1, (document_id, owner, int(security_flag), hexlified_aes_key_ciphertext, iv_str, 0))

    elif security_flag == "2":  # security_flag is Integrity

        # overwrite file_content in the file  (may or may not overwrite existing file)
        with open(full_server_documents_file_path, 'w') as f:
            f.write(file_content)

        full_server_documents_signed_file_path = cwd + '/documents/' + document_id + '_signed.txt'

        # sign file content with server's public key and store in a signed file
        signed_file_content = sign_value_with_serverPrivateKey_ForInteg(file_content)
        with open(full_server_documents_signed_file_path, 'w') as f:
            f.write(signed_file_content)

        # delete any found existing metadata of file in User_Documents table
        interactWith_User_Documents_table(False, document_id, None, None, None)

        # add new metadata for file
        run_database_query(
            "INSERT INTO 'User_Documents'('document_id', 'owner', 'security_flag', 'conf_enc_key', 'conf_enc_iv', 'doc_status') VALUES (?, ?, ?, ?, ?, ?);",
            1, (document_id, owner, int(security_flag), None, None, 0))

    return procedure_completed


def checkout_file(document_id: str):
    '''
    method takes care of transferring a file from client to server during checkout operation
    returns the file content to send to client
    '''

    file_content = None
    no_integrity_problem = True

    # get the security flag, encrypted aes key, and iv on this document
    all_document_info = run_database_query("SELECT * FROM User_Documents WHERE document_id = ?", 2, (document_id,))

    security_flag = str(all_document_info[0][2])
    hexlified_aes_key_ciphertext = all_document_info[0][3]
    iv_str = all_document_info[0][4]

    # compute full file path to server/application/documents for original file
    cwd = os.getcwd()
    full_server_documents_file_path = cwd + '/documents/' + document_id + '.txt'
    full_server_documents_signed_file_path = None

    if security_flag == "1":  # security_flag is Confidentiality
        # revert aes key to unencrypted format
        aes_key_ciphertext = bytes.fromhex(hexlified_aes_key_ciphertext)
        aes_key = decrypt_aes_key_ForConf(aes_key_ciphertext)

        # revert iv from str to int
        iv = int(iv_str)

        try:
            # read encrypted file content
            with open(full_server_documents_file_path, 'r') as f:
                file_content_ciphertext_hexed = f.read()

            # revert encrypted file content to byte format
            file_content_ciphertext = bytes.fromhex(file_content_ciphertext_hexed)

            # decrypt from AES-256-CTR encryption
            aes = pyaes.AESModeOfOperationCTR(aes_key, pyaes.Counter(iv))
            file_content = aes.decrypt(file_content_ciphertext)
        except:
            # assuming if the file is missing this is a server integrity problem
            no_integrity_problem = False

    elif security_flag == "2":  # security_flag is Integrity

        try:
            # read file_content in the orignal file
            with open(full_server_documents_file_path, 'r') as f:
                file_content = f.read()

            full_server_documents_signed_file_path = cwd + '/documents/' + document_id + '_signed.txt'

            # read signed file content
            with open(full_server_documents_signed_file_path, 'r') as f:
                signed_file_content = f.read()

            no_integrity_problem = compare_signed_with_unsigned_ForInteg(file_content, signed_file_content)
        except:
            # assuming if the file is missing this is a server integrity problem
            no_integrity_problem = False

    # Null-out file content if integrity check fails
    if not no_integrity_problem:
        file_content = None

    if no_integrity_problem:
        # update meta-data of document to indicate it is checked out
        run_database_query("UPDATE User_Documents SET doc_status = ? WHERE document_id = ?", 1, (1, document_id))

        # remove the server-side signed file - since that cannot be reused
        if security_flag == "2":
            os.remove(full_server_documents_signed_file_path)

    # tuplelize content to send back
    fc_and_integCheck_tuple = (file_content, no_integrity_problem)

    return fc_and_integCheck_tuple


def delete_file(document_id: str) -> bool:
    '''
    method takes care of deleting a file from server during delete operation
    returns whether the procedure was completed successfully
    '''
    procedure_completed = False

    # get the security flag of this document
    all_document_info = run_database_query("SELECT * FROM User_Documents WHERE document_id = ?", 2, (document_id,))
    security_flag = str(all_document_info[0][2])

    # compute full file path to server/application/documents for original file
    cwd = os.getcwd()
    full_server_documents_file_path = cwd + '/documents/' + document_id + '.txt'
    full_server_documents_signed_file_path = None

    if security_flag == "1":  # security_flag is Confidentiality
        try:
            # remove file
            os.remove(full_server_documents_file_path)
        except:
            # assuming if the file is missing this is a server integrity problem
            procedure_completed = False

    elif security_flag == "2":  # security_flag is Integrity
        try:
            # remove file
            os.remove(full_server_documents_file_path)

            # remove signed file
            os.remove(full_server_documents_signed_file_path)
        except:
            # assuming if the file is missing this is a server integrity problem
            procedure_completed = False

    # delete all grants to document
    interactWith_Documents_Access_Grants_table(False, document_id, None, None)

    # delete all meta-data of document
    interactWith_User_Documents_table(False, document_id, None, None, None)

    procedure_completed = True

    return procedure_completed


# helper methods for grants
def add_grant(document_id: str, target_users: str, access_right: str, access_time: str) -> bool:
    '''
    adds grant to the Documents_Access_Grants table
    '''
    grant_added = False
    try:
        access_right = int(access_right)  # ...for storage purposes

        # calculate the time till the grant expires
        seconds_to_add = int(access_time)
        access_till_time = datetime.now() + timedelta(seconds=seconds_to_add)

        # remove all existing grants for the file from the Documents_Access_Grants table
        interactWith_Documents_Access_Grants_table(False, document_id, None, None)

        # add the grant to the Documents_Access_Grants table
        run_database_query(
            "INSERT INTO 'Documents_Access_Grants'('document_id', 'target_users', 'access_right', 'access_till_time') VALUES (?, ?, ?, ?);",
            1, (document_id, target_users, access_right, access_till_time))

        grant_added = True

    except Exception as error:
        grant_added = False
        print("exception occurred when adding grant:", error)

    return grant_added


class welcome(Resource):
    def get(self):
        return "Welcome to the secure shared server!"


class login(Resource):
    def post(self):
        data = request.get_json()
        '''
            Response format for success and failure are given below. The same
            keys ('status', 'message', 'session_token') should be used.
        '''

        # Information coming from the client
        user_id = data['user-id']
        statement = data['statement']
        signed_statement = data['signed-statement']

        success = verify_statement(statement, signed_statement,
                                   user_id)  # verify the signed_statement and find if it is valid (True)

        if success:
            # below generates a secure (cryptographically-speaking) random URL-safe text string
            session_token = secrets.token_urlsafe(16)  # Generate session token

            # Similar response format given below can be used for all the other functions
            response = {
                'status': 200,
                'message': 'Login Successful',
                'session_token': session_token,
            }

            # add new user to database
            run_database_query(
                "INSERT INTO 'Active_Users'('user_id', 'host_client', 'session_token') VALUES (?, ?, ?);", 1,
                (user_id, statement.split(' ', 1)[0], session_token))

        else:
            response = {
                'status': 700,
                'message': 'Login Failed',
                'session_token': "INVALID",
            }
        return jsonify(response)


class checkout(Resource):
    """
    Expected response status codes
    1) 200 - Document Successfully checked out
    2) 702 - Access denied checking out
    3) 703 - Check out failed due to broken integrity
    4) 704 - Check out failed since file not found on the server
    5) 700 - Other failures
    """

    def post(self):
        data = request.get_json()
        document_id = data['document-id']
        session_token = data['session-token']

        # verify session is active (viz. exists in Active_Users)
        session_is_active = interactWith_Active_Users_table(True, None, session_token)
        response_status = 2  # this indicates which response to return AND  whether the server should checkout the file (only if response_status == 1)

        if session_is_active:

            # get the user information then check if the user is owner of the file OR if the user has a checkin grant to the file
            all_user_info = run_database_query("SELECT * FROM Active_Users WHERE session_token = ?", 2,
                                               (session_token,))

            # print(f"DEBUG: retrieved all_user_info: {all_user_info}")
            user_id = all_user_info[0][0]

            # verify file with name (document-id) doesn't exist in User_Documents table
            file_exists = interactWith_User_Documents_table(True, document_id, None, None, None)

            if file_exists:
                checkout_access = False
                # print("DEBUG: file exists")
                if all_user_info is not None or len(all_user_info) > 0:
                    documentId_with_this_user_as_owner_exists = interactWith_User_Documents_table(True, document_id,
                                                                                                  user_id, None, None)

                    if documentId_with_this_user_as_owner_exists:
                        checkout_access = True
                        # print("DEBUG: user is file owner")
                    else:
                        # get the owner of the document (who we know is not this user)
                        # all_document_info = run_database_query("SELECT * FROM User_Documents WHERE document_id = ?", 2, (document_id,))
                        # print(f"DEBUG: owner is actually: {all_document_info[0][1]}")

                        # check if the user has the right to checkout for the file currently in the Documents_Access_Grants table
                        checkout_access = interactWith_Documents_Access_Grants_table(True, document_id, user_id,
                                                                                     2)  # 2 = checkout right

                    # if document-id in User_Documents table AND user has right to checkout, check if document is checked out
                    if checkout_access:
                        document_is_checked_out = interactWith_User_Documents_table(True, document_id, None, None,
                                                                                    1)  # 1 = checked_out
                        if not document_is_checked_out:
                            # print("DEBUG: file is not checked out")
                            # send response 200 indicating that client can checkout file because they are owner OR have checkout grant to it
                            # ...and it is currently not checked out
                            response_status = 1
                        else:
                            # assumption that this error can be used in this case as well
                            # print("DEBUG: file is checked out")
                            response_status = 2
                    else:
                        # print("DEBUG: checkout access is not allowed")
                        response_status = 2
                else:
                    # print("DEBUG: all_user_info could not be acquired")
                    response_status = 5
            else:
                # since file doesn't exist...
                response_status = 4
        else:
            # print("DEBUG: session is not active")
            response_status = 5

        # ------------------------------------------------------------------------------
        # logic to derive response and checkout file (if valid)
        # ------------------------------------------------------------------------------
        # get the file content if response is expected to be status code 200
        if response_status == 1:
            # check-out the file content and return file_content IF no_integrity_problem
            # file_cent will be None if no_integrity_problem is False
            (file_content, no_integrity_problem) = checkout_file(document_id)

            if not no_integrity_problem:
                response_status = 3

        if response_status == 1:
            response = {
                'status': 200,
                'message': 'Document Successfully checked out',
                'file-content': file_content,
            }

        elif response_status == 2:
            response = {
                'status': 702,
                'message': 'Access denied checking out',
            }

        elif response_status == 3:
            response = {
                'status': 703,
                'message': 'Check out failed due to broken integrity',
            }

        elif response_status == 4:
            response = {
                'status': 704,
                'message': 'Check out failed since file not found on the server',
            }

        elif response_status == 5:
            response = {
                'status': 700,
                'message': 'Other failures',
            }
        return jsonify(response)


class checkin(Resource):
    """
    Expected response status codes:
    1) 200 - Document Successfully checked in
    2) 702 - Access denied checking in
    3) 700 - Other failures
    """

    def post(self):
        data = request.get_json()
        # Information coming from the client
        document_id = data['document-id']
        security_flag = data['security-flag']
        session_token = data['session-token']
        file_content = data['file-content']

        owner = None
        user_id = None

        # print(f"DEBUG: sending for checkin  - document_id = {document_id}, security_flag = {security_flag}, session_token = {session_token}, file_content = {file_content}")
        # verify session is active (viz. exists in Active_Users)
        session_is_active = interactWith_Active_Users_table(True, None, session_token)
        response_status = 2  # this indicates which response to return AND  whether the server should checkin the file (only if response_status == 1)

        if session_is_active:

            # get the user information then check if the user is owner of the file OR if the user has a checkin grant to the file
            all_user_info = run_database_query("SELECT * FROM Active_Users WHERE session_token = ?", 2,
                                               (session_token,))

            # print(f"DEBUG: retrieved all_user_info: {all_user_info}")
            user_id = all_user_info[0][0]

            # verify file with name (document-id) doesn't exist in User_Documents table
            file_exists = interactWith_User_Documents_table(True, document_id, None, None, None)

            if file_exists:
                checkin_access = False
                # print("DEBUG: file exists")
                if all_user_info is not None or len(all_user_info) > 0:
                    documentId_with_this_user_as_owner_exists = interactWith_User_Documents_table(True, document_id,
                                                                                                  user_id, None, None)

                    if documentId_with_this_user_as_owner_exists:
                        owner = user_id
                        checkin_access = True
                        # print("DEBUG: user is file owner")
                    else:
                        # get the owner of the document (who we know is not this user)
                        all_document_info = run_database_query("SELECT * FROM User_Documents WHERE document_id = ?", 2,
                                                               (document_id,))
                        owner = all_document_info[0][1]
                        # print(f"DEBUG: owner is actually: {owner}")

                        # check if the user has the right to checkin for the file currently in the Documents_Access_Grants table
                        checkin_access = interactWith_Documents_Access_Grants_table(True, document_id, user_id,
                                                                                    1)  # 1 = checkin right

                    # if document-id in User_Documents table AND user has right to checkin, check if document is checked out
                    if checkin_access:
                        response_status = 1
                    else:
                        # print("DEBUG: checkin access is not allowed")
                        response_status = 2
                else:
                    # print("DEBUG: all_user_info could not be acquired")
                    response_status = 3
            else:
                # since file doesn't exist this user is made the owner
                owner = user_id

                # send response 200 indicating that client can send file since it doesn't exist
                response_status = 1
        else:
            # print("DEBUG: session is not active")
            response_status = 3

        # ------------------------------------------------------------------------------
        # logic to derive response and checkin file (if valid)
        # ------------------------------------------------------------------------------
        # check in file if response is expected to be status code 200
        if response_status == 1:
            # check-in the actual file content
            checked_in_success = checkin_file(document_id, owner, security_flag, file_content)
            if not checked_in_success:
                response_status == 3

        if response_status == 1:
            response = {
                'status': 200,
                'message': 'Document Successfully checked in',
            }

        elif response_status == 2:
            response = {
                'status': 702,
                'message': 'Access denied checking in',
            }

        elif response_status == 3:
            response = {
                'status': 700,
                'message': 'Other failures',
            }
        return jsonify(response)


class grant(Resource):
    """
        Expected response status codes:
        1) 200 - Successfully granted access
        2) 702 - Access denied to grant access
        3) 700 - Other failures
    """

    def post(self):
        data = request.get_json()
        # Information coming from the client
        document_id = data['document-id']
        target_users = data['target-users']
        access_right = data['access-right']
        access_time = data['access-time']
        session_token = data['session-token']

        # print(f"DEBUG: sending for grant  - document_id = {document_id}, target_users = {target_users}, access_right = {access_right}, access_time = {access_time}")
        # verify session is active (viz. exists in Active_Users)
        session_is_active = interactWith_Active_Users_table(True, None, session_token)
        response_status = 2  # this indicates which response to return AND whether the server should add the grant (only if response_status == 1)

        if session_is_active:

            # get the user information then check if the user is owner of the file OR if the user has a checkin grant to the file
            all_user_info = run_database_query("SELECT * FROM Active_Users WHERE session_token = ?", 2,
                                               (session_token,))

            # print(f"DEBUG: retrieved all_user_info: {all_user_info}")
            user_id = all_user_info[0][0]

            # verify file with name (document-id) doesn't exist in User_Documents table
            file_exists = interactWith_User_Documents_table(True, document_id, None, None, None)

            if file_exists:
                grant_access = False
                # print("DEBUG: file exists")
                if all_user_info is not None or len(all_user_info) > 0:
                    documentId_with_this_user_as_owner_exists = interactWith_User_Documents_table(True, document_id,
                                                                                                  user_id, None, None)

                    if documentId_with_this_user_as_owner_exists:
                        grant_access = True
                        # print("DEBUG: user is file owner")
                    else:
                        response_status = 2

                    # if document-id in Documents_Access_Grants table AND user has right to grant (viz. owner) then try to add the grant
                    if grant_access:
                        # add grant
                        grant_added = add_grant(document_id, target_users, access_right, access_time)
                        if grant_added:
                            response_status = 1
                    else:
                        # print("DEBUG: grant access is not allowed")
                        response_status = 2
                else:
                    # print("DEBUG: all_user_info could not be acquired")
                    response_status = 3
            else:
                # print("DEBUG: file does not exist")
                response_status = 3
        else:
            # print("DEBUG: session is not active")
            response_status = 3

        # ------------------------------------------------------------------------------
        # logic to derive response and checkout file (if valid)
        # ------------------------------------------------------------------------------
        if response_status == 1:
            response = {
                'status': 200,
                'message': 'Successfully granted access',
            }
        elif response_status == 2:
            response = {
                'status': 702,
                'message': 'Access denied to grant access',
            }
        elif response_status == 3:
            response = {
                'status': 700,
                'message': 'Other failures',
            }

        return jsonify(response)


class delete(Resource):
    """
        Expected response status codes:
        1) 200 - Successfully deleted the file
        2) 702 - Access denied deleting file
        3) 704 - Delete failed since file not found on the server
        4) 700 - Other failures
    """

    def post(self):
        data = request.get_json()

        # Information coming from the client
        document_id = data['document-id']
        session_token = data['session-token']

        # print(f"DEBUG: sending for delete  - document_id = {document_id}")
        # verify session is active (viz. exists in Active_Users)
        session_is_active = interactWith_Active_Users_table(True, None, session_token)
        response_status = 2  # this indicates which response to return AND whether the server should add the grant (only if response_status == 1)

        if session_is_active:

            # get the user information then check if the user is owner of the file OR if the user has a checkin grant to the file
            all_user_info = run_database_query("SELECT * FROM Active_Users WHERE session_token = ?", 2,
                                               (session_token,))

            # print(f"DEBUG: retrieved all_user_info: {all_user_info}")
            user_id = all_user_info[0][0]

            # verify file with name (document-id) doesn't exist in User_Documents table
            file_exists = interactWith_User_Documents_table(True, document_id, None, None, None)

            if file_exists:
                delete_access = False
                # print("DEBUG: file exists")
                if all_user_info is not None or len(all_user_info) > 0:
                    documentId_with_this_user_as_owner_exists = interactWith_User_Documents_table(True, document_id,
                                                                                                  user_id, None, None)
                    if documentId_with_this_user_as_owner_exists:
                        delete_access = True
                        # print("DEBUG: user is file owner")
                    else:
                        response_status = 2

                    # if document-id in Documents_Access_Grants table AND user has right to delete (viz. owner) then try to delete file
                    if delete_access:
                        # delete file
                        file_deleted = delete_file(document_id)
                        if file_deleted:
                            response_status = 1
                    else:
                        # print("DEBUG: delete access is not allowed")
                        response_status = 2
                else:
                    # print("DEBUG: all_user_info could not be acquired")
                    response_status = 4
            else:
                # print("DEBUG: file does not exist")
                response_status = 3
        else:
            # print("DEBUG: session is not active")
            response_status = 4

        # ------------------------------------------------------------------------------
        # logic to derive response and checkout file (if valid)
        # ------------------------------------------------------------------------------

        if response_status == 1:
            response = {
                'status': 200,
                'message': 'Successfully deleted the file',
            }
        elif response_status == 2:
            response = {
                'status': 702,
                'message': 'Access denied deleting file',
            }
        elif response_status == 3:
            response = {
                'status': 704,
                'message': 'Delete failed since file not found on the server',
            }
        elif response_status == 4:
            response = {
                'status': 700,
                'message': 'Other failures',
            }
        return jsonify(response)


class logout(Resource):
    def post(self):
        """
            Expected response status codes:
            1) 200 - Successfully logged out
            2) 700 - Failed to log out
        """
        data = request.get_json()

        # Information coming from the client
        session_token = data['session-token']

        # verify session is active (viz. exists in Active_Users)
        session_is_active = interactWith_Active_Users_table(True, None, session_token)
        response_status = 2  # this indicates which response to return AND  whether the server should logout the user (only if response_status == 1)

        if session_is_active:
            # get the user information then check if the user is owner of the file OR if the user has a checkin grant to the file
            all_user_info = run_database_query("SELECT * FROM Active_Users WHERE session_token = ?", 2,
                                               (session_token,))
            # print(f"DEBUG: retrieved all_user_info: {all_user_info}")
            # user_id = all_user_info[0][0]

            if all_user_info is not None or len(all_user_info) > 0:
                # delete this user
                interactWith_Active_Users_table(False, None, session_token)
                response_status = 1
            else:
                # print("DEBUG: all_user_info could not be acquired")
                response_status = 2
        else:
            # print("DEBUG: session is not active")
            response_status = 2

        # ------------------------------------------------------------------------------
        # logic to derive response and checkout file (if valid)
        # ------------------------------------------------------------------------------

        if response_status == 1:
            response = {
                'status': 200,
                'message': 'Successfully logged out',
            }
        elif response_status == 2:
            response = {
                'status': 700,
                'message': 'Failed to log out',
            }
        return jsonify(response)


api.add_resource(welcome, '/')
api.add_resource(login, '/login')
api.add_resource(checkin, '/checkin')
api.add_resource(checkout, '/checkout')
api.add_resource(grant, '/grant')
api.add_resource(delete, '/delete')
api.add_resource(logout, '/logout')


def main():
    setup_the_database()
    secure_shared_service.run(debug=True)


if __name__ == '__main__':
    main()
