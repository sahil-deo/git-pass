from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader
import base64
import json
import requests
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Create your views here.

def passwords(request):

    if request.method == 'POST':
        _token = request.COOKIES.get('_token')
        _repo = request.COOKIES.get('_repo')
        _username = request.COOKIES.get('_username')
        _path = request.COOKIES.get('_path')

        
        old_content = get_file_from_github(_username, _repo, _path, "password",  _token)
        print(old_content)
        content = convertFromString(old_content)
        print(content)
        context = {'content': content}
        return render(request, 'passwords.html', context)
    

    return render(request, 'getdata.html')


def newpassword(request):

    if request.method == 'POST':
        
        _name = request.POST.get('name')
        _uname = request.POST.get('uname')
        _pass = request.POST.get('password')

        _token = request.COOKIES.get('_token')
        _repo = request.COOKIES.get('_repo')
        _username = request.COOKIES.get('_username')
        _path = request.COOKIES.get('_path')
        
        content = [_name, _uname, _pass]

        old_content = convertFromString(get_file_from_github(_username, _repo, _path, "password", _token))
        print(old_content)
        old_content.append(content)
        print(old_content)

        push_to_github(_token, _username, _repo, _path, convertToString(old_content), "password")

    # template = loader.get_template('new.html')
    # return HttpResponse(template.render(), request)
    
    return render(request, 'new.html')




def home(request):
    c_token = request.COOKIES.get('_token')
    c_repo = request.COOKIES.get('_repo')
    c_username = request.COOKIES.get('_username')
    c_path = request.COOKIES.get('_path')



    if request.method == 'POST':
        
        _token = request.POST.get('token')
        _repo = request.POST.get('repo')
        _username = request.POST.get('username')
        _path = request.POST.get('path')
        _action = request.POST.get('action')

        if _action == "All Passwords":
            redirect_url = "/passwords/"
        elif _action == "New Password":
            redirect_url = "/new/"
        else:
            redirect_url = "/"  # fallback
        
        response = HttpResponseRedirect(redirect_url)
        if c_token == "none" or (c_token != _token):
            response.set_cookie('_token', _token)
        if c_repo == "none" or c_repo != _repo:
            response.set_cookie('_repo', _repo)
        if c_path == "none" or c_path != _path:
            response.set_cookie('_path', _path)
        if c_username == "none" or c_username != _username:
            response.set_cookie('_username', _username)
        return response

    t = ""
    r = ""
    p = ""
    u = ""

    if c_token != "none":
        t = c_token
    if c_repo != "none":
        r = c_repo
    if c_path != "none":
        p = c_path
    if c_username != "none":
        u = c_username

    context = {
        'token': t,
        'repo': r,
        'path': p,
        'username': u
    }

    template = loader.get_template('home.html')
    return HttpResponse(template.render(context, request))



def push_to_github(token, owner, repo, path, new_content, password, commit_msg="Update via token", branch="main"):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json"
    }

    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"

    # Get current file SHA (needed for update)
    response = requests.get(url, headers=headers, params={"ref": branch})
    if response.status_code == 200:
        sha = response.json()['sha']
    else:
        sha = None  # File does not exist yet

    # Prepare content
    encoded_content = base64.b64encode(enc(new_content, password).encode()).decode()
    payload = {
        "message": commit_msg,
        "content": encoded_content,
        "branch": branch
    }
    if sha:
        payload["sha"] = sha

    # Push file (create or update)
    result = requests.put(url, headers=headers, data=json.dumps(payload))

    if result.status_code in [200, 201]:
        print("✅ File pushed successfully.")
        return result.json()
    else:
        print("❌ Error:", result.text)
        return None

def get_file_from_github(owner, repo, path, password, token=None, branch="main"):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    headers = {
        "Accept": "application/vnd.github.v3+json"
    }
    if token:
        headers["Authorization"] = f"token {token}"

    params = {"ref": branch}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        content_data = response.json()
        decoded_content = base64.b64decode(content_data['content']).decode()
        if len(decoded_content) > 10:
            dec_content = denc(decoded_content, password)
            return dec_content
            pass   
        return decoded_content
    else:
        raise Exception(f"Error fetching file: {response.status_code} - {response.text}")


def convertToString(lst):
    
   # Input list of lists

    # Flatten the list and join with ':'
    result = ':'.join(word for group in lst for word in group)
    return result


def convertFromString(s):
    s = s[0:]
    print(s)
    words = [w for w in s.split(':') if w]
    # Group every 3 words into sublists
    result = [words[i:i+3] for i in range(0, len(words), 3)]
    return result


def enc(data, password):

    data = data.encode()

    # Derive key
    salt = get_random_bytes(16)  # chatGPT: random salt, store this
    key = PBKDF2(password, salt, dkLen=32)

    # Encrypt
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Combine salt + nonce + tag + ciphertext
    encrypted_blob = salt + cipher.nonce + tag + ciphertext

    # Encode to base64 for storage/transmission
    encrypted_b64 = base64.b64encode(encrypted_blob).decode()

    print("Encrypted (base64):", encrypted_b64)

    return encrypted_b64



def denc(data, password):
    # Decode from base64 to binary
    raw = base64.b64decode(data)  # chatGPT: decode before splitting

    # Extract parts
    salt, nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:48], raw[48:]
    key = PBKDF2(password, salt, dkLen=32)

    # Decrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    print("Decrypted:", plaintext.decode())

    return plaintext.decode()
