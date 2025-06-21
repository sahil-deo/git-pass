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


def home(request):
    
    c_token = request.COOKIES.get('_token')
    c_repo = request.COOKIES.get('_repo')
    c_username = request.COOKIES.get('_username')
    c_path = request.COOKIES.get('_path')


    c_mas_passsword = request.session.get('mas_password')


    if request.method == 'POST':
        
        _token = request.POST.get('token')
        _repo = request.POST.get('repo')
        _username = request.POST.get('username')
        _path = request.POST.get('path')
        _action = request.POST.get('action')
        _mas_password = request.POST.get('mas_password')
        request.session['mas_password'] = _mas_password

        redirect_url = "/passwords/"
        
        response = HttpResponseRedirect(redirect_url)

        if _token != "Token is Saved, Input to Change Token" and _token != c_token:
            response.set_cookie('_token', enc(_token, _mas_password))
       
        if c_repo != _repo:
            response.set_cookie('_repo', _repo)
       
        if c_path != _path:
            response.set_cookie('_path', _path)
        
        if c_username != _username:
            response.set_cookie('_username', _username)
        

        return response

    if((c_token != None or c_token =="Token is Saved, Input to Change Token") and c_repo != None and c_username != None and c_path != None and c_mas_passsword != None ):
        return HttpResponseRedirect('/passwords/')

    t, r, u, p, m = "", "", "", "", ""
    if c_token != None:
        t = "Token is Saved, Input to Change Token"
    
    if c_repo != None:
        r = c_repo
        
    if c_username != None:
        u = c_username
    
    if c_path != None:
        p = c_path
    
    
    context = {
        'repo': r,
        'token': t,
        'username': u,
        'path': p,
 
    }

    template = loader.get_template('home.html')
    return HttpResponse(template.render(context, request))

def passwords(request):

    _token = request.COOKIES.get('_token')
    _repo = request.COOKIES.get('_repo')
    _username = request.COOKIES.get('_username')
    _path = request.COOKIES.get('_path')
    _mas_password = request.session.get('mas_password')

    if _token == None or _repo == None or _username == None or _path == None or _mas_password == None:
        return redirect("../")

    try:
        old_content = get_file_from_github(_username, _repo, _path, _mas_password, _token)

        print(old_content)
        content = convertFromString(old_content)
        print(content)
        context = {'content': content}
        
    except(): 
        
        context = {'content', [[]]}
        

    return render(request, 'passwords.html', context)

def newpassword(request):

    print("OUT PASS:", request.session['mas_password'])

    if request.method == 'POST':
        
        _name = request.POST.get('name')
        _uname = request.POST.get('uname')
        _pass = request.POST.get('password')
        _mas_password = request.session.get('mas_password')


        print("MAS PASS:", _mas_password)
        _token = request.COOKIES.get('_token')
        _repo = request.COOKIES.get('_repo')
        _username = request.COOKIES.get('_username')
        _path = request.COOKIES.get('_path')
        
        content = [_name, _uname, _pass]

        old_content = convertFromString(get_file_from_github(_username, _repo, _path, _mas_password, _token))
        print(old_content)
        old_content.append(content)
        print(old_content)

        push_to_github(_token, _username, _repo, _path, convertToString(sortList(old_content)), _mas_password)
    
    return render(request, 'new.html')

def settings(request):
    c_token = request.COOKIES.get('_token')
    c_repo = request.COOKIES.get('_repo')
    c_username = request.COOKIES.get('_username')
    c_path = request.COOKIES.get('_path')
    c_mas_password = request.session['mas_password']
    
    if request.method == 'POST':
        _token = request.POST.get('token')
        _repo = request.POST.get('repo')
        _username = request.POST.get('username')
        _path = request.POST.get('path')
        _action = request.POST.get('action')
        _mas_password = request.POST.get('mas_password')
        request.session['mas_password'] = _mas_password

        redirect_url = "/settings/"
        
        response = HttpResponseRedirect(redirect_url)

        if _token != "Token is Saved, Input to Change Token" and _token != c_token:
            response.set_cookie('_token', enc(_token, _mas_password))
       
        if c_repo != _repo:
            response.set_cookie('_repo', _repo)
       
        if c_path != _path:
            response.set_cookie('_path', _path)
        
        if c_username != _username:
            response.set_cookie('_username', _username)
        

        return response


        pass
    

    t, r, u, p, m = "", "", "", "", ""
    if c_token != None:
        t = "Token is Saved, Input to Change Token"
    
    if c_repo != None:
        r = c_repo
        
    if c_username != None:
        u = c_username
    
    if c_path != None:
        p = c_path
    
    
    context = {
        'repo': r,
        'token': t,
        'username': u,
        'path': p,
 
    }

    template = loader.get_template('settings.html')
    return HttpResponse(template.render(context, request))



def update(request, id):
    if request.method == 'POST':
        
        if request.POST.get('action') == "Delete":
            return delete(request, id)

        _name = request.POST.get('0')
        _uname = request.POST.get('1')
        _pass = request.POST.get('2')
        _mas_password = request.session['mas_password']

        _token = request.COOKIES.get('_token')
        _repo = request.COOKIES.get('_repo')
        _username = request.COOKIES.get('_username')
        _path = request.COOKIES.get('_path')
        
        content = [_name, _uname, _pass]

        old_content = convertFromString(get_file_from_github(_username, _repo, _path, _mas_password, _token))        
        print(old_content)
        del old_content[id]
        old_content.append(content)
        print(old_content)

        push_to_github(_token, _username, _repo, _path, convertToString(sortList(old_content)), _mas_password)
        return redirect("../")

def delete(request, id):
    if request.method == 'POST':
        
        _mas_password = request.session['mas_password']

        _token = request.COOKIES.get('_token')
        _repo = request.COOKIES.get('_repo')
        _username = request.COOKIES.get('_username')
        _path = request.COOKIES.get('_path')
        

        old_content = convertFromString(get_file_from_github(_username, _repo, _path, _mas_password, _token))        
        print(old_content)
        del old_content[id]

        push_to_github(_token, _username, _repo, _path, convertToString(sortList(old_content)), _mas_password)
        return redirect("../")

    pass



def deleteall(request):
    _token = request.COOKIES.get('_token')
    _repo = request.COOKIES.get('_repo')
    _username = request.COOKIES.get('_username')
    _path = request.COOKIES.get('_path')

    push_to_github(_token, _username, _repo, _path, "", request.session['mas_password'])

    return redirect("/")



def push_to_github(token, owner, repo, path, new_content, password, commit_msg="Update via token", branch="main"):
    
    headers = {
        "Authorization": f"token {denc(token, password)}",
        "Accept": "application/vnd.github+json"
    }

    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"

    # Get current file SHA (needed for update)
    response = requests.get(url, headers=headers, params={"ref": branch})
    if response.status_code == 200:
        sha = response.json()['sha']
    else:
        sha = None  # File does not exist yet

    # Prepare content (sort, encrypt, encode, decode)
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
        headers["Authorization"] = f"token {denc(token, password)}"

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



def sortList(lst):
    sort =  sorted(lst, key=lambda x: x[0].casefold())
    print("Sorted", sort)
    return sort