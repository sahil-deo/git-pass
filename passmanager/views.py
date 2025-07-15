from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader
from django.contrib import messages

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import base64
import json
import requests
import csv
from datetime import datetime
# Create your views here.

def checkData(request):
    _token = request.COOKIES.get('_token')
    _repo = request.COOKIES.get('_repo')
    _username = request.COOKIES.get('_username')
    _path = request.COOKIES.get('_path')
    _mas_password = request.session.get('mas_password')

    if _token == None or _repo == None or _username == None or _path == None or _mas_password == None:
        return False
    else:
        return True


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
    
    if checkData(request) == False:
        return redirect("/")
        


    _token = request.COOKIES.get('_token')
    _repo = request.COOKIES.get('_repo')
    _username = request.COOKIES.get('_username')
    _path = request.COOKIES.get('_path')
    _mas_password = request.session.get('mas_password')

    try:
        check, error, old_content = get_file_from_github(_token, _username, _repo, _path, _mas_password)


        if not check:
            del request.session['mas_password']
            return redirect("/")

        content = [[]]
        if old_content != None: 
            content = convertFromString(old_content)

        
        context = {'content': content}
        
    except(): 
        
        context = {'content', [[]]}
        

    return render(request, 'passwords.html', context)

def newpassword(request):
    
    
    if checkData(request) == False:
        return redirect("/")

    if request.method == 'POST':
        
        _name = request.POST.get('name')
        _uname = request.POST.get('uname')
        _pass = request.POST.get('password')
        _mas_password = request.session.get('mas_password')

        _token = request.COOKIES.get('_token')
        _repo = request.COOKIES.get('_repo')
        _username = request.COOKIES.get('_username')
        _path = request.COOKIES.get('_path')
        
        if _name == "":
            _name = " "
        
        if _uname == "":
            _uname = " "
        
        if _pass == "":
            _pass = " "

        content = [_name, _uname, _pass]

        check, error, old_content = get_file_from_github(_token, _username, _repo, _path, _mas_password)

        if old_content == None:
            old_content = [[]]

        elif old_content != None:
            old_content = convertFromString(old_content)
        old_content.append(content)
        push_to_github(_token, _username, _repo, _path, _mas_password,convertToString(sortList(old_content)))
    
    return render(request, 'new.html')

def settings(request):

    
    if checkData(request) == False:
        return redirect("/")
    
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
        _mas_password = request.POST.get('mas_password')

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

def instructions(request):
    return render(request, "instructions.html")




def reset_master(request):
    if checkData(request) == False:
        return redirect("/")
    
    if request.method == 'POST':

        current_password = request.POST.get("old_password") 
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")
        
        if current_password == request.session.get('mas_password'):

            if new_password == confirm_password:
                mas_password = request.session.get('mas_password')
                token = request.COOKIES.get('_token')
                repo = request.COOKIES.get('_repo')
                username = request.COOKIES.get('_username')
                path = request.COOKIES.get('_path')
                
                check, error, content = get_file_from_github(token, username, repo, path, mas_password)
                
                if check:  
                    decrypted_token = denc(request.COOKIES.get('_token'), mas_password)
                    
                    request.session['mas_password'] = new_password
                    
                    response = HttpResponseRedirect("../")
                    response.set_cookie('_token', enc(decrypted_token, new_password))
                    
                    push_to_github(enc(decrypted_token, new_password), username, repo, path, new_password, content)
                    
                    messages.success(request, "Master password updated successfully!")
                    return response
                else:
                    messages.error(request, f"Error accessing GitHub data: {error}")
            else:
                messages.error(request, "New passwords do not match!")
        else:
            pass
            messages.error(request, "Current password is incorrect!")
    
    return render(request, "resetmaster.html")

def update(request, id):


    
    if checkData(request) == False:
        return redirect("/")
    
    if request.method == 'POST':
        _mas_password = request.session.get('mas_password')
        _token = request.COOKIES.get('_token')
        _repo = request.COOKIES.get('_repo')
        _username = request.COOKIES.get('_username')
        _path = request.COOKIES.get('_path')
        
        if request.POST.get('action') == "Delete":
            return delete(request, id)

        _name = request.POST.get('0')
        _uname = request.POST.get('1')
        _pass = request.POST.get('2')
        
        if _name == "":
            _name = " "
        
        if _uname == "":
            _uname = " "
        
        if _pass == "":
            _pass = " "
        
        content = [_name, _uname, _pass]

        a, b, old_content = get_file_from_github(_token, _username, _repo, _path, _mas_password)        
        old_content = convertFromString(old_content)
        del old_content[id]
        old_content.append(content)


        push_to_github(_token, _username, _repo, _path, _mas_password,convertToString(sortList(old_content)))
        return redirect("../")

def delete(request, id):

    
    if checkData(request) == False:
        return redirect("/")
    if request.method == 'POST':
        
        _mas_password = request.session.get('mas_password')

        _token = request.COOKIES.get('_token')
        _repo = request.COOKIES.get('_repo')
        _username = request.COOKIES.get('_username')
        _path = request.COOKIES.get('_path')
        

        a, b, old_content = get_file_from_github(_token, _username, _repo, _path, _mas_password)        
        old_content = convertFromString(old_content)
        del old_content[id]

        push_to_github(_token, _username, _repo, _path, _mas_password,convertToString(sortList(old_content)))
        return redirect("../")

    pass

def deleteall(request):

    if checkData(request) == False:
        return redirect("/")

    _mas_password = request.session.get('mas_password')
    _token = request.COOKIES.get('_token')
    _repo = request.COOKIES.get('_repo')
    _username = request.COOKIES.get('_username')
    _path = request.COOKIES.get('_path')


    push_to_github(_token, _username, _repo, _path, _mas_password, "")


    return redirect("/")

def logout(request):

    if checkData(request) == False:
        return redirect("/")

    del request.session['mas_password']
    return redirect("..")

def create_backup(request):
    if checkData(request) == False:
        return redirect('/')
    

    if request.method == 'POST':
        _mas_password = request.session.get('mas_password')
        _token = request.COOKIES.get('_token')
        _repo = request.COOKIES.get('_repo')
        _username = request.COOKIES.get('_username')
        _path = request.COOKIES.get('_path')


        now = datetime.now()
        _timedate = f"{now.day}-{now.month}-{now.year}"

        _backfilename = f"{_timedate}-{_path}.backup"

        check, error, _content = get_file_from_github(_token, _username, _repo, _path, _mas_password)

        push_to_github(_token, _username, _repo, _backfilename, _mas_password, _content, "Backup for Passwords")

    
    return redirect("../")

    pass



def push_to_github(token, owner, repo, path, password, new_content, commit_msg="Update via token", branch="main"):

    try:
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
            return result.json()
        else:
            return None
        
    except Exception:
        pass

def get_file_from_github(token, owner, repo, path, password, branch="main"):

    try:
        # Step 1: Decrypt token. This is where the ValueError can happen.
        try:
            decrypted_token = denc(token, password)
        except ValueError: # Catch the specific "MAC check failed" error
            return (False, "Decryption failed. Please check your Master Password.", None)
        except Exception as e: # Catch any other unexpected decryption errors
            return (False, "An unexpected decryption error occurred.", None)

        headers = {
            "Authorization": f"token {decrypted_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"

        # Step 2: Get the file content
        response = requests.get(url, headers=headers, params={"ref": branch})

        if response.status_code == 200:
            content_b64 = response.json().get('content')
            encrypted_content = base64.b64decode(content_b64).decode()
            
            # Step 3: Decrypt the file content itself. This could also fail.
            try:
                decrypted_content = ""
                if(encrypted_content != "\n"):
                    print("size:", len(encrypted_content))
                    decrypted_content = denc(encrypted_content, password)
                return (True, "File fetched successfully.", decrypted_content)
            except ValueError:
                return (False, "Could not decrypt the file content. The Master Password may be incorrect for this file.", None)
        
        # Handle API errors
        elif response.status_code == 401:
            return (False, "Authentication failed. Your GitHub token is likely invalid.", None)
        elif response.status_code == 404:
            return (False, "File or Repository not found. Check your Username, Repo Name, and File Path.", None)
        else:
            error_details = response.json().get('message', response.text)
            return (False, f"GitHub API Error: {response.status_code} - {error_details}", None)

    except requests.exceptions.RequestException as e:
        return (False, "A network error occurred. Please check your internet connection.", None)
    except Exception as e:
        return (False, "An unexpected error occurred.", None)

def convertToString(lst):
    # ✅ ChatGPT fix: replaced `:`-joining with JSON string
    return json.dumps(lst)

def convertFromString(s):
    # ✅ ChatGPT fix: replaced manual split with JSON decoding
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return []



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


    return plaintext.decode()



def sortList(lst):
    safe_list = [item for item in lst if isinstance(item, list) and len(item) > 0]
    sort = sorted(safe_list, key=lambda x: str(x[0]).casefold())
    return sort


def fromCsv(file_path):
    result = []
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if len(row) == 3:
                result.append(row)
    return result


def upload_csv(request):
    
    
    if not checkData(request):
        return redirect("/")

    
    
    if request.method == 'POST' and request.FILES.get('passwordfile'):
        _mas_password = request.session.get('mas_password')
        _token = request.COOKIES.get('_token')
        _repo = request.COOKIES.get('_repo')
        _username = request.COOKIES.get('_username')
        _path = request.COOKIES.get('_path')
        
        
        uploaded_file = request.FILES['passwordfile']
        decoded_file = uploaded_file.read().decode('utf-8').splitlines()
        reader = csv.reader(decoded_file)

        next(reader, None) # skip header row

        data = []
        for row in reader:
            if len(row) >= 1:
                data.append(row[:3]) 

        check, error, old_content = (get_file_from_github(_token, _username, _repo, _path, _mas_password))        
        old_content = convertFromString(old_content)
        old_content.extend(data)

        push_to_github(_token, _username, _repo, _path, _mas_password,convertToString(sortList(old_content)))

        return redirect("../")

    return redirect("../")