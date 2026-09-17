from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader
from django.contrib import messages

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import base64
import json
import logging
import requests
import csv
from datetime import datetime

logger = logging.getLogger(__name__)

# Create your views here.
def notes(request):
    # Render the notes page, separate from passwords
    # Logic to load notes from the notes file (path from cookies/session)
    if checkData(request) == False:
        return redirect("/")

    _token = request.COOKIES.get('_token')
    _repo = request.COOKIES.get('_repo')
    _username = request.COOKIES.get('_username')
    notes_path = request.COOKIES.get('_notes_path') or request.session.get('notes_path')
    _mas_password = request.session.get('mas_password')

    notes = []
    current_label = request.GET.get('label', '').strip()
    all_labels = []
    if _token and _repo and _username and notes_path and _mas_password:
        try:
            check, error, old_content = get_file_from_github(_token, _username, _repo, notes_path, _mas_password)
            if check and old_content:
                notes = old_content
        except Exception:
            notes = ""
    return render(request, 'notes.html', {'encrypted_content': notes, 'mas_password': _mas_password, 'current_label': current_label})

def newnote(request):
    if checkData(request) == False:
        return redirect("/")

    _token = request.COOKIES.get('_token')
    _repo = request.COOKIES.get('_repo')
    _username = request.COOKIES.get('_username')
    notes_path = request.COOKIES.get('_notes_path') or request.session.get('notes_path')
    _mas_password = request.session.get('mas_password')

    if request.method == 'POST':
        encrypted_content = request.POST.get('encrypted_content')
        if encrypted_content:
            push_to_github(_token, _username, _repo, notes_path, _mas_password, encrypted_content)
        return redirect('/notes/')

    check, error, old_content = get_file_from_github(_token, _username, _repo, notes_path, _mas_password)
    context = {'encrypted_content': old_content if old_content else "", 'mas_password': _mas_password}
    return render(request, 'newnote.html', context)

def update_note(request, id):
    if checkData(request) == False:
        return redirect("/")

    _token = request.COOKIES.get('_token')
    _repo = request.COOKIES.get('_repo')
    _username = request.COOKIES.get('_username')
    notes_path = request.COOKIES.get('_notes_path') or request.session.get('notes_path')
    _mas_password = request.session.get('mas_password')

    if request.method == 'POST':
        encrypted_content = request.POST.get('encrypted_content')
        if encrypted_content:
            push_to_github(_token, _username, _repo, notes_path, _mas_password, encrypted_content)
        return redirect('/notes/')
    return redirect('/notes/')

def delete_note(request, id):
    if checkData(request) == False:
        return redirect("/")

    _token = request.COOKIES.get('_token')
    _repo = request.COOKIES.get('_repo')
    _username = request.COOKIES.get('_username')
    notes_path = request.COOKIES.get('_notes_path') or request.session.get('notes_path')
    _mas_password = request.session.get('mas_password')

    encrypted_content = request.POST.get('encrypted_content')
    if encrypted_content:
        push_to_github(_token, _username, _repo, notes_path, _mas_password, encrypted_content)
    return redirect('/notes/')

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
    c_notes_path = request.COOKIES.get('_notes_path') or request.session.get('notes_path')

    c_mas_password = request.session.get('mas_password')



    if request.method == 'POST':
        _token = request.POST.get('token')
        _repo = request.POST.get('repo')
        _username = request.POST.get('username')
        _path = request.POST.get('path')
        _notes_path = request.POST.get('notes_path')
        _action = request.POST.get('action')
        _mas_password = request.POST.get('mas_password')
        request.session['mas_password'] = _mas_password
        request.session['notes_path'] = _notes_path

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
        if _notes_path:
            response.set_cookie('_notes_path', _notes_path)
        return response

    if((c_token != None or c_token =="Token is Saved, Input to Change Token") and c_repo != None and c_username != None and c_path != None and c_mas_password != None ):
        return HttpResponseRedirect('/passwords/')

    t, r, u, p, m, n = "", "", "", "", "", ""
    if c_token != None:
        t = "Token is Saved, Input to Change Token"

    if c_repo != None:
        r = c_repo

    if c_username != None:
        u = c_username

    if c_path != None:
        p = c_path

    if c_notes_path != None:
        n = c_notes_path

    context = {
        'repo': r,
        'token': t,
        'username': u,
        'path': p,
        'notes_path': n,

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
            messages.error(request, error)
            del request.session['mas_password']
            return redirect("/")

        content = ""
        if old_content != None:
            content = old_content

        context = {'content': content, 'mas_password': _mas_password}

    except Exception:
        logger.exception("Unexpected password page error for repo=%s/%s path=%s", _repo, _username, _path)
        messages.error(request, "Something went wrong while contacting GitHub. Please try again.")
        context = {'content': "", 'mas_password': _mas_password}

    return render(request, 'passwords.html', context)

def newpassword(request):


    if checkData(request) == False:
        return redirect("/")

    if request.method == 'POST':

        _mas_password = request.session.get('mas_password')
        _token = request.COOKIES.get('_token')
        _repo = request.COOKIES.get('_repo')
        _username = request.COOKIES.get('_username')
        _path = request.COOKIES.get('_path')

        encrypted_content = request.POST.get('encrypted_content')
        if encrypted_content:
            push_to_github(_token, _username, _repo, _path, _mas_password, encrypted_content)
            return redirect("/passwords/")

    _mas_password = request.session.get('mas_password')
    _token = request.COOKIES.get('_token')
    _repo = request.COOKIES.get('_repo')
    _username = request.COOKIES.get('_username')
    _path = request.COOKIES.get('_path')
    check, error, old_content = get_file_from_github(_token, _username, _repo, _path, _mas_password)
    context = {'encrypted_content': old_content if old_content else "", 'mas_password': _mas_password}
    return render(request, 'new.html', context)

def settings(request):


    if checkData(request) == False:
        return redirect("/")

    c_token = request.COOKIES.get('_token')
    c_repo = request.COOKIES.get('_repo')
    c_username = request.COOKIES.get('_username')
    c_path = request.COOKIES.get('_path')
    c_notes_path = request.COOKIES.get('_notes_path') or request.session.get('notes_path')
    if request.method == 'POST':
        _token = request.POST.get('token')
        _repo = request.POST.get('repo')
        _username = request.POST.get('username')
        _path = request.POST.get('path')
        _notes_path = request.POST.get('notes_path')
        _action = request.POST.get('action')
        _mas_password = request.POST.get('mas_password')
        request.session['notes_path'] = _notes_path

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
        if _notes_path:
            response.set_cookie('_notes_path', _notes_path)
        return response


        pass


    t, r, u, p, m, n = "", "", "", "", "", ""
    if c_token != None:
        t = "Token is Saved, Input to Change Token"

    if c_repo != None:
        r = c_repo

    if c_username != None:
        u = c_username

    if c_path != None:
        p = c_path

    if c_notes_path != None:
        n = c_notes_path

    context = {
        'repo': r,
        'token': t,
        'username': u,
        'path': p,
        'notes_path': n,
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

        encrypted_content = request.POST.get('encrypted_content')
        if encrypted_content:
            push_to_github(_token, _username, _repo, _path, _mas_password, encrypted_content)
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


        encrypted_content = request.POST.get('encrypted_content')
        if encrypted_content:
            push_to_github(_token, _username, _repo, _path, _mas_password, encrypted_content)
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
        notes_path = request.COOKIES.get('_notes_path') or request.session.get('notes_path')

        now = datetime.now()
        _timedate = f"{now.day}-{now.month}-{now.year}"

        # Backup passwords file
        _backfilename_pw = f"{_timedate}-{_path}.backup"
        check_pw, error_pw, _content_pw = get_file_from_github(_token, _username, _repo, _path, _mas_password)
        push_to_github(_token, _username, _repo, _backfilename_pw, _mas_password, _content_pw, "Backup for Passwords")

        # Backup notes file if present
        if notes_path:
            _backfilename_notes = f"{_timedate}-{notes_path}.backup"
            check_notes, error_notes, _content_notes = get_file_from_github(_token, _username, _repo, notes_path, _mas_password)
            push_to_github(_token, _username, _repo, _backfilename_notes, _mas_password, _content_notes, "Backup for Notes")

    return redirect("../")



def _log_github_error(action, owner, repo, path, details, exc_info=False):
    logger.warning(
        "GitHub %s failed for repo=%s/%s path=%s: %s",
        action,
        owner,
        repo,
        path,
        details,
        exc_info=exc_info,
    )


def push_to_github(token, owner, repo, path, password, new_content, commit_msg="Update via token", branch="main"):

    try:
        headers = {
            "Authorization": f"token {denc(token, password)}",
            "Accept": "application/vnd.github+json"
        }

        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"

        response = requests.get(url, headers=headers, params={"ref": branch})
        if response.status_code == 200:
            sha = response.json()['sha']
        else:
            sha = None

        encoded_content = base64.b64encode(new_content.encode()).decode()

        payload = {
            "message": commit_msg,
            "content": encoded_content,
            "branch": branch
        }
        if sha:
            payload["sha"] = sha

        result = requests.put(url, headers=headers, data=json.dumps(payload))

        if result.status_code in [200, 201]:
            return result.json()

        _log_github_error(
            "push",
            owner,
            repo,
            path,
            f"status={result.status_code} response={result.text[:300]}",
        )
        return None

    except Exception:
        _log_github_error("push", owner, repo, path, "unexpected exception while pushing", exc_info=True)
        return None


def get_file_from_github(token, owner, repo, path, password, branch="main"):

    try:
        try:
            decrypted_token = denc(token, password)
        except ValueError:
            _log_github_error("fetch", owner, repo, path, "master password mismatch or token decryption failed")
            return (False, "Incorrect master password.", None)
        except Exception:
            _log_github_error("fetch", owner, repo, path, "unexpected token decryption error", exc_info=True)
            return (False, "Something went wrong while contacting GitHub. Please try again.", None)

        headers = {
            "Authorization": f"token {decrypted_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"

        response = requests.get(url, headers=headers, params={"ref": branch})

        if response.status_code == 200:
            content_b64 = response.json().get('content')
            encrypted_content = base64.b64decode(content_b64).decode()
            return (True, "File fetched successfully.", encrypted_content)

        elif response.status_code == 401:
            _log_github_error("fetch", owner, repo, path, f"GitHub token rejected status={response.status_code} message={response.text[:300]}")
            return (False, "GitHub token is invalid or expired.", None)
        elif response.status_code == 404:
            _log_github_error("fetch", owner, repo, path, f"GitHub file/repo not found status={response.status_code} message={response.text[:300]}")
            return (False, "Repository, file path, or access is incorrect.", None)
        else:
            error_details = response.json().get('message', response.text)
            _log_github_error("fetch", owner, repo, path, f"status={response.status_code} message={error_details}")
            return (False, "Something went wrong while contacting GitHub. Please try again.", None)

    except requests.exceptions.RequestException:
        _log_github_error("fetch", owner, repo, path, "network error while contacting GitHub", exc_info=True)
        return (False, "Connection to GitHub failed. Please try again.", None)
    except Exception:
        _log_github_error("fetch", owner, repo, path, "unexpected exception while fetching GitHub content", exc_info=True)
        return (False, "Something went wrong while contacting GitHub. Please try again.", None)

def convertToString(lst):
    return json.dumps(lst)

def convertFromString(s):
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return []



def enc(data, password):

    data = data.encode()

    # Derive key
    salt = get_random_bytes(16)
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
    raw = base64.b64decode(data)  # decode before splitting

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


        encrypted_content = request.POST.get('encrypted_content')
        if encrypted_content:
            push_to_github(_token, _username, _repo, _path, _mas_password, encrypted_content)

        return redirect("../")

    return redirect("../")
