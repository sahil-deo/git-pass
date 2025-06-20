from django.shortcuts import render
from django.http import HttpResponse
from django.template import loader
import base64
import json
import requests

# Create your views here.

def passwords(request):
    return HttpResponse("Cyber World")


def newpassword(request):

    if request.method == 'POST':
        content = request.POST.get('name') + ":" + request.POST.get('uname') + ":" + request.POST.get('password')
        push_to_github(request.POST.get('token'), request.POST.get('username'), request.POST.get('repo'), request.POST.get('path'), content)

    # template = loader.get_template('new.html')
    # return HttpResponse(template.render(), request)

    return render(request, 'new.html')



def home(request):
    template = loader.get_template('home.html')
    return HttpResponse(template.render())



def push_to_github(token, owner, repo, path, new_content, commit_msg="Update via token", branch="main"):
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
    encoded_content = base64.b64encode(new_content.encode()).decode()
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
