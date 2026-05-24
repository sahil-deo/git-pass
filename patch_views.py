import re

with open('passmanager/views.py', 'r') as f:
    content = f.read()

# 1. Modify push_to_github
content = content.replace('encoded_content = base64.b64encode(enc(new_content, password).encode()).decode()', 
                          'encoded_content = base64.b64encode(new_content.encode()).decode()')

# 2. Modify get_file_from_github
old_denc_block = """            # Step 3: Decrypt the file content itself. This could also fail.
            try:
                decrypted_content = ""
                if(encrypted_content != "\\n"):
                    print("size:", len(encrypted_content))
                    decrypted_content = denc(encrypted_content, password)
                return (True, "File fetched successfully.", decrypted_content)
            except ValueError:
                return (False, "Could not decrypt the file content. The Master Password may be incorrect for this file.", None)"""

new_denc_block = """            return (True, "File fetched successfully.", encrypted_content)"""
content = content.replace(old_denc_block, new_denc_block)

# 3. Modify passwords view
old_pw_block = """        content = [[]]
        if old_content != None: 
            content = convertFromString(old_content)

        
        context = {'content': content}
        
    except(): 
        
        context = {'content', [[]]}"""

new_pw_block = """        content = ""
        if old_content != None: 
            content = old_content
        context = {'content': content, 'mas_password': _mas_password}
    except: 
        context = {'content': "", 'mas_password': _mas_password}"""
content = content.replace(old_pw_block, new_pw_block)

# 4. Modify newpassword view
old_newpw_block = """        _name = request.POST.get('name')
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
    
    return render(request, 'new.html')"""

new_newpw_block = """        _mas_password = request.session.get('mas_password')
        _token = request.COOKIES.get('_token')
        _repo = request.COOKIES.get('_repo')
        _username = request.COOKIES.get('_username')
        _path = request.COOKIES.get('_path')
        
        encrypted_content = request.POST.get('encrypted_content')
        if encrypted_content:
            push_to_github(_token, _username, _repo, _path, _mas_password, encrypted_content)
            return redirect('/passwords/')
    
    _mas_password = request.session.get('mas_password')
    _token = request.COOKIES.get('_token')
    _repo = request.COOKIES.get('_repo')
    _username = request.COOKIES.get('_username')
    _path = request.COOKIES.get('_path')
    check, error, old_content = get_file_from_github(_token, _username, _repo, _path, _mas_password)
    context = {'encrypted_content': old_content if old_content else "", 'mas_password': _mas_password}
    return render(request, 'new.html', context)"""
content = content.replace(old_newpw_block, new_newpw_block)

# 5. Modify update view
old_update_block = """        if request.POST.get('action') == "Delete":
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
        return redirect("../")"""

new_update_block = """        encrypted_content = request.POST.get('encrypted_content')
        if encrypted_content:
            push_to_github(_token, _username, _repo, _path, _mas_password, encrypted_content)
        return redirect("../")"""
content = content.replace(old_update_block, new_update_block)

# 6. Modify delete view
old_delete_block = """        a, b, old_content = get_file_from_github(_token, _username, _repo, _path, _mas_password)        
        old_content = convertFromString(old_content)
        del old_content[id]

        push_to_github(_token, _username, _repo, _path, _mas_password,convertToString(sortList(old_content)))
        return redirect("../")"""

new_delete_block = """        encrypted_content = request.POST.get('encrypted_content')
        if encrypted_content:
            push_to_github(_token, _username, _repo, _path, _mas_password, encrypted_content)
        return redirect("../")"""
content = content.replace(old_delete_block, new_delete_block)

with open('passmanager/views.py', 'w') as f:
    f.write(content)

