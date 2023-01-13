"""
Library which enables functionality with Ansible-Semaphore

Semaphore is an open-source fork of what was Ansible Tower, 
a way to automate the disposition of Ansible Playbooks.
Find Semaphore here: https://www.ansible-semaphore.com/
This module works with the API included with Semaphore.

This module requires you to possess both a URL to a Semaphore 
installation, and all required credentials you might need.

This module requires requests, urllib3, and urllib
--------------
After importing as a module, instantiate a SemaphoreClient 
object:
sc = SemaphoreClient(host)

:Version: 1.0 January 2023
"""

import requests
import getpass
import urllib3
from urllib import parse

class SemaphoreClient(object):
    """A SemaphoreClient Object, which contains all the API functionality as methods.

    :param host: The URL to the Semaphore instance
    :type host: str
    :param verify: Should the SSL certificate, if there is one, be verified?
        (default is True)
    :type verify: bool
    """
    def __init__(self, host: str, verify=True) -> None:
        self.user = input('Semaphore Username: ')
        self.passwd = getpass.getpass(prompt='Semaphore Password: ')
        self.host = f'https://{host}/api'
        self.verify = verify
        self.cookie_jar = None
        if not self.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def login(self) -> bool:
        """Logs you in to the Semaphore server.
        
        This should be performed first, otherwise, all other methods will fail.
        :returns: True if the login was successful, false otherwise (or an exception)
        :rtype: bool
        """
        data = {
            'auth': self.user,
            'password': self.passwd.replace('\\','\\\\')
        }
        r = requests.post(self.host+'/auth/login', json=data, verify=self.verify)
        self.cookie_jar = r.cookies
        if r.status_code == 204:
            return True
        elif r.status_code == 400 or r.status_code == 401:
            return False
        r.raise_for_status()
    
    def logout(self) -> bool:
        """Logs you out of the Semaphore server.

        This is technically optional to perform, however, it will destroy your 
        session cookie, requiring re-authentication with the login method.
        :returns: True if the logout was successful, false otherwise.
        :rtype: bool
        """
        r = requests.post(self.host+'/auth/logout', verify=self.verify, cookies=self.cookie_jar)
        if r.status_code == 204:
            self.cookie_jar = None
            return True
        else:
            return False
    
    def tokens(self) -> list:
        """Lists the API tokens associated with the current user. 

        API tokens are an additional way to authenticate with the API.
        They are currently not supported by this module as an alternative 
        login method; instead, this module relies on storing the cookie 
        created by the login method.
        :returns: A list of tokens (serialized from JSON)
        :rtype: list
        """
        r = requests.get(self.host+'/user/tokens', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def create_token(self) -> dict:
        """Creates an API token for a given user - you must be logged in first.

        :returns: An object (dictionary) with details about the created token.
        :rtype: dict
        """
        r = requests.post(self.host+'/user/tokens', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def delete_token(self, token: str) -> bool:
        """Invalidates an API token passed as an argument.

        :param token: The API token to invalidate
        :type token: str
        :returns: True if the token was invalidated, false otherwise.
        :rtype: bool
        """
        token = parse.quote(token)
        r = requests.delete(self.host+'/user/tokens/'+token, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def project(self, id: int) -> dict:
        id = str(id)
        r = requests.get(self.host+'/project/'+id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def update_project(self, id: int, data: dict) -> bool:
        id = str(id)
        r = requests.put(self.host+'/project/'+id, json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def delete_project(self, id: int) -> bool:
        id = str(id)
        r = requests.delete(self.host+'/project/'+id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
        
    def events(self, id: int) -> list:
        id = str(id)
        r = requests.get(self.host+'/project/'+id+'/events', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def users(self, id: int, sort: str, order: str) -> list:
        id = str(id)
        if sort not in ['name', 'username', 'email', 'admin']:
            raise Exception('Sort must be either name, username, email, or admin')
        if order not in ['asc', 'desc']:
            raise Exception('Order must be either asc or desc')
        payload = {
            'sort': sort,
            'order': order
        }
        r = requests.get(self.host+'/project/'+id+'/users', params=payload, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def link_user(self, id: int, user_id: int, admin: bool) -> bool:
        id = str(id)
        data = {
            'user_id': user_id,
            'admin': admin
        }
        r = requests.post(self.host+'/project/'+id+'/users', json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
        
    def remove_user(self, id: int, user_id: int) -> bool:
        id = str(id)
        user_id = str(user_id)
        r = requests.delete(self.host+'/project/'+id+'/users/'+user_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def make_admin(self, id: int, user_id: int) -> bool:
        id = str(id)
        user_id = str(user_id)
        r = requests.post(self.host+'/project/'+id+'/users/'+user_id+'/admin', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def revoke_admin(self, id: int, user_id: int) -> bool:
        id = str(id)
        user_id = str(user_id)
        r = requests.delete(self.host+'/project/'+id+'/users/'+user_id+'/admin', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def keys(self, id: int, key_type: str, sort: str, order: str) -> list:
        id = str(id)
        if key_type not in ['none', 'ssh', 'login_password']:
            raise Exception('key_type must be either none, ssh, or login_password')
        if sort not in ['name', 'type']:
            raise Exception('sort must be either name or type')
        if order not in ['asc', 'desc']:
            raise Exception('order must be either asc or desc')
        payload = {
            'Key type': key_type,
            'sort': sort,
            'order': order
        }
        r = requests.get(self.host+'/project/'+id+'/keys', params=payload, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def add_key(self, id: int, name: str, type_s: str, login_password = {}, ssh_key = {}) -> bool:
        if type_s not in ['none', 'ssh', 'login_password']:
            raise Exception('type must be either none, ssh, or login_password')
        data = {
            'login_password': login_password,
            'ssh': ssh_key,
            'name': name,
            'type': type_s,
            'project_id': id
        }
        id = str(id)
        r = requests.post(self.host+'/project/'+id+'/keys', json=data, verify=self.verify, cookies=self.cookie_jar)
        if r.status_code == 204:
            return True
        elif r.status_code == 400:
            return False
        else:
            r.raise_for_status()
            return False
    
    def update_key(self, id: int, key_id: int, name: str, type_s: str,  login_password = {}, ssh_key = {}) -> bool:
        if type_s not in ['none', 'ssh', 'login_password']:
            raise Exception('type must be either none, ssh, or login_password')
        if login_password == {}:
            login_password = {'login': '', 'password': ''}
        if ssh_key == {}:
            ssh_key = {'login': '', 'passphrase': '', 'private_key': ''}
        data = {
            'login_password': login_password,
            'ssh': ssh_key,
            'name': name,
            'override_secret': True,
            'type': type_s,
            'project_id': id
        }
        id = str(id)
        key_id = str(key_id)
        r = requests.put(self.host+'/project/'+id+'/keys/'+key_id, json=data, verify=self.verify, cookies=self.cookie_jar)
        if r.status_code == 204:
            return True
        elif r.status_code == 400:
            return False
        else:
            r.raise_for_status()
            return False
    
    def delete_key(self, id: int, key_id: int) -> bool:
        id = str(id)
        key_id = str(key_id)
        r = requests.delete(self.host+'/project/'+id+'/keys/'+key_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def repositories(self, id: int, sort: str, order: str) -> list:
        id = str(id)
        if sort not in ['name', 'git_url', 'ssh_key']:
            raise Exception('sort must be either name, git_url, or ssh_key')
        if order not in ['asc', 'desc']:
            raise Exception('order must be either asc or desc')
        payload = {
            'sort': sort,
            'order': order
        }
        r = requests.get(self.host+'/project/'+id+'/repositories', params=payload, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def add_repository(self, id: int, name: str, project_id: int, git_url: str, git_branch: str, ssh_key_id: int) -> bool:
        id = str(id)
        data = {
            'name': name,
            'project_id': project_id,
            'git_url': git_url,
            'git_branch': git_branch,
            'ssh_key_id': ssh_key_id
        }
        r = requests.post(self.host+'/project/'+id+'/repositories', json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def remove_repository(self, id: int, repo_id: int) -> bool:
        id = str(id)
        repo_id = str(repo_id)
        r = requests.delete(self.host+'/project/'+id+'/repositories/'+repo_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def inventory(self, id: int, sort: str, order: str) -> list:
        id = str(id)
        if sort not in ['name', 'type']:
            raise Exception('sort must be either name or type')
        if order not in ['asc', 'desc']:
            raise Exception('order must be either asc or desc')
        payload = {
            'sort': sort,
            'order': order
        }
        r = requests.get(self.host+'/project/'+id+'/inventory', params=payload, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def create_inventory(self, id: int, name: str, project_id: int, inventory: str, ssh_key_id: int, become_key_id: int, type_s: str) -> dict:
        id = str(id)
        if type_s not in ['static', 'file']:
            raise Exception('type must be either static or file')
        data = {
            'name': name,
            'project_id': project_id,
            'inventory': inventory,
            'ssh_key_id': ssh_key_id,
            'become_key_id': become_key_id,
            'type': type_s
        }
        r = requests.post(self.host+'/project/'+id+'/inventory', json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()

    def update_inventory(self, id: int, inventory_id: int, name: str, project_id: int, inventory: str, ssh_key_id: int, become_key_id: int, type_s: str) -> bool:
        id = str(id)
        inventory_id = str(inventory_id)
        if type_s not in ['static', 'file']:
            raise Exception('type must be either static or file')
        data = {
            'name': name,
            'project_id': project_id,
            'inventory': inventory,
            'ssh_key_id': ssh_key_id,
            'become_key_id': become_key_id,
            'type': type_s
        }
        r = requests.put(self.host+'/project/'+id+'/inventory/'+inventory_id, json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def delete_inventory(self, id: int, inventory_id: int) -> bool:
        id = str(id)
        inventory_id = str(inventory_id)
        r = requests.delete(self.host+'/project/'+id+'/inventory/'+inventory_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204: 
            return True
        else:
            return False
    
    def environment(self, id: int, sort: str, order: str) -> list:
        id = str(id)
        payload = {
            'sort': sort,
            'order': order
        }
        r = requests.get(self.host+'/project/'+id+'/environment', params=payload, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def add_environment(self, id: int, name: str, project_id: int, password: str, json: str) -> bool:
        id = str(id)
        data = {
            'name': name,
            'project_id': project_id,
            'password': password,
            'json': json
        }
        r = requests.post(self.host+'/project/'+id+'/environment', json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def update_environment(self, id: int, environment_id: int, name: str, project_id: int, password: str, json: str) -> bool:
        id = str(id)
        environment_id = str(environment_id)
        data = {
            'name': name,
            'project_id': project_id,
            'password': password,
            'json': json
        }
        r = requests.put(self.host+'/project/'+id+'/environment/'+environment_id, json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def remove_environment(self, id: int, environment_id: int) -> bool:
        id = str(id)
        environment_id = str(environment_id)
        r = requests.delete(self.host+'/project/'+id+'/environment/'+environment_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def templates(self, id: int, sort: str, order: str) -> list:
        id = str(id)
        if sort not in ['alias', 'playbook', 'ssh_key', 'inventory', 'environment', 'repository']:
            raise Exception('sort must be either alias, playbook, ssh_key, inventory, environment, repository')
        if order not in ['asc', 'desc']:
            raise Exception('order must be either asc or desc')
        payload = {
            'sort': sort,
            'order': order
        }
        r = requests.get(self.host+'/project/'+id+'/templates', params=payload, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def create_template(self, id: int, template_data = {}) -> dict:
        id = str(id)
        r = requests.post(self.host+'/project/'+id+'/templates', json=template_data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def get_template(self, id: int, template_id: int) -> dict:
        id = str(id)
        template_id = str(template_id)
        r = requests.get(self.host+'/project/'+id+'/templates/'+template_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def update_template(self, id: int, template_id: int, project_id: int, inventory_id: int, repo_id: int, environment_id: int, view_id: int, alias: str, playbook: str, arguments: str, description: str, override_args: bool) -> bool:
        id = str(id)
        template_id = str(template_id)
        data = {
            'project_id': project_id,
            'inventory_id': inventory_id,
            'repository_id': repo_id,
            'environment_id': environment_id,
            'view_id': view_id,
            'alias': alias,
            'playbook': playbook,
            'arguments': arguments,
            'description': description,
            'override_args': override_args
        }
        r = requests.put(self.host+'/project/'+id+'/templates/'+template_id, json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def delete_template(self, id: int, template_id: int) -> bool:
        id = str(id)
        template_id = str(template_id)
        r = requests.delete(self.host+'/project/'+id+'/templates/'+template_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def views(self, id: int) -> list:
        id = str(id)
        r = requests.get(self.host+'/project/'+id+'/views', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def create_view(self, id: int, title: str, project_id: int, position: int) -> dict:
        id = str(id)
        data = {
            'title': title,
            'project_id': project_id,
            'position': position
        }
        r = requests.post(self.host+'/project/'+id+'/views', json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def view(self, id: int, view_id: int) -> dict:
        id = str(id)
        view_id = str(view_id)
        r = requests.get(self.host+'/project/'+id+'/views/'+view_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def update_view(self, id: int, view_id: int, title: str, project_id: int, position: int) -> bool:
        id = str(id)
        view_id = str(view_id)
        data = {
            'title': title,
            'project_id': project_id,
            'position': position
        }
        r = requests.put(self.host+'/project/'+id+'/views/'+view_id, json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def delete_view(self, id: int, view_id: int) -> bool:
        id = str(id)
        view_id = str(view_id)
        r = requests.delete(self.host+'/project/'+id+'/views/'+view_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def tasks(self, id: int) -> list:
        id = str(id)
        r = requests.get(self.host+'/project/'+id+'/tasks', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def start_task(self, id: int, template_id: int, debug: bool, dry_run: bool, playbook: str, environment: str) -> dict:
        id = str(id)
        data = {
            'template_id': template_id,
            'debug': debug,
            'dry_run': dry_run,
            'playbook': playbook,
            'environment': environment
        }
        r = requests.post(self.host+'/project/'+id+'/tasks', json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def last_200_tasks(self, id: int) -> list:
        id = str(id)
        r = requests.get(self.host+'/project/'+id+'/tasks/last', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def single_task(self, id: int, task_id: int) -> dict:
        id = str(id)
        task_id = str(task_id)
        r = requests.get(self.host+'/project/'+id+'/tasks/'+task_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def delete_task(self, id: int, task_id: int) -> bool:
        id = str(id)
        task_id = str(task_id)
        r = requests.delete(self.host+'/project/'+id+'/tasks/'+task_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def task_output(self, id: int, task_id: int) -> list:
        id = str(id)
        task_id = str(task_id)
        r = requests.get(self.host+'/project/'+id+'/tasks/'+task_id+'/output', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def user(self) -> dict:
        r = requests.get(self.host+'/user/', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def user_tokens(self) -> list:
        r = requests.get(self.host+'/user/tokens', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def create_token(self) -> list:
        r = requests.post(self.host+'/user/tokens', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def delete_token(self, token: str) -> bool:
        token = parse.quote(token)
        r = requests.delete(self.host+'/user/tokens/'+token, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def users(self) -> list:
        r = requests.get(self.host+'/users', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def create_user(self, name: str, username: str, email: str, alert: bool, admin: bool) -> dict:
        data = {
            'name': name,
            'username': username,
            'email': email,
            'alert': alert,
            'admin': admin
        }
        r = requests.post(self.host+'/users', json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def user_profile(self, user_id: int) -> dict:
        user_id = str(user_id)
        r = requests.get(self.host+'/users/'+user_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def update_user(self, user_id: int, name: str, username: str, email: str, alert: bool, admin: bool) -> bool:
        user_id = str(user_id)
        data = {
            'name': name,
            'username': username,
            'email': email,
            'alert': alert,
            'admin': admin
        }
        r = requests.put(self.host+'/users/'+user_id, json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def delete_user(self, user_id: int) -> bool:
        user_id = str(user_id)
        r = requests.delete(self.host+'/users/'+user_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def update_password(self, user_id: int, password: str) -> bool:
        user_id = str(user_id)
        data = {
            'password': password
        }
        r = requests.post(self.host+'/users/'+user_id+'/password', json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def ping(self) -> str:
        r = requests.get(self.host+'/ping', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.text
    
    def info(self) -> dict:
        r = requests.get(self.host+'/info', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def events(self) -> list:
        r = requests.get(self.host+'/events', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def last_200_events(self) -> list:
        r = requests.get(self.host+'/events/last', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def projects(self) -> list:
        r = requests.get(self.host+'/projects', verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def create_project(self, name: str, alert: bool) -> bool:
        data = {
            'name': name,
            'alert': alert
        }
        r = requests.post(self.host+'/projects', json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 201:
            return True
        else:
            return False
    
    def schedule(self, project_id: int, schedule_id: int) -> dict:
        project_id = str(project_id)
        schedule_id = str(schedule_id)
        r = requests.get(self.host+'/project/'+project_id+'/schedules/'+schedule_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
    def delete_schedule(self, project_id: int, schedule_id: int) -> bool:
        project_id = str(project_id)
        schedule_id = str(schedule_id)
        r = requests.delete(self.host+'/project/'+project_id+'/schedules/'+schedule_id, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def update_schedule(self, project_id: int, schedule_id: int, id: int, cron_format: str, schedule_project_id: int, template_id: int) -> bool:
        project_id = str(project_id)
        schedule_id = str(schedule_id)
        data = {
            'id': id,
            'cron_format': cron_format,
            'project_id': schedule_project_id,
            'template_id': template_id
        }
        r = requests.put(self.host+'/project/'+project_id+'/schedules/'+schedule_id, json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        if r.status_code == 204:
            return True
        else:
            return False
    
    def create_schedule(self, project_id: int, id: int, cron_format: str, schedule_project_id: int, template_id: int) -> dict:
        project_id = str(project_id)
        data = {
            'id': id,
            'cron_format': cron_format,
            'project_id': schedule_project_id,
            'template_id': template_id
        }
        r = requests.post(self.host+'/project/'+project_id+'/schedules', json=data, verify=self.verify, cookies=self.cookie_jar)
        r.raise_for_status()
        return r.json()
    
