# Automatic deployment of shiny apps on vps using webhooks

For a long time, I've been hosting shiny apps on a vps. These apps rely on data that is updated weekly. The usual process was then to gather the new data on my laptop, commit in my local repo, push to the remote, ssh to the vps and pull the changes there.

A cumbersome process that can be simplified a lot by making use of webhooks that are offered by Github or Bitbucket. I could find some blogposts that show how to do this with Github Actions, but not using the more lightweight webhooks approach (no Docker needed, no private ssh keys stored on Github, etc.). Note that in my case, the remote is hosted on Bitbucket (historical reasons) and as such Github Action was not even a viable option.

However, setting this up turned out more error prone than I anticipated. I share this post to help others trying to achieve the same.

## Install shiny-server and set up apache/nginx
First of all, you need to install shiny-server on your vps. There are numerous tutorials online, so I will not delve deeper into this in this post. Depending on your preference, you might have chosen Apache or Nginx as your webserver. I have Apache, but the approach should be very similar for Nginx.

In my case, I have a regular website running on `mydomain.com`. I've created a subdomain specifically for the shiny apps on `shiny.mydomain.com`. This implies that in my Apache config, I redirect all traffic to `shiny.mydomain.com` to `localhost:3838`. The shiny apps are stored in the usual `/srv/shiny-server` folder, together with the local git repository of each app. Nothing special here, this is just a fairly typical shiny-server setup.

## Create webhook on Bitbucket (or Github)
The goal is now to have the server automatically pull changes (i.e. new commits) from the remote repo on Bitbucket. First step is then to [create a webhook for the repo](https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/ "Bitbucket Docs"). For the url, I've chosen something like: `shiny.mydomain.com/mywebhooks/myscript`. Make sure you make use of a strong secret (let Bitbucket suggest one) and do not skip certificate verification. As for the triggers, I've only selected the 'repository push'.

## Set-up the vps to allow webhook triggers
Now, on the vps we have to update the Apache (or Nginx) config because all traffic to the shiny subdomain is redirected to shiny-server, but for the webhook, we want the webserver to take care of the request, not shiny-server. The following lines achieve this (make sure these are added to the virtual hosts related to your shiny subdomain):

```
<Location "/mywebhooks">
    SetHandler cgi-script
    AddHandler cgi-script .cgi .py
    Options +ExecCGI
</Location>
ScriptAlias "/mywebhooks/" "/someparentfolder/mycgidir/"

ProxyPass /mywebhooks !
ProxyPass / http://localhost:3838/ 
ProxyPassReverse / http://localhost:3838/
```

The location blok makes sure that requests to the webhook url will run cgi scripts. For the `AddHandler` line, make sure the file extension of your listner script (see below) is listed here (`.py` in my case).

The `ScriptAlias` line links the mywebhooks url to a physical directory on the vps. The `ProxyPass` lines make sure that all requests to mywebhooks are *not* forwarded to the shiny-server on the localhost, but all other requests are.

## Test the current set-up
At this point you can do an intermediate test by creating a small cgi script that returns some text when the webhook is triggered, which can be done by simply visiting the url of the webhook in your browser. Note that your script should adhere the cgi format, so it has to return minimal headers to be executed properly. Also, the owner of the script and the directory of the cgi scripts should be the process that is trying to execute the script (most likeliy that will be apache/nginx). Check your cgi log to see the userid of the user that is trying to run the script if in doubt. And of course, do not forget to make the script executable (`chmod +x myscript.py`). Here is an example script:

```python
#!/usr/bin/env python3

# Print necessary headers
print("Content-type: text/html")
print()

# HTML content to be displayed in the browser
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CGI Script Response</title>
</head>
<body>
    <h1>Hello from CGI Script!</h1>
    <p>This is a simple CGI script written in Python.</p>
</body>
</html>
"""

# Print the HTML content to the browser
print(html_content)
```

## Adjust the testscript to perform a git pull
Once this is working, the testscript above can be adjusted so that instead of printing HTML, it now pulls the changes from the remote. Note that it is necessary that the process that is executing the script (again, this will most likely be apache/nginx) has the required (write) permissions for the repository and directory it resides in on the vps. Also, you'll have to make sure that the user executing the script on the vps can pull without providing a password. This can be done by setting up the usual ssh public/private key pair and add the public key to your online repo. Again, see the [Bitbucket docs](https://support.atlassian.com/bitbucket-cloud/docs/set-up-personal-ssh-keys-on-linux/ "Bitbucket Docs").

```python
#!/usr/bin/env python3

# Print necessary headers
print("Content-type: text/html")
print()

# Define the path to the Git repository
repository_path = "/path/to/your/repository"

# Pull the Git repository
pull_command = f"git -C {repository_path} pull origin master"
subprocess.run(pull_command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
```

## Add security
The final step is then to make sure that only Bitbucket (or Github) is authorized to trigger the webhook. For this, we make use of the secret that was defined on Bitbucket when making the webhook. In the `X-Hub-Signature` of the post request that Bitbucket will send to the webhook every time a new push is made to the repo, a HMAC signature will be created. In your code that handles webhook deliveries, you should calculate a HMAC of the body using your secret token and compare your result with that signature. Only when there is a match, the repo should be pulled. More detailed info via [Bitbucket Docs](https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/ "Bitbucket Docs").

```python
#!/usr/bin/env python3
import os
import sys
import hashlib
import hmac

# Read the message from stdin
message = sys.stdin.read()

# Extract the signature from the environment variable
given_signature = os.environ.get('HTTP_X_HUB_SIGNATURE', '').split('=')[-1]

# Define the secret (replace with your actual secret)
secret = b"mystrongsecret012345"

# Calculate the HMAC-SHA256 signature
hash_object = hmac.new(secret, message.encode("utf-8"), hashlib.sha256)
calculated_signature = "sha256=" + hash_object.hexdigest()

# Print the required headers
print("Status: 204 No Content")
print("Content-type: text/plain")
print()

# Compare the signatures
if not hmac.compare_digest(calculated_signature, given_signature):
    #print("Signatures do not match")
    #print(f"Expected signature: {calculated_signature}")
    #print(f"Actual signature: {given_signature}")
else:
    #print("Signatures match")
    # If signatures match, perform git pull or any other desired action
    os.system("cd /path/to/your/repository/ && git pull")
```

You can test this setup by pushing a new commit to the remote repo on Bitbucket and doublecheck that the vps automatically pulled in this change. Note that it is recommended not to store your secret directly in the cgi script, but to let the script access the secret in a different location.

If this tutorial was helpful to you, please star this repo, thanks!

