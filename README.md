SGMS (Simple GMAIL Mail Sender)
===============================

Simple tool to send email via a GMAIL account. It uses the GMAIL API.

The tool is expected to run from a host with a web browser to run the OAuth2 flow.

Setup GMAIL side
----------------

At https://developers.google.com/gmail/api/quickstart/python

1. Enable the GMAIL API then:
2. Enter project name: Perso-Mailer
3. Configure your OAuth client: Desktop app
4. Click on API Console link

Via the console link or at https://console.cloud.google.com/apis/credentials

1. Make sure to have selected: Perso-Mailer project
2. Click on OAuth client
3. Download JSON, and save the file to ~/.sgms/credentials.json.

Install sgms into your user account
-----------------------------------

```
pip install --user -r requirements.txt
python setup.py install --user
```

Run the OAuth2 process to retreive the token
--------------------------------------------

```
sgms --auth-only
```

Create a message in YAML format
-------------------------------

Create a file message.yaml with content such as

```YAML
---
to: <mon-gazier>@mail.com
subject: Hey my Friend
body: I wish you a very good day !
```

Or see example/message.yaml as en example.

Send an email
-------------

The email to send must be provided as a YAML payload.

```
sgms --from-email user@gmail.com --yaml-message mail.yaml
```
