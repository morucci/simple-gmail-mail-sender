# Copyright (c) <2020> <fboucher@redhat.com>

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import pickle
import yaml
import base64
import logging
import argparse
from pathlib import Path

from typing import Union, Any, Dict, List, Literal, TypedDict

from googleapiclient.discovery import build, Resource
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from email.mime.text import MIMEText

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
WORKDIR = Path("~/.sgms/").expanduser()
TOKEN = WORKDIR / Path("token.pickle")
CREDS = WORKDIR / Path("credentials.json")


SendStatus = Literal["SENT", "SKIPPED", "FAILURE"]


def create_workspace(workdir: Path) -> Union[Path, None]:
    logging.info("Ensure %s exists" % workdir)
    if not workdir.exists():
        workdir.mkdir(mode=0o700)
        return workdir
    else:
        return None


def auth(token: Path, credentials: Path) -> Credentials:
    creds = None

    if token.exists():
        logging.info("Reading token file %s" % token)
        creds = pickle.loads(token.read_bytes())
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            logging.info("Refresh token ...")
            creds.refresh(Request())
        else:
            logging.info("Running auth flow using %s" % credentials)
            flow = InstalledAppFlow.from_client_secrets_file(str(credentials), SCOPES)
            creds = flow.run_local_server(port=0)
        logging.info("Writting token file %s" % token)
        token.touch(mode=0o600, exist_ok=True)
        token.write_bytes(pickle.dumps(creds))
    return creds


class Message(TypedDict):
    sender: str
    to: str
    subject: str
    body: str


class RawMessage(TypedDict):
    raw: str


def load_yaml_message(yaml_data: Dict[str, str], sender: str) -> Message:
    return Message(
        sender=sender,
        to=yaml_data["to"],
        subject=yaml_data["subject"],
        body=yaml_data["body"],
    )


def load_message_from_file(path: Path, sender: str) -> Union[None, Message]:
    try:
        logging.info("Reading yaml message %s" % path)
        return load_yaml_message(
            yaml_data=yaml.safe_load(path.read_bytes()), sender=sender
        )
    except Exception:
        logging.exception("Unable to load message from file %s" % path)
        return None


def create_message(message: Message) -> RawMessage:
    d = MIMEText(message["body"])
    d["to"] = message["to"]
    d["from"] = message["sender"]
    d["subject"] = message["subject"]

    return RawMessage(raw=base64.urlsafe_b64encode(d.as_bytes()).decode())


def send_message(service: Resource, message: Message) -> Union[Any, None]:
    raw_message = create_message(message)
    try:
        ret = (
            service.users()
            .messages()
            .send(userId=message["sender"], body=raw_message)
            .execute()
        )
        logging.info("Sent message to %s (Id: %s)" % (message["to"], ret["id"]))
        return ret
    except Exception:
        logging.exception("Unable to send message to %s" + message["to"])
    return None


def load_and_send(service: Resource, yaml_message: Path, from_email: str) -> SendStatus:
    if yaml_message.suffix in [".yml", ".yaml"]:
        if yaml_message.name.startswith("_sent_"):
            # Short circuit as already sent
            return "SKIPPED"
        m = load_message_from_file(Path(yaml_message), from_email)
        if m:
            status = send_message(service, m)
            return "SENT"
    else:
        logging.info("Skipping %s due to invalid file extension")
    return "FAILURE"


def process_directory(
    service: Resource, directory: Path, from_email: str
) -> List[SendStatus]:
    ret = []
    if directory.exists():
        logging.info("Reading %s ..." % directory)
        paths = directory.iterdir()
        for path in paths:
            if path.suffix in [".yml", ".yaml"]:
                status = load_and_send(service, path, from_email)
                if status == "SENT":
                    path.rename(path.parent / Path("_sent_" + str(path.name)))
                ret.append(status)
    else:
        logging.info("Unable to find %s" % path)
    return ret


def main() -> None:

    parser = argparse.ArgumentParser(prog="sgms")
    parser.add_argument("--loglevel", help="logging level", default="INFO")
    parser.add_argument(
        "--from-email", help="The from recipient address", required=False
    )
    parser.add_argument("--yaml-message", help="The message in YAML", required=False)
    parser.add_argument(
        "--from-directory",
        help="The directory to read YAML message from",
        required=False,
    )
    parser.add_argument(
        "--auth-only",
        help="Only perform the auth flow to get the token",
        action="store_true",
    )

    args = parser.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.loglevel.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.ERROR)

    create_workspace(workdir=WORKDIR)

    try:
        creds = auth(token=TOKEN, credentials=CREDS)
    except Exception:
        logging.info("Unable to authenticate")
        sys.exit(-1)
    if args.auth_only:
        sys.exit(0)

    if not args.from_email:
        logging.info("Please provide --from-email")

    service: Resource = build("gmail", "v1", credentials=creds)

    if args.yaml_message:
        if not load_and_send(service, Path(args.yaml_message), args.from_email):
            sys.exit(-1)
    elif args.from_directory:
        directory = Path(args.from_directory).expanduser()
        status = process_directory(service, directory, args.from_email)
        sent = len(list(filter(lambda s: s == "SENT", status)))
        skipped = len(list(filter(lambda s: s == "SKIPPED", status)))
        failed = len(list(filter(lambda s: s == "FAILURE", status)))
        logging.info("Sent: %s, Skipped: %s, failed: %s" % (sent, skipped, failed))
        if failed:
            sys.exit(-1)
    else:
        logging.info(
            "No action performed. Did you forget to pass --from-email or --from-directory"
        )
