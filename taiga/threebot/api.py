from uuid import uuid4
import urllib
import json
import nacl.encoding
import nacl.signing
import requests
import base64
from django.conf import settings
from django.shortcuts import redirect
from nacl.public import Box

from taiga.base.status import HTTP_400_BAD_REQUEST
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext as _
from django.contrib.auth import login
from django.http import JsonResponse

from taiga.projects.models import Membership
from taiga.users.serializers import UserAdminSerializer
from taiga.auth.tokens import get_token_for_user
from taiga.base import response

def check_registered(username, email):
    user_model = get_user_model()
    res = user_model.objects.filter(username=username)
    if res:
        return res[0]

    res = user_model.objects.filter(email=email)
    if res:
        return res[0]


def get_threebot_url(req):
    private_key = nacl.signing.SigningKey(settings.PRIVATE_KEY, encoder=nacl.encoding.Base64Encoder)
    public_key = private_key.verify_key

    state = str(uuid4()).replace("-", "")
    req.session["state"] = state

    params = {
        "state": state,
        "appid": settings.SITES["front"]["domain"],
        "scope": '{"user": true, "email": true}',
        "redirecturl": "/threebot",
        "publickey": public_key.to_curve25519_public_key().encode(encoder=nacl.encoding.Base64Encoder),
    }

    return JsonResponse({"url": "{0}?{1}".format("https://login.threefold.me", urllib.parse.urlencode(params))})

def callback(req):
    
    signedhash = req.GET.get("signedhash")
    username = req.GET.get("username")
    data = req.GET.get("data")

    if signedhash is None or username is None or data is None:
        raise HTTP_400_BAD_REQUEST()
    data = json.loads(data)

    res = requests.get(
        "https://login.threefold.me/api/users/{0}".format(username), {"Content-Type": "application/json"}
    )
    if res.status_code != 200:
        raise HTTP_400_BAD_REQUEST("Error getting user pub key")

    user_pub_key = nacl.signing.VerifyKey(res.json()["publicKey"], encoder=nacl.encoding.Base64Encoder)
    nonce = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])
    private_key = nacl.signing.SigningKey(settings.PRIVATE_KEY, encoder=nacl.encoding.Base64Encoder)

    state = user_pub_key.verify(base64.b64decode(signedhash)).decode()

    # if state != req.session.get("state"):
    #     return response.BadRequest({"error": "Invalid state. not matching one in user session"})

    box = Box(private_key.to_curve25519_private_key(), user_pub_key.to_curve25519_public_key())

    try:
        decrypted = box.decrypt(ciphertext, nonce)
        result = json.loads(decrypted)
        email = result["email"]["email"]
        emailVerified = result["email"]["verified"]
        # if not emailVerified:
        #     return response.BadRequest({"error": "email not verified"})

        user_model = get_user_model()
        users = user_model.objects.filter(email=email)
        if len(users) == 0:
            username = username.replace('.3bot', '')
            user = user_model(username=username, email=email, full_name=username)
            user.is_active = True
            user.save()
        else:
            user = users[0]
        login(req, user)
    except:
        return response.BadRequest({"error": "error decrypting message"})
    serializer = UserAdminSerializer(user)
    data = dict(serializer.data)
    data["auth_token"] = get_token_for_user(user, "authentication")
    data.pop('roles')
    return JsonResponse(data)
