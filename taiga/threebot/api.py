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
        "appid": req.META["HTTP_HOST"],
        "scope": '{"user": true, "email": true}',
        "redirecturl": "/api/v1/threebot/callback",
        "publickey": public_key.to_curve25519_public_key().encode(encoder=nacl.encoding.Base64Encoder),
    }

    return JsonResponse("{0}?{1}".format("https://login.threefold.me", urllib.parse.urlencode(params)))


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

    if state != req.session.get("state"):
        return JsonResponse({"error": "Invalid state. not matching one in user session"}, stats=400)

    box = Box(private_key.to_curve25519_private_key(), user_pub_key.to_curve25519_public_key())

    try:
        decrypted = box.decrypt(ciphertext, nonce)
        result = json.loads(decrypted)
        email = result["email"]["email"]
        emailVerified = result["email"]["verified"]
        if not emailVerified:
            return JsonResponse({"error": "eail not verified"}, stats=400)

        user = check_registered(username, email)

        if user is None:
            user_model = get_user_model()
            user = user_model(username=username, email=email, full_name=username)
            user.set_password(str(uuid4().replace("-" "")))
            user.is_active = True
            user.save()

            ms = Membership()
            ms.user = user
            ms.email = email
            ms.save()
        login(user)
    except:
        return JsonResponse({"error": "error decrypting message"}, stats=400)
