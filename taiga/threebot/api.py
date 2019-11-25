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
from taiga.users.serializers import UserAdminSerializer, UserSerializer
from taiga.auth.tokens import get_token_for_user
from taiga.base import response
from django.db.models import Q
from taiga.auth.backends import Token
from taiga.base.exceptions import NotAuthenticated
from django.contrib.auth import login
from taiga.base import exceptions as exc
from taiga.base.exceptions import ValidationError

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
    t = Token()
    try:
        user, _ = t.authenticate(req)
        if user:
            login( req, user)
    except NotAuthenticated:
        pass

    signedhash = req.GET.get("signedhash")
    username = req.GET.get("username")
    data = req.GET.get("data")

    if signedhash is None or username is None or data is None:
        return JsonRespnse({"_error_message": "one or more parameter values were missing (signedhash, username, or data", "_error_type": ""}, status=400)
    data = json.loads(data)

    res = requests.get(
        "https://login.threefold.me/api/users/{0}".format(username), {"Content-Type": "application/json"}
    )
    if res.status_code != 200:
        return JsonResponse({"_error_message": "Error retrieving public key for user", "_error_type": ""}, status=400)

    user_pub_key = nacl.signing.VerifyKey(res.json()["publicKey"], encoder=nacl.encoding.Base64Encoder)
    nonce = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])
    private_key = nacl.signing.SigningKey(settings.PRIVATE_KEY, encoder=nacl.encoding.Base64Encoder)

    state = user_pub_key.verify(base64.b64decode(signedhash)).decode()

    #if state != req.session.get("state"):
    #    return JsonResponse({"_error_message": "Invalid state", "_error_type": ""}, status=400)

    box = Box(private_key.to_curve25519_private_key(), user_pub_key.to_curve25519_public_key())
    try:
        decrypted = box.decrypt(ciphertext, nonce)
        result = json.loads(decrypted)
        email = result["email"]["email"]
        emailVerified = result["email"]["verified"]
        if not emailVerified:
            return JsonResponse({"_error_message": "Email not verified", "_error_type": ""}, status=400)     

        user_model = get_user_model()
        pk = res.json()["publicKey"]
       
        users_with_email = user_model.objects.filter(email=email)
        if users_with_email:
            user_with_email = users_with_email[0]
        else:
            user_with_email = None

        # Link user to 3bot login account
        if req.user.is_authenticated():
            user = user_model.objects.filter(id=req.user.id)[0]
            if user_with_email and user_with_email.id != req.user.id:
                return JsonResponse({"_error_message": "Email address is linked with another active account", "_error_type": ""}, status=400)
            # user already linked with 3 bot login
            if user.public_key:
                # user linking another account
                if user.public_key != pk:
                    user.email = email
                    user.public_key = pk
                    user.threebot_name = username.replace('.3bot', '')
                    user.save()
            else:
                # user linking their account for first time
                user.email = email
                user.public_key = pk
                user.full_name = username.replace('.3bot', '')
                user.threebot_name = username.replace('.3bot', '')
                user.save()
        else:
            users = user_model.objects.filter(Q(email=email) | Q(public_key=pk))
            if len(users) == 0:
                # new user
                username = username.replace('.3bot', '')
                user = user_model(username=username, email=email, full_name=username, public_key=pk)
                user.is_active = True
                user.threebot_name = username
                user.save()
            else:
                # email or public key exists
                user = users[0]
                if user.public_key != pk:
                    user.public_key = pk
                    user.threebot_name = username.replace('.3bot', '')
                    user.save()
                elif user.email != email:
                    user.email = email
                    user.threebot_name = username.replace('.3bot', '')
                    user.save()
        login(req, user)
    except:
        raise
    serializer = UserAdminSerializer(user)
    data = dict(serializer.data)
    data["auth_token"] = get_token_for_user(user, "authentication")
    data['public_key'] = pk
    data['email'] = email
    data['threebot_name'] = username.replace('.3bot', '')
    data['roles'] = [role for role in data['roles']]
    return JsonResponse(data)
