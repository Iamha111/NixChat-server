from flask import Flask, request, jsonify
from flask_jwt_extended import (JWTManager, jwt_required,
                                create_access_token,
                                get_jwt_identity,
                                verify_jwt_in_request)
from werkzeug.security import (generate_password_hash,
                               check_password_hash)
import os
import sys
import json
import datetime


VERSION = "1.0.0"
API_VERSIONS = ["1.0.0"]


app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.urandom(32).hex()
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False

jwt = JWTManager(app)


class DB:
    def __init__(self):

        self.path = "db.json"

        self.db = {}

        self.load()

    def load(self):
        "Loads db from the disk"

        try:
            with open(self.path, "r") as f:
                self.db = json.load(f)
        except FileNotFoundError:
            with open(self.path, "w") as f:
                json.dump(
                    {"users": [], "groups": []},
                    f, indent=4
                )

            self.load()

    def sync(self):
        "Backups db to the disk"

        with open(self.path, "w") as f:
            json.dump(self.db, f, indent=4)


db = DB()


def register(data):
    "Register an user"
    
    for u in db.db["users"]:
        if u["username"] == data["username"]:
            return jsonify({"msg": "Username was taken already"}), 400        

    pwh = generate_password_hash(data["password"], method="pbkdf2:sha256")

    db.db["users"].append({"username": data["username"], "rank": "",
                           "password": pwh, "messages": [], "chats": [],
                           "pixmap": "", "publickey": "", "groups": []})

    db.sync()

    return jsonify({"msg": "Success"}), 201


def login(json):

    username = json["username"]
    password = json["password"]

    r = False

    for user in db.db["users"]:
        if user["username"] == username:
            if check_password_hash(user["password"], password):
                r = True

    if r:
        token = create_access_token(identity=username)
        return jsonify({"msg": "Success", "token": token}), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 400


def send(json, sender):
    "Send message to some user"

    # Payload must be "from", "messages"
    # "messages" must be "to", "contents", "date"
    
    message = json["message"]
    rt = json["receiver_type"]

    msg = {
        "from": sender,
        "contents": message["contents"],
        "date": message["date"]
    }

    if rt == "user":
        for u in db.db["users"]:
            if u["username"] == message["to"]:
                u["messages"].append(msg)
                if sender not in u["chats"]:
                    u["chats"].append(sender)

            if u["username"] == sender:
                if message["to"] not in u["chats"]:
                    u["chats"].append(message["to"])

    elif rt == "group":
        for g in db.db["groups"]:
            if g["name"] == message["to"]:
                g["messages"].append(msg)

    db.sync()

    return jsonify({"msg": "Success"})


def clear_messages(data, user):
    "Clear messages"

    for u in db.db["users"]:
        if u["username"] == user:
            u["messages"] = []

    for g in db.db["groups"]:
        if user in g["members"]:
            for msg in g["messages"]:
                if user in msg["contents"]:
                    msg["contents"].pop(user)
                if len(msg["contents"]) == 0:
                    g["messages"].remove(msg)

    db.sync()

    return jsonify({"msg": "ok"})


def sync(payload, user):
    "Return only basic user info"

    r = {}

    print("user is ", user)

    for u in db.db["users"]:
        if u["username"] == user:
            r["messages"] = u["messages"]
            r["chats"] = u["chats"]
            r["groups"] = u["groups"]

    for g in db.db["groups"]:
        if g["name"] in r["groups"]:
            for msg in g["messages"]:
                if user in msg["contents"]:
                    m = {
                        "from": g["name"],
                        "contents": msg["contents"][user],
                        "date": msg["date"]
                    }

                    r["messages"].append(m)

    return jsonify(r)


def get_my_info(_, user):
    "Return user's info"

    r = {}

    for u in db.db["users"]:
        if u["username"] == user:
            r = u
            break

    return jsonify(r)


def set_my_info(data, user):
    "Set user's info"

    for u in db.db["users"]:
        if u["username"] == user:
                
            if "pixmap" in data:
                u["pixmap"] = data["pixmap"]

            if "publickey" in data:
                u["publickey"] = data["publickey"]

    db.sync()

    return jsonify({"msg": "Success"})


def get_user_info(payload):
    "Get public info of some user"

    user = payload["user"]

    r = {"msg": "Unknown user"}

    for u in db.db["users"]:
        if u["username"] == user:
            r = {"username": u["username"],
                 "rank": u["rank"],
                 "pixmap": u["pixmap"],
                 "publickey": u["publickey"],
                 "msg": "Success"}

    return jsonify(r)


def remove_user(data, user):
    "Removes an user"

    for u in db.db["users"]:
        for msg in u["messages"]:
            if msg["from"] == user:
                u["messages"].remove(msg)
                
        if user in u["chats"]:
            u["chats"].remove(user)
            
        if u["username"] == user:
            db.db["users"].remove(u)

    return jsonify({"msg": "Success"})


def add_group(data, admin):
    "Adds a group"

    db.db["groups"].append({
        "name": data["name"],
        "messages": [],
        "admin": admin,
        "members": [admin]
    })

    for u in db.db["users"]:
        if u["username"] == admin:
            u["groups"].append(data["name"])

    db.sync()

    return jsonify({"msg": "Success"})


def get_group_info(data):
    "Return group info"

    name = data["name"]

    for g in db.db["groups"]:
        if g["name"] == name:
            return jsonify(g)

    return jsonify({"msg": "Unknown group"})


def modify_group(data, user):
    "Modifies a group"

    for g in db.db["groups"]:
        if g["name"] == data["name"]:
            if g["admin"] == user:
                if "pixmap" in data:
                    g["pixmap"] = data["pixmap"]
            else:
                return jsonify({"msg": "You aren't an admin"})

    db.sync()

    return jsonify({"msg": "Success"})
    

def remove_group(data, user):
    "Removes a group"

    for g in db.db["groups"]:
        if g["name"] == data["name"]:
            if g["admin"] == user:

                for u in db.db["users"]:
                    if g["name"] in u["groups"]:
                        u["groups"].remove(g["name"])

                db.db["groups"].remove(g)
                
            else:
                return jsonify({"msg": "You aren't an admin"})

    db.sync()

    return jsonify({"msg": "Success"})


def add_group_member(data):
    "Adds a group member"

    target = data["user"]
    group_ok = target_ok = False

    for u in db.db["users"]:
        if u["username"] == target:
            target_ok = True
            print("uok")

    for g in db.db["groups"]:
        if g["name"] == data["group"]:
            group_ok = True
            print("gok")

    if group_ok and target_ok:
        for u in db.db["users"]:
            if u["username"] == target:
                u["groups"].append(data["group"])

        for g in db.db["groups"]:
            if g["name"] == data["group"]:
                g["members"].append(target)

        db.sync()

        return jsonify({"msg": "Success"})
    else:
        return jsonify({"msg": "Invalid group or user"})
    

def remove_chat(data, user):
    "Removes a chat"

    for u in db.db["users"]:
        if u["username"] == user:
            u["chats"].remove(data["name"])

    return jsonify({"msg": "Success"})


def ping(data):
    "Ping"

    return jsonify({"msg": "pong"})


def control(json, username):
    "Server administration"

    perm = False

    for u in db.db["users"]:
        if u["username"] == username:
            if u["rank"] == "Administrator":
                perm = True

    if perm:
        action = json["action"]
        r = {"msg": "Success"}
        rc = 200

        if action == "dump_db":
            r["data"] = db.db
            
        elif action == "load_db":
            db.db = json["data"]
            db.sync()
            
        elif action == "ban_user":
            remove_user({}, json["username"])
            
        elif action == "set_rank":
            for u in db.db["users"]:
                if u["name"] == json["username"]:
                    u["rank"] == json["rank"]
                    db.sync()

        return jsonify(r), rc
            
    else:
        return jsonify({"msg": "You can't control the server"}), 403


def check_json(json):
    "Checks json integrity"
    res = "ok"

    if not "version" in json:
        res = 'No "versions" in json'
    else:
        if not json["version"] in API_VERSIONS:
            res = "Unsupported API version"
    if not "method" in json:
        res = 'No "method" in json'
    if not "payload" in json:
        res = 'No "payload" in json'

    return res


@app.route("/", methods=["POST"])
def entry():
    "An RPC entry"

    # Get reqired data from the request

    json = request.json
    jwt = request.headers.get("Authorization")

    # Check json integrity

    json_integrity = check_json(json)

    if json_integrity != "ok":
        return jsonify({"msg": json_integrity}), 400

    if jwt:
        verify_jwt_in_request()
        username = get_jwt_identity()
    else:
        username = None
        
    # These lines are dangerous. Use only for development.
    # print("Debug info:")
    # print("json:", json, "jwt:", jwt, "username:", username)

    # Call function from "method"

    need_jwt = ["send", "sync", "set_my_info", "remove_chat",
                "add_group", "remove_group", "remove_user",
                "modify_group", "clear_messages", "control"]

    method_table = {
        "register": register,
        "login": login,
        "get_user_info": get_user_info,
        "send": send,
        "sync": sync,
        "clear_messages": clear_messages,
        "set_my_info": set_my_info,
        "remove_user": remove_user,
        "remove_chat": remove_chat,
        "add_group": add_group,
        "remove_group": remove_group,
        "add_group_member": add_group_member,
        "modify_group": modify_group,
        "get_group_info": get_group_info,
        "ping": ping,
        "control": control
    }
    
    if json["method"] in method_table:
        if json["method"] in need_jwt:
            r = method_table[json["method"]](json["payload"], username)
        else:
            r = method_table[json["method"]](json["payload"])
        return r
    else:
        return jsonify({"msg": "Invalid method"}), 501

    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
