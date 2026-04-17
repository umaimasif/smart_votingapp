import os
import traceback
import hashlib
from collections import Counter
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="Smart Voting System API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

_import_error = None
try:
    from pymongo import MongoClient
    from passlib.context import CryptContext
    from jose import jwt

    MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://umaimaasif:voting123@cluster0.amdgtd5.mongodb.net/?retryWrites=true&w=majority")
    client = MongoClient(MONGO_URI, tls=True, tlsAllowInvalidCertificates=True, serverSelectionTimeoutMS=5000)
    db = client["voting_database"]
    users_collection = db["users"]
    votes_collection = db["votes"]
    login_attempts_collection = db["login_attempts"]

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    SECRET_KEY = os.getenv("SECRET_KEY", "super_secret_voting_key_change_me_later")
    ALGORITHM = "HS256"
except Exception:
    _import_error = traceback.format_exc()


def get_password_hash(password): return pwd_context.hash(password)
def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)
def create_access_token(data: dict, minutes: int = 60):
    d = data.copy()
    d["exp"] = datetime.utcnow() + timedelta(minutes=minutes)
    return jwt.encode(d, SECRET_KEY, algorithm=ALGORITHM)

def check_ready():
    if _import_error:
        raise HTTPException(status_code=500, detail=f"Init error: {_import_error}")

def check_rate_limit(cnic: str, ip: str):
    cutoff = datetime.utcnow() - timedelta(minutes=15)
    count = login_attempts_collection.count_documents({"cnic": cnic, "timestamp": {"$gte": cutoff}})
    if count >= 5:
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again in 15 minutes.")
    login_attempts_collection.insert_one({"cnic": cnic, "ip": ip, "timestamp": datetime.utcnow()})


class UserRegister(BaseModel):
    cnic: str = Field(..., pattern=r'^\d{5}-\d{7}-\d{1}$')
    name: str
    password: str
    role: str = "voter"

class LoginRequest(BaseModel):
    cnic: str = Field(..., pattern=r'^\d{5}-\d{7}-\d{1}$')
    password: str

class VoteRequest(BaseModel):
    candidateID: int


# ── Health ──────────────────────────────────────────────────────────────────
@app.get("/api")
def home(): return {"message": "Smart Voting System API", "status": "ok"}

@app.get("/api/debug")
def debug():
    try:
        client.admin.command("ping")
        db_status = "connected"
    except Exception as e:
        db_status = str(e)
    return {"import_error": _import_error, "python": os.sys.version, "db": db_status}


# ── Auth ─────────────────────────────────────────────────────────────────────
@app.post("/api/register")
def register(user: UserRegister):
    check_ready()
    if users_collection.find_one({"cnic": user.cnic}):
        raise HTTPException(400, "CNIC already registered")
    users_collection.insert_one({
        "cnic": user.cnic, "name": user.name,
        "password": get_password_hash(user.password),
        "hasVoted": False, "role": user.role
    })
    return {"message": f"{user.role.capitalize()} registered successfully"}

@app.post("/api/login")
def login(body: LoginRequest, req: Request):
    check_ready()
    ip = req.headers.get("x-forwarded-for", req.client.host if req.client else "unknown")
    check_rate_limit(body.cnic, ip)
    user = users_collection.find_one({"cnic": body.cnic})
    if not user or not verify_password(body.password, user["password"]):
        raise HTTPException(401, "Invalid credentials")
    return {
        "message": "Login Success",
        "token": create_access_token({"sub": user["cnic"]}, minutes=60),
        "refresh_token": create_access_token({"sub": user["cnic"], "type": "refresh"}, minutes=1440),
        "name": user["name"],
        "hasVoted": user.get("hasVoted", False),
        "role": user.get("role", "voter")
    }

@app.post("/api/refresh")
def refresh(authorization: str = Header(None)):
    check_ready()
    if not authorization:
        raise HTTPException(401, "No token")
    try:
        payload = jwt.decode(authorization.split(" ")[1], SECRET_KEY,
                             algorithms=[ALGORITHM], options={"verify_exp": False})
        cnic = payload.get("sub")
        if not cnic: raise ValueError()
    except Exception:
        raise HTTPException(401, "Invalid token")
    return {"token": create_access_token({"sub": cnic}, minutes=60)}


# ── Voting ────────────────────────────────────────────────────────────────────
@app.post("/api/vote")
def cast_vote(body: VoteRequest, req: Request, authorization: str = Header(None)):
    check_ready()
    if not authorization:
        raise HTTPException(401, "Not logged in")
    try:
        user_cnic = jwt.decode(authorization.split(" ")[1], SECRET_KEY, algorithms=[ALGORITHM]).get("sub")
    except Exception:
        raise HTTPException(401, "Invalid token")

    user = users_collection.find_one({"cnic": user_cnic})
    if not user: raise HTTPException(404, "User not found")
    if user.get("role") == "admin": raise HTTPException(403, "Admins cannot vote")
    if user.get("hasVoted"): raise HTTPException(400, "You have already voted")

    last = votes_collection.find_one(sort=[("_id", -1)])
    prev_hash = last["hash"] if last and "hash" in last else "0"
    timestamp = str(datetime.utcnow())
    current_hash = hashlib.sha256(f"{user_cnic}{body.candidateID}{timestamp}{prev_hash}".encode()).hexdigest()

    votes_collection.insert_one({
        "userCNIC": user_cnic, "candidateID": body.candidateID,
        "time": timestamp, "previousHash": prev_hash, "hash": current_hash
    })
    users_collection.update_one({"cnic": user_cnic}, {"$set": {"hasVoted": True}})
    return {"message": "Vote recorded on blockchain!", "receiptHash": current_hash}


# ── Results ───────────────────────────────────────────────────────────────────
LABELS = ["Ahmed Khan", "Usman Ali", "Ayesha Noor", "Kamran Shah"]

@app.get("/api/results")
def get_results():
    check_ready()
    counts = [votes_collection.count_documents({"candidateID": i}) for i in range(1, 5)]
    total_voters = users_collection.count_documents({"$or": [{"role": "voter"}, {"role": {"$exists": False}}]})
    total_voted = sum(counts)
    max_v = max(counts)
    winner = "No votes yet" if max_v == 0 else " & ".join([LABELS[i] for i, v in enumerate(counts) if v == max_v])
    return {
        "labels": LABELS, "data": counts, "winner": winner,
        "stats": {"total": total_voters, "voted": total_voted, "left": total_voters - total_voted}
    }

@app.get("/api/admin/voters")
def get_voters():
    check_ready()
    voters = list(users_collection.find(
        {"$or": [{"role": "voter"}, {"role": {"$exists": False}}]},
        {"_id": 0, "password": 0}
    ))
    return {"voters": voters}

@app.get("/api/timeline")
def get_timeline():
    check_ready()
    pipeline = [
        {"$addFields": {"parsedTime": {"$dateFromString": {"dateString": "$time", "onError": None}}}},
        {"$match": {"parsedTime": {"$ne": None}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%H:00", "date": "$parsedTime"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}},
        {"$project": {"hour": "$_id", "count": 1, "_id": 0}}
    ]
    result = list(votes_collection.aggregate(pipeline))
    if not result:
        return {"labels": ["No data"], "data": [0]}
    return {"labels": [r["hour"] for r in result], "data": [r["count"] for r in result]}


# ── Blockchain ────────────────────────────────────────────────────────────────
@app.get("/api/blockchain")
def get_blockchain():
    check_ready()
    raw = list(votes_collection.find({}, {"_id": 0}).sort("_id", 1))
    chain = []
    for i, v in enumerate(raw):
        expected = hashlib.sha256(
            f"{v['userCNIC']}{v['candidateID']}{v['time']}{v['previousHash']}".encode()
        ).hexdigest()
        chain.append({
            "block": i + 1,
            "candidateID": v.get("candidateID"),
            "time": v.get("time"),
            "hash": v.get("hash", ""),
            "previousHash": v.get("previousHash", ""),
            "valid": v.get("hash") == expected
        })
    return {"chain": chain, "length": len(chain)}

@app.get("/api/verify/{vote_hash}")
def verify_hash(vote_hash: str):
    check_ready()
    vote = votes_collection.find_one({"hash": vote_hash}, {"_id": 0, "userCNIC": 0})
    if not vote:
        raise HTTPException(404, "Hash not found in blockchain")
    return {"found": True, "block": vote}

@app.get("/api/chain-integrity")
def chain_integrity():
    check_ready()
    votes = list(votes_collection.find({}, {"_id": 0}).sort("_id", 1))
    for i, v in enumerate(votes):
        expected = hashlib.sha256(
            f"{v['userCNIC']}{v['candidateID']}{v['time']}{v['previousHash']}".encode()
        ).hexdigest()
        if v.get("hash") != expected:
            return {"valid": False, "total_blocks": len(votes), "broken_at_block": i + 1}
        if i > 0 and v.get("previousHash") != votes[i - 1]["hash"]:
            return {"valid": False, "total_blocks": len(votes), "broken_at_block": i + 1}
    return {"valid": True, "total_blocks": len(votes), "broken_at_block": None}

@app.get("/api/anomalies")
def detect_anomalies():
    check_ready()
    votes = list(votes_collection.find({}, {"_id": 0}).sort("_id", 1))
    anomalies = []

    for i in range(1, len(votes)):
        # Rapid voting check
        try:
            t1 = datetime.fromisoformat(votes[i-1]["time"].replace(" ", "T").split(".")[0])
            t2 = datetime.fromisoformat(votes[i]["time"].replace(" ", "T").split(".")[0])
            if abs((t2 - t1).total_seconds()) < 2:
                anomalies.append({"type": "RAPID_VOTING", "severity": "MEDIUM",
                                   "message": f"Blocks #{i} and #{i+1} cast less than 2 seconds apart"})
        except Exception:
            pass
        # Chain break check
        if votes[i].get("previousHash") != votes[i-1].get("hash"):
            anomalies.append({"type": "CHAIN_BREAK", "severity": "HIGH",
                               "message": f"Hash chain broken at block #{i+1}"})

    for cnic, count in Counter(v.get("userCNIC") for v in votes).items():
        if count > 1:
            anomalies.append({"type": "DUPLICATE_VOTE", "severity": "HIGH",
                               "message": f"Multiple votes from same voter ({cnic[:5]}-XXXXX-X)"})

    return {"anomalies": anomalies, "total": len(anomalies), "clean": len(anomalies) == 0}
