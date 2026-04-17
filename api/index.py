import os
import traceback
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
import hashlib

# --- 1. Server Setup & CORS ---
app = FastAPI(title="Smart Voting System API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# --- 2. Lazy imports with error capture ---
_import_error = None
try:
    from pymongo import MongoClient
    from passlib.context import CryptContext
    from jose import jwt

    MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://umaimaasif:umaima123456.@cluster0.amdgtd5.mongodb.net/?retryWrites=true&w=majority")
    client = MongoClient(MONGO_URI, tls=True, tlsAllowInvalidCertificates=True, serverSelectionTimeoutMS=5000)
    db = client["voting_database"]
    users_collection = db["users"]
    votes_collection = db["votes"]

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    SECRET_KEY = "super_secret_voting_key_change_me_later"
    ALGORITHM = "HS256"
except Exception as e:
    _import_error = traceback.format_exc()

# --- 3. Helper functions ---
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=60)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def check_ready():
    if _import_error:
        raise HTTPException(status_code=500, detail=f"Server init error: {_import_error}")

# --- 4. Data Models ---
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

# --- 5. APIs ---
@app.get("/api")
def home():
    return {"message": "Welcome to the Smart Voting Backend!", "status": "ok", "error": _import_error}

@app.get("/api/debug")
def debug():
    return {"import_error": _import_error, "python": os.sys.version}

@app.post("/api/register")
def register_user(user: UserRegister):
    check_ready()
    if users_collection.find_one({"cnic": user.cnic}):
        raise HTTPException(status_code=400, detail="CNIC already registered")
    users_collection.insert_one({
        "cnic": user.cnic, "name": user.name, "password": get_password_hash(user.password),
        "hasVoted": False, "role": user.role
    })
    return {"message": f"{user.role.capitalize()} registered successfully"}

@app.post("/api/login")
def login(request: LoginRequest):
    check_ready()
    user = users_collection.find_one({"cnic": request.cnic})
    if not user or not verify_password(request.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {
        "message": "Login Success",
        "token": create_access_token(data={"sub": user["cnic"]}),
        "name": user["name"],
        "hasVoted": user.get("hasVoted", False),
        "role": user.get("role", "voter")
    }

@app.post("/api/vote")
def cast_vote(request: VoteRequest, authorization: str = Header(None)):
    check_ready()
    if not authorization:
        raise HTTPException(status_code=401, detail="Not logged in")
    try:
        user_cnic = jwt.decode(authorization.split(" ")[1], SECRET_KEY, algorithms=[ALGORITHM]).get("sub")
    except:
        raise HTTPException(status_code=401, detail="Invalid Token")

    user = users_collection.find_one({"cnic": user_cnic})
    if not user: raise HTTPException(status_code=404, detail="User not found")
    if user.get("role") == "admin": raise HTTPException(status_code=403, detail="Admins cannot vote!")
    if user.get("hasVoted") == True: raise HTTPException(status_code=400, detail="You have already voted.")

    last_vote = votes_collection.find_one(sort=[("_id", -1)])
    previous_hash = last_vote["hash"] if last_vote and "hash" in last_vote else "0"

    timestamp = str(datetime.utcnow())
    data_to_hash = f"{user_cnic}{request.candidateID}{timestamp}{previous_hash}"
    current_hash = hashlib.sha256(data_to_hash.encode()).hexdigest()

    votes_collection.insert_one({
        "userCNIC": user_cnic, "candidateID": request.candidateID, "time": timestamp,
        "previousHash": previous_hash, "hash": current_hash
    })
    users_collection.update_one({"cnic": user_cnic}, {"$set": {"hasVoted": True}})
    return {"message": "Vote submitted securely to blockchain!", "receiptHash": current_hash}

@app.get("/api/results")
def get_results():
    check_ready()
    votes = [votes_collection.count_documents({"candidateID": i}) for i in range(1, 5)]
    labels = ["Ahmed Khan", "Usman Ali", "Ayesha Noor", "Kamran Shah"]

    max_votes = max(votes)
    winner_name = "No votes cast" if max_votes == 0 else " & ".join([labels[i] for i, v in enumerate(votes) if v == max_votes])

    total_citizens = users_collection.count_documents({"$or": [{"role": "voter"}, {"role": {"$exists": False}}]})
    total_voted = sum(votes)
    votes_left = total_citizens - total_voted

    return {
        "labels": labels, "data": votes, "winner": winner_name,
        "stats": {"total": total_citizens, "voted": total_voted, "left": votes_left}
    }

@app.get("/api/admin/voters")
def get_voters():
    check_ready()
    voters = list(users_collection.find({"$or": [{"role": "voter"}, {"role": {"$exists": False}}]}, {"_id": 0, "password": 0}))
    return {"voters": voters}
