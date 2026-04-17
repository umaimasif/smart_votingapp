import os
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pymongo import MongoClient
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import hashlib # NEW: Used for Blockchain Security

# --- 1. Server Setup & CORS ---
app = FastAPI(title="Smart Voting System API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = MongoClient(MONGO_URI, tls=True, tlsAllowInvalidCertificates=True)
db = client["voting_database"]
users_collection = db["users"]
votes_collection = db["votes"]

# --- 3. Security Setup ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "super_secret_voting_key_change_me_later"
ALGORITHM = "HS256"

def get_password_hash(password): return pwd_context.hash(password)
def verify_password(plain_password, hashed_password): return pwd_context.verify(plain_password, hashed_password)
def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=60)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

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
@app.get("/")
def home(): return {"message": "Welcome to the Smart Voting Backend!"}

@app.post("/api/register")
def register_user(user: UserRegister):
    if users_collection.find_one({"cnic": user.cnic}): raise HTTPException(status_code=400, detail="CNIC already registered")
    users_collection.insert_one({
        "cnic": user.cnic, "name": user.name, "password": get_password_hash(user.password),
        "hasVoted": False, "role": user.role
    })
    return {"message": f"{user.role.capitalize()} registered successfully"}

@app.post("/api/login")
def login(request: LoginRequest):
    user = users_collection.find_one({"cnic": request.cnic})
    if not user or not verify_password(request.password, user["password"]): raise HTTPException(status_code=401, detail="Invalid credentials")
    return {
        "message": "Login Success", "token": create_access_token(data={"sub": user["cnic"]}),
        "name": user["name"], "hasVoted": user.get("hasVoted", False), "role": user.get("role", "voter")
    }

@app.post("/vote")
def cast_vote(request: VoteRequest, authorization: str = Header(None)):
    if not authorization: raise HTTPException(status_code=401, detail="Not logged in")
    try: user_cnic = jwt.decode(authorization.split(" ")[1], SECRET_KEY, algorithms=[ALGORITHM]).get("sub")
    except: raise HTTPException(status_code=401, detail="Invalid Token")
        
    user = users_collection.find_one({"cnic": user_cnic})
    if not user: raise HTTPException(status_code=404, detail="User not found")
    if user.get("role") == "admin": raise HTTPException(status_code=403, detail="Admins cannot vote!")
    if user.get("hasVoted") == True: raise HTTPException(status_code=400, detail="You have already voted.")
        
    # NEW: Blockchain Logic - Link this vote to the last vote!
    last_vote = votes_collection.find_one(sort=[("_id", -1)])
    previous_hash = last_vote["hash"] if last_vote and "hash" in last_vote else "0"
    
    timestamp = str(datetime.utcnow())
    data_to_hash = f"{user_cnic}{request.candidateID}{timestamp}{previous_hash}"
    current_hash = hashlib.sha256(data_to_hash.encode()).hexdigest()

    new_vote = {
        "userCNIC": user_cnic, "candidateID": request.candidateID, "time": timestamp,
        "previousHash": previous_hash, "hash": current_hash # Cryptographically locked!
    }
    votes_collection.insert_one(new_vote)
    users_collection.update_one({"cnic": user_cnic}, {"$set": {"hasVoted": True}})
    
    # Return the hash so the frontend can make a receipt
    return {"message": "Vote submitted securely to blockchain!", "receiptHash": current_hash}

@app.get("/api/results")
def get_results():
    votes = [votes_collection.count_documents({"candidateID": i}) for i in range(1, 5)]
    labels = ["Ahmed Khan", "Usman Ali", "Ayesha Noor", "Kamran Shah"]
    
    max_votes = max(votes)
    winner_name = "No votes cast" if max_votes == 0 else " & ".join([labels[i] for i, v in enumerate(votes) if v == max_votes])
    
    # NEW: Calculate the exact stats you asked for!
    total_citizens = users_collection.count_documents({"$or": [{"role": "voter"}, {"role": {"$exists": False}}]})
    total_voted = sum(votes)
    votes_left = total_citizens - total_voted

    return {
        "labels": labels, "data": votes, "winner": winner_name,
        "stats": {"total": total_citizens, "voted": total_voted, "left": votes_left}
    }

@app.get("/api/admin/voters")
def get_voters():
    voters = list(users_collection.find({"$or": [{"role": "voter"}, {"role": {"$exists": False}}]}, {"_id": 0, "password": 0}))
    return {"voters": voters}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
    
