from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List
import torch
from transformers import pipeline
from datetime import datetime, timedelta
import jwt
import yaml
BODY_MODEL_NAME = "mustafaAbdulazizHamza/deberta-phishing-detector-body"
SUBJECT_MODEL_NAME = "mustafaAbdulazizHamza/deberta-phishing-detector-subject"

body_tokenizer = AutoTokenizer.from_pretrained(BODY_MODEL_NAME)
body_model     = AutoModelForSequenceClassification.from_pretrained(BODY_MODEL_NAME)
device    = torch.device("cuda" if torch.cuda.is_available() else "cpu")
body_model.to(device)
body_model.eval()

subject_tokenizer = AutoTokenizer.from_pretrained(SUBJECT_MODEL_NAME)
subject_model     = AutoModelForSequenceClassification.from_pretrained(SUBJECT_MODEL_NAME)
device    = torch.device("cuda" if torch.cuda.is_available() else "cpu")
subject_model.to(device)
subject_model.eval()

def classify(inputs, model, tokenizer):
    inputs = tokenizer(
        inputs,
        padding=True,
        truncation=True,
        max_length=512,
        return_tensors="pt"
    ).to(device)

    with torch.no_grad():
        outputs = model(**inputs)
        probs   = torch.nn.functional.softmax(outputs.logits, dim=1)
        preds   = torch.argmax(probs, dim=1).cpu().numpy()

    return preds

def classify_email(subjects, bodies):
    if isinstance(subjects, str):
        subjects = [subjects]
    if isinstance(bodies, str):
        bodies = [bodies]
    spreds = classify(subjects, subject_model, subject_tokenizer)
    bpreds = classify(bodies, body_model, body_tokenizer)
    return spreds[0], bpreds[0]

app = FastAPI(title="Nightshade Filter: An E-mail Phishing Detection API", version="1.0.0")
def load_config(path="config.yaml"):
    with open(path, "r") as f:
        config = yaml.safe_load(f)
    return config
config = load_config()
SECRET_KEY = config["SECRET_KEY"]
ALGORITHM = config["ALGORITHM"]
TOKEN_EXPIRATION_HOURS = config["TOKEN_EXPIRATION_HOURS"]
USERNAME = config["USERNAME"]
PASSWORD = config["PASSWORD"]
MaxNumEmails = config["MaxNumEmails"]
HOST = config["HOST"]
PORT = config["PORT"]
SSL_CERTFILE = config["SSL_CERTFILE"]
SSL_KEYFILE = config["SSL_KEYFILE"]

security = HTTPBearer()


class Email(BaseModel):
    subject: str = Field(..., min_length=1, description="Email subject")
    body: str = Field(..., min_length=1, description="Email body")


class EmailListRequest(BaseModel):
    emails: List[Email] = Field(..., description="List of emails to classify")


class PredictionResult(BaseModel):
    prediction: int


class EmailListResponse(BaseModel):
    total_emails: int
    predictions: List[PredictionResult]
    current_user: str

class LoginRequest(BaseModel):
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


def create_access_token(username: str, expires_in_hours: int = TOKEN_EXPIRATION_HOURS) -> str:
    expiration = datetime.utcnow() + timedelta(hours=expires_in_hours)
    payload = {
        "sub": username,
        "exp": expiration,
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        return username
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/login", response_model=TokenResponse)
async def login(credentials: LoginRequest):

    if credentials.username != USERNAME or credentials.password != PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    access_token = create_access_token(credentials.username)
    expiration = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRATION_HOURS)
    expires_in = int((expiration - datetime.utcnow()).total_seconds())    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in
    )


@app.post("/predict", response_model=EmailListResponse)
async def predict_emails(
    request: EmailListRequest,
    current_user: str = Depends(verify_token)
):
    if not request.emails:
        raise HTTPException(status_code=400, detail="Email list cannot be empty")
    
    if len(request.emails) > MaxNumEmails:
        raise HTTPException(status_code=400, detail=f"Maximum {MaxNumEmails} emails per request")
    predictions = []
    for email in request.emails:
        spreds, bpreds = classify_email(email.subject, email.body)
        result = PredictionResult(
            prediction=int((spreds + bpreds) > 0)
            )
        predictions.append(result)
    
    return EmailListResponse(
        total_emails=len(request.emails),
        predictions=predictions,
        current_user=current_user
    )


@app.post("/predict-single")
async def predict_single_email(
    email: Email,
    current_user: str = Depends(verify_token)
):
    spreds, bpreds = classify_email(email.subject, email.body)
    
    return {
        "prediction": int((spreds+bpreds) > 0),
        "current_user": current_user
    }


@app.get("/")
async def health_check():
    return {
        "status": "ok",
        "gpu_available": torch.cuda.is_available()
    }
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app,
    host=HOST,
    port=PORT,
    reload=True,ssl_certfile=SSL_CERTFILE,
    ssl_keyfile=SSL_KEYFILE

    )
