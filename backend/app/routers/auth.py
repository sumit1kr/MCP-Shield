from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from app.database import get_db
from app.models import User, RefreshToken
from app.schemas import UserRegister, UserLogin, TokenResponse, UserOut
from app.services import auth_service
from app.dependencies import get_current_user
import uuid

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    # Check if email is unique
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This email is already registered. Login instead?"
        )
    
    # Create new user
    hashed_pwd = auth_service.hash_password(user_data.password)
    new_user = User(
        email=user_data.email,
        hashed_password=hashed_pwd,
        full_name=user_data.full_name
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Generate tokens
    access_token = auth_service.create_access_token(data={"sub": str(new_user.id)})
    refresh_token_value = auth_service.create_refresh_token()
    
    # Save refresh token in DB
    db_refresh_token = RefreshToken(
        user_id=new_user.id,
        token_hash=refresh_token_value,  # Stored directly as hash or token identifier
        expires_at=datetime.utcnow() + timedelta(days=7)
    )
    db.add(db_refresh_token)
    db.commit()
    
    return TokenResponse(access_token=access_token, refresh_token=refresh_token_value)

@router.post("/login", response_model=TokenResponse)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == credentials.email).first()
    
    # Always return 401 on failure (do not reveal if email exists)
    if not user or not auth_service.verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
        
    # Generate tokens
    access_token = auth_service.create_access_token(data={"sub": str(user.id)})
    refresh_token_value = auth_service.create_refresh_token()
    
    # Save refresh token in DB
    db_refresh_token = RefreshToken(
        user_id=user.id,
        token_hash=refresh_token_value,
        expires_at=datetime.utcnow() + timedelta(days=7)
    )
    db.add(db_refresh_token)
    db.commit()
    
    return TokenResponse(access_token=access_token, refresh_token=refresh_token_value)

@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user
