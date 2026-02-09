#project cross time-zone
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import random
import smtplib
from email.message import EmailMessage
import psycopg2
import os
import uuid
import base64
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from datetime import date
# --------------------------------------------------------------------------------
# CONFIGURATION
# --------------------------------------------------------------------------------

JWT_SECRET = "g7X9Fq2KrmP4bTz8LwH1nS3vDaE6YpQjR5UcV0MfNiZoJbKtWxYhCdGuVsBlAoEp"
JWT_ALGO = "HS256"

MAIL_USERNAME = "spsoftcts@gmail.com"
MAIL_PASSWORD = "nhduwpfrmjojwrdl"  
MAIL_FROM = "spsoftcts@gmail.com"
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587

# Temporary store for OTP email tracking
TEMP_EMAIL_STORE = {
    "pending_email": None,
    "forgot_email": None
}

# PostgreSQL connection
conn = psycopg2.connect(
    host="localhost",
    database="postgres",
    user="postgres",
    password="Password123"
)
cursor = conn.cursor()

# ----------------------------------------
# DB TABLE SETUP
# ----------------------------------------

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    otp VARCHAR(10),
    otp_expires_at TIMESTAMP,
    is_verified BOOLEAN DEFAULT FALSE,
    profile_image VARCHAR(255),
    timezone VARCHAR(100) NOT NULL DEFAULT 'UTC'
);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS groups(
    id SERIAL PRIMARY KEY,
    created_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_name VARCHAR(255) NOT NULL,
    group_description TEXT,
    group_icon VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS group_members (
    id SERIAL PRIMARY KEY,
    group_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT CHECK (role IN ('admin', 'member')),
    added_at TIMESTAMP DEFAULT NOW()
);
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS group_invites (
    id SERIAL PRIMARY KEY,
    group_id INTEGER NOT NULL,
    invited_by INTEGER NOT NULL,
    invited_email TEXT NOT NULL,
    status TEXT CHECK (status IN ('pending', 'accepted', 'rejected')),
    invited_user_id INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);
""")
cursor.execute(""" CREATE TABLE IF NOT EXISTS user_nicknames (
    id SERIAL PRIMARY KEY,
    owner_user_id INT NOT NULL,   -- who set the nickname (you)
    target_user_id INT NOT NULL,  -- whom the nickname is for
    nickname VARCHAR(255),
    UNIQUE (owner_user_id, target_user_id)
);
""")

cursor.execute(""" CREATE TABLE IF NOT EXISTS user_status (
    user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL CHECK (status IN ('available', 'busy', 'dnd')),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);""")
cursor.execute(""" CREATE TABLE IF NOT EXISTS user_availability (
    id SERIAL PRIMARY KEY,

    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    from_time TIME NOT NULL,
    to_time TIME NOT NULL,
    available_from_utc TIMESTAMP NOT NULL,
    available_to_utc TIMESTAMP NOT NULL,
    initial_notification_sent BOOLEAN DEFAULT FALSE,
    reminder_sent BOOLEAN DEFAULT FALSE,
    confirmation_status VARCHAR(20) DEFAULT 'PENDING',
    confirmation_responded_at TIMESTAMP NULL,
    auto_declined BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")
cursor.execute(""" CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50),
    reference_id INT,
    message TEXT,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

conn.commit()

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


app = FastAPI(title="Cross Timezone Scheduler Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # for testing: allow all origins
    allow_credentials=False,  # we don't need cookies
    allow_methods=["*"],      # GET, POST, PUT, DELETE, OPTIONS, ...
    allow_headers=["*"],      # all headers including Authorization
)
def response(success: bool, message: str, data=None, status_code=200):
    return {
        "statusCode": status_code,
        "success": success,
        "message": message,
        "data": data
    }
MEDIA_ROOT = "media"
os.makedirs(MEDIA_ROOT, exist_ok=True)
app.mount("/media", StaticFiles(directory=MEDIA_ROOT), name="media")

# --------------------------------------------------------------------------------
# MODELS
# --------------------------------------------------------------------------------

class SignupModel(BaseModel):
    name: str
    email: EmailStr
    password: str
    timezone: str | None = None 
    profile_image_base64:  str | None = None
 



class SigninModel(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordModel(BaseModel):
    email: EmailStr

# --------------------------------------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------------------------------------
def save_base64_image(base64_string: str, subdir: str) -> str:
    """
    base64_string: 'data:image/png;base64,.....' OR plain 'iVBORw0KGgo...'
    subdir: 'users' or 'groups'
    returns: URL path like '/media/users/123abc.png'
    """
    if not base64_string:
        return None

    # If it has data URL header, strip it and detect extension
    ext = "png"
    if "," in base64_string:
        header, base64_data = base64_string.split(",", 1)
        if "jpeg" in header or "jpg" in header:
            ext = "jpg"
        elif "gif" in header:
            ext = "gif"
    else:
        base64_data = base64_string

    try:
        image_bytes = base64.b64decode(base64_data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid image data: {e}")

    folder = os.path.join(MEDIA_ROOT, subdir)
    os.makedirs(folder, exist_ok=True)

    filename = f"{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(folder, filename)

    with open(filepath, "wb") as f:
        f.write(image_bytes)

    # This is what you store in DB and return to frontend
    return f"/media/{subdir}/{filename}"
def send_email_otp(to_email: str, otp: str):
    msg = EmailMessage()
    msg["Subject"] = "Your OTP Verification Code"
    msg["From"] = MAIL_FROM
    msg["To"] = to_email

    msg.set_content(
        f"Your OTP is: {otp}\n\n"
        f"This OTP is valid for ONLY 5 minutes. Please do not share it with anyone."
    )

    with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as s:
        s.starttls()
        s.login(MAIL_USERNAME, MAIL_PASSWORD)
        s.send_message(msg)


def create_jwt_token(email: str):
    payload = {
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

# --------------------------------------------------------------------------------
# SIGNUP
# --------------------------------------------------------------------------------
# Store pending signups until OTP is verified
PENDING_SIGNUPS = {}  

OTP_VALIDITY_MINUTES = 5


# @app.post("/auth/signup")
# def signup(data: SignupModel):
#     # Check if user already exists in DB
#     cursor.execute("SELECT 1 FROM users WHERE email=%s", (data.email,))
#     exists = cursor.fetchone()

#     if exists:
#         return response(False, "Email already registered", None, 400)

#     # Generate OTP + expiry
#     otp = str(random.randint(100000, 999999))
#     otp_expires_at = datetime.utcnow() + timedelta(minutes=OTP_VALIDITY_MINUTES)

#     # Save profile image if provided
#     profile_image_path = None
#     if data.profile_image_base64:
#         profile_image_path = save_base64_image(
#             data.profile_image_base64,
#             subdir="users"
#         )

#     # Store signup temporarily (NOT in DB)
#     PENDING_SIGNUPS[data.email] = {
#         "name": data.name,
#         "email": data.email,
#         "password": pwd_context.hash(data.password),
#         "profile_image": profile_image_path,
#         "otp": otp,
#         "otp_expires_at": otp_expires_at,
#     }

#     # Send OTP
#     send_email_otp(data.email, otp)

#     # Return formatted response
#     return response(
#         True,
#         f"Signup started. OTP sent to email. OTP is valid for {OTP_VALIDITY_MINUTES} minutes.",
#         None,
#         200
#     )

@app.post("/auth/signup")
def signup(data: SignupModel):

    # ✅ Default timezone = UTC
    user_timezone = data.timezone or "UTC"

    # ✅ Validate timezone
    try:
        pytz.timezone(user_timezone)
    except Exception:
        return response(False, "Invalid timezone", None, 400)

    cursor.execute("SELECT 1 FROM users WHERE email=%s", (data.email,))
    if cursor.fetchone():
        return response(False, "Email already registered", None, 400)

    otp = str(random.randint(100000, 999999))
    otp_expires_at = datetime.utcnow() + timedelta(minutes=5)
    profile_image_path = None
    if data.profile_image_base64:
        profile_image_path = save_base64_image(
            data.profile_image_base64,
            subdir="users"
        )
    PENDING_SIGNUPS[data.email] = {
        "name": data.name,
        "email": data.email,
        "password": pwd_context.hash(data.password),
        "timezone": user_timezone,   # 👈 always set
        "otp": otp,
        "otp_expires_at": otp_expires_at,
        "profile_image": profile_image_path
    }

    send_email_otp(data.email, otp)

    return response(
        True,
        "Signup started. OTP sent to email.",
        None,
        200
    )

class VerifyOTPModel(BaseModel):
    email: EmailStr
    otp: str


@app.post("/auth/signup/verify-otp")
def verify_signup_otp(data: VerifyOTPModel):
    pending = PENDING_SIGNUPS.get(data.email)

    if not pending:
        return response(
            False,
            "No pending signup found for this email",
            None,
            400
        )

    # 1️⃣ Check OTP
    if pending["otp"] != data.otp:
        return response(
            False,
            "Invalid OTP",
            None,
            400
        )

    # 2️⃣ Check OTP expiry
    if datetime.utcnow() > pending["otp_expires_at"]:
        return response(
            False,
            "OTP expired. Please request a new OTP.",
            None,
            400
        )

    try:
        # 3️⃣ Create user ONLY after OTP verification
        cursor.execute("""
            INSERT INTO users (
                name,
                email,
                password,
                otp,
                otp_expires_at,
                is_verified,
                profile_image,
                timezone
            )
            VALUES (%s, %s, %s, NULL, NULL, TRUE, %s, %s)
            RETURNING id
        """, (
            pending["name"],
            pending["email"],
            pending["password"],
            pending["profile_image"],
            pending.get("timezone", "UTC")  # ✅ FIX
        ))

        user_id = cursor.fetchone()[0]
        conn.commit()

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return response(
            False,
            "User already exists",
            None,
            400
        )

    except Exception as e:
        conn.rollback()
        return response(
            False,
            f"Signup failed: {str(e)}",
            None,
            500
        )

    # 4️⃣ Fetch pending invitations
    cursor.execute("""
        SELECT
            gi.id AS invite_id,
            g.id AS group_id,
            g.group_name
        FROM group_invites gi
        JOIN groups g ON g.id = gi.group_id
        WHERE gi.invited_email = %s
          AND gi.status = 'pending'
        ORDER BY gi.created_at DESC
    """, (data.email,))

    rows = cursor.fetchall()

    invited_groups = [
        {
            "invite_id": row[0],
            "group_id": row[1],
            "group_name": row[2]
        }
        for row in rows
    ]

    # 5️⃣ Cleanup pending signup AFTER success
    PENDING_SIGNUPS.pop(data.email, None)

    return response(
        True,
        "Signup successful",
        {
            "id": user_id,
            "email": data.email,
            "timezone": pending.get("timezone", "UTC"),
            "invited_groups": invited_groups
        },
        200
    )


class ResendOTPModel(BaseModel):
    email: EmailStr

@app.post("/auth/signup/resend-otp")
def resend_signup_otp(data: ResendOTPModel):
    pending = PENDING_SIGNUPS.get(data.email)
    if not pending:
        return response(False, "No pending signup found for this email", None, 400)

    # Generate new OTP + expiry
    new_otp = str(random.randint(100000, 999999))
    new_expiry = datetime.utcnow() + timedelta(minutes=OTP_VALIDITY_MINUTES)

    pending["otp"] = new_otp
    pending["otp_expires_at"] = new_expiry

    send_email_otp(data.email, new_otp)

    return response(True, "OTP resent successfully. It is valid for 5 minutes.", None, 200)




@app.post("/auth/signin")
def signin(data: SigninModel):
    cursor.execute(
        """
        SELECT id, name, email, password, is_verified, profile_image
        FROM users
        WHERE email = %s
        """,
        (data.email,)
    )
    user = cursor.fetchone()

    if not user:
        return response(False, "User not found", None, 400)

    user_id, name, email, password, is_verified, profile_image = user

    if not is_verified:
        return response(False, "User not verified", None, 400)

    if not pwd_context.verify(data.password, password):
        return response(False, "Incorrect password", None, 400)

    token = create_jwt_token(email)

    return response(
        True,
        "Signin successful",
        {
            "user_id": user_id,
            "name": name,
            "email": email,
            "access_token": token,
            "profile_image": profile_image
        },
        200
    )




@app.post("/auth/forgot-password")
def forgot_password(data: ForgotPasswordModel):

    email = data.email

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    exists = cursor.fetchone()

    if not exists:
        raise HTTPException(400, "Email not registered")

    otp = str(random.randint(100000, 999999))
    TEMP_EMAIL_STORE["forgot_email"] = email

    cursor.execute("UPDATE users SET otp=%s WHERE email=%s", (otp, email))
    conn.commit()

    send_email_otp(email, otp)

    return response(
        True,
        f"Password reset OTP sent",
        None,
        200
    )

@app.post("/auth/forgot-password/verify-otp")
def verify_reset_otp(data: VerifyOTPModel):

    email = TEMP_EMAIL_STORE.get("forgot_email")

    if not email:
        raise HTTPException(400, "No password reset session found.")

    cursor.execute("SELECT otp FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    if not user or user[0] != data.otp:
        raise HTTPException(400, "Invalid OTP")

    return response(
        True,
        f"OTP verified. You can now reset password.",
        None,
        200
    )

class ResetPasswordModel(BaseModel):
    email: EmailStr
    password: str

@app.post("/auth/reset-password")
def reset_password(data: ResetPasswordModel):

    # Email stored during /forgot-password
    email = TEMP_EMAIL_STORE.get("forgot_email")

    if not email:
        return response(False, "No reset password session found.", None, 400)

    # Check if the email matches the original forgot email session
    if data.email.lower() != email.lower():
        return response(False, "Email mismatch. Invalid reset request.", None, 400)

    # Fetch existing password from DB
    cursor.execute("SELECT password FROM users WHERE email=%s", (email,))
    row = cursor.fetchone()

    if not row:
        return response(False, "User not found.", None, 400)

    old_hashed_password = row[0]

    # ❌ Check: new password must NOT match old password
    if pwd_context.verify(data.password, old_hashed_password):
        return response(False, "New password cannot be the same as the old password.", None, 400)

    # Hash the new password
    new_hashed_password = pwd_context.hash(data.password)

    # Update the password
    cursor.execute(
        "UPDATE users SET password=%s WHERE email=%s",
        (new_hashed_password, email)
    )
    conn.commit()

    # Clear session
    TEMP_EMAIL_STORE["forgot_email"] = None

    return response(
        True,
        "Password reset successful",
        None,
        200
    )



@app.post("/auth/logout")
def logout():
    return {"message": "Logout successful ."}



from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

# this defines the "Bearer" auth scheme Swagger will use
token_auth_scheme = HTTPBearer(auto_error=True)

def auth_user(credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    email = payload.get("email")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    cursor.execute("""
        SELECT id, name, email, is_verified, timezone
        FROM users
        WHERE email = %s
    """, (email,))

    row = cursor.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="User not found")

    if not row[3]:
        raise HTTPException(status_code=401, detail="User not verified")

    return {
        "id": row[0],
        "name": row[1],
        "email": row[2],
        "timezone": row[4] if isinstance(row[4], str) and row[4].strip() else "UTC"
    }

# -----------------------------
# GROUP MODELS
# -----------------------------
from pydantic import BaseModel, EmailStr
from fastapi import Depends, HTTPException

class CreateGroupModel(BaseModel):
    group_name: str
    group_description: str | None = None
    group_icon_base64: str | None = None

class InviteModel(BaseModel):
    email: EmailStr

class AddMemberModel(BaseModel):
    email: EmailStr


# -----------------------------
# EMAIL HELPER FOR INVITES
# -----------------------------
def send_invite_email(
    to_email: str,
    group_name: str,
    invited_by_name: str,
    invite_id: int,
    custom_message: str = None  # ✅ NEW (optional)
):
    msg = EmailMessage()
    msg["Subject"] = f"Invitation to join {group_name} on CTS"
    msg["From"] = MAIL_FROM
    msg["To"] = to_email

    # ✅ Use custom message for reinvite, else default message
    plain_text_message = custom_message or (
        f"Hello,\n\n"
        f"You have been invited by {invited_by_name} to join the group "
        f"'{group_name}' on CTS.\n\n"
        f"If you don't have a CTS account, please create one using this email: {to_email}.\n"
        f"After logging in, go to your 'Invitations' section to accept or reject the invite.\n\n"
        f"Invite ID: {invite_id}\n"
        f"Thank you,\nCTS Team"
    )

    msg.set_content(plain_text_message)

    # ✅ HTML body
    html_body = f"""
    <html>
      <body>
        <p>Hello,</p>
        <p>{custom_message or f"You have been invited by <b>{invited_by_name}</b> to join the group <b>{group_name}</b> on CTS."}</p>

        <p>If you don't have a CTS account, please create one using this email:
           <b>{to_email}</b>.</p>

        <p>After logging in, navigate to your <b>Invitations</b> section to 
           <b>Accept</b> or <b>Reject</b> the invite.</p>

        <p><b>Invite ID:</b> {invite_id}</p>

        <p>Thank you,<br/>CTS Team</p>
      </body>
    </html>
    """

    msg.add_alternative(html_body, subtype="text/html")

    with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as s:
        s.starttls()
        s.login(MAIL_USERNAME, MAIL_PASSWORD)
        s.send_message(msg)

# -----------------------------
# CREATE GROUP
# -----------------------------
@app.post("/groups/create")
def create_group(data: CreateGroupModel, user=Depends(auth_user)):

    group_icon_path = None
    if data.group_icon_base64:
        group_icon_path = save_base64_image(
            data.group_icon_base64,
            subdir="groups"
        )

    cursor.execute("""
        INSERT INTO groups (created_by, group_name, group_description, group_icon)
        VALUES (%s, %s, %s, %s)
        RETURNING id
    """, (
        user["id"],
        data.group_name,
        data.group_description,
        group_icon_path
    ))
    group_id = cursor.fetchone()[0]
    conn.commit()

    # creator becomes admin (unchanged)
    cursor.execute("""
        INSERT INTO group_members (group_id, user_id, role)
        VALUES (%s, %s, 'admin')
    """, (group_id, user["id"]))
    conn.commit()

    return response(
    True,
    "Group created successfully",
    {
        "group_id": group_id,
        "group_icon": group_icon_path
    },
    200
    )



@app.get("/groups")
def get_groups(user=Depends(auth_user)):
    cursor.execute("""
        SELECT DISTINCT
            g.id,
            g.group_name,
            g.group_description,
            g.group_icon,
            g.created_by
        FROM groups g
        LEFT JOIN group_members gm
            ON gm.group_id = g.id
        WHERE g.created_by = %s
           OR gm.user_id = %s
        ORDER BY g.id DESC
    """, (user["id"], user["id"]))

    rows = cursor.fetchall()

    groups = [
        {
            "id": r[0],
            "name": r[1],
            "description": r[2],
            "group_icon": r[3],
            "is_creator": r[4] == user["id"]  # 🔥 useful for frontend
        }
        for r in rows
    ]

    return response(
        True,
        "Groups fetched successfully",
        groups,
        200
    )



@app.get("/groups/{group_id}")
def group_details(group_id: int, user=Depends(auth_user)):
    # ✅ Allow access if user is creator OR member
    cursor.execute("""
        SELECT 
            g.id,
            g.group_name,
            g.group_description,
            g.group_icon,
            g.created_by
        FROM groups g
        LEFT JOIN group_members gm
            ON gm.group_id = g.id
        WHERE g.id = %s
          AND (g.created_by = %s OR gm.user_id = %s)
    """, (group_id, user["id"], user["id"]))

    group_row = cursor.fetchone()

    if not group_row:
        return response(
            False,
            "You are not authorized to view this group",
            None,
            403
        )

    group_creator_id = group_row[4]

    # ✅ Fetch members with nickname + availability
    cursor.execute("""
        SELECT 
            u.id,
            u.name,
            u.email,
            u.profile_image,
            un.nickname,
            CASE
            WHEN us.status = 'busy' THEN 1
            WHEN us.status = 'dnd' THEN 2
            ELSE 0
        END AS availability_status
        FROM group_members gm
        JOIN users u ON u.id = gm.user_id
        LEFT JOIN user_nicknames un
            ON un.target_user_id = u.id
           AND un.owner_user_id = %s
        LEFT JOIN user_status us
            ON us.user_id = u.id
        WHERE gm.group_id = %s
        ORDER BY u.name
    """, (user["id"], group_id))

    rows = cursor.fetchall()

    members = [
        {
            "user_id": r[0],
            "display_name": r[4] if r[4] else r[1],
            "email": r[2],
            "profile_image": r[3],
            "nickname": r[4],
            "availability_status": r[5],
            "is_creator": True if r[0] == group_creator_id else False
        }
        for r in rows
    ]

    return response(
        True,
        "Group details fetched successfully",
        {
            "group_id": group_row[0],
            "group_name": group_row[1],
            "group_description": group_row[2],
            "group_icon": group_row[3],
            "members": members
        },
        200
    )

class SetNicknameModel(BaseModel):
    target_user_id: int
    nickname: str


@app.post("/users/nickname")
def set_nickname(
    data: SetNicknameModel,
    user=Depends(auth_user)
):
    # Optional validation: prevent self-nickname
    if data.target_user_id == user["id"]:
        return response(
            False,
            "You cannot set a nickname for yourself",
            None,
            400
        )

    cursor.execute("""
        INSERT INTO user_nicknames (owner_user_id, target_user_id, nickname)
        VALUES (%s, %s, %s)
        ON CONFLICT (owner_user_id, target_user_id)
        DO UPDATE SET nickname = EXCLUDED.nickname
    """, (user["id"], data.target_user_id, data.nickname))

    conn.commit()

    return response(
        True,
        "Nickname updated successfully",
        {
            "target_user_id": data.target_user_id,
            "nickname": data.nickname
        },
        200
    )


# -----------------------------
# ADD MEMBER (DIRECT OR INVITE)
# -----------------------------
# 

@app.get("/groups/{group_id}/search-members")
def search_members(group_id: int, q: str, user=Depends(auth_user)):

    # admin check
    cursor.execute("""
        SELECT role FROM group_members
        WHERE group_id=%s AND user_id=%s
    """, (group_id, user["id"]))
    row = cursor.fetchone()
    if not row or row[0] != "admin":
        return response(False, "Only admins can search members", None, 403)

    # search users by email
    cursor.execute("""
        SELECT id, name, email, profile_image
        FROM users
        WHERE email ILIKE %s
        LIMIT 10
    """, (f"%{q}%",))

    rows = cursor.fetchall()

    members = [
        {
            "user_id": r[0],
            "name": r[1],
            "email": r[2],
            "profile_image": r[3]
        }
        for r in rows
    ]

    return response(
        True,
        "Members fetched successfully",
        {
            "group_id": group_id,
            "query": q,
            "results": members
        },
        200
    )
from typing import List

class AddMembersSubmitModel(BaseModel):
    group_id: int
    user_ids: list[int]

@app.post("/groups/add-members")
def add_members_on_submit(
    data: AddMembersSubmitModel,
    user=Depends(auth_user)
):
    try:
        cursor.execute("""
            SELECT id
            FROM groups
            WHERE id = %s AND created_by = %s
        """, (data.group_id, user["id"]))

        if not cursor.fetchone():
            return response(False, "Only group creator can add members", None, 403)

        added_users = []
        skipped_users = []
        invalid_users = []

        for member_id in data.user_ids:
            # Validate user exists
            cursor.execute(
                "SELECT id FROM users WHERE id = %s",
                (member_id,)
            )
            if not cursor.fetchone():
                invalid_users.append(member_id)
                continue

            # Check already member
            cursor.execute("""
                SELECT 1 FROM group_members
                WHERE group_id = %s AND user_id = %s
            """, (data.group_id, member_id))
            if cursor.fetchone():
                skipped_users.append(member_id)
                continue

            # Insert member
            cursor.execute("""
                INSERT INTO group_members (group_id, user_id)
                VALUES (%s, %s)
            """, (data.group_id, member_id))

            added_users.append(member_id)

        conn.commit()

        return response(
            True,
            "Members processed successfully",
            {
                "group_id": data.group_id,
                "added_user_ids": added_users,
                "skipped_user_ids": skipped_users,
                "invalid_user_ids": invalid_users
            },
            200
        )

    except Exception as e:
        conn.rollback()
        return response(
            False,
            f"Failed to add members: {str(e)}",
            None,
            500
        )



from typing import List

class RemoveMembersModel(BaseModel):
    group_id: int
    user_ids: list[int]

@app.post("/groups/remove-members")
def remove_group_members(
    data: RemoveMembersModel,
    user=Depends(auth_user)
):
    # 1️⃣ Only group creator can remove members
    cursor.execute("""
        SELECT id
        FROM groups
        WHERE id = %s AND created_by = %s
    """, (data.group_id, user["id"]))

    if not cursor.fetchone():
        return response(
            False,
            "Only group creator can remove members",
            None,
            403
        )

    # 2️⃣ Creator cannot remove themselves
    if user["id"] in data.user_ids:
        return response(
            False,
            "Group creator cannot remove themselves",
            None,
            400
        )

    removed_users = []
    invalid_users = []

    for member_id in data.user_ids:
        # 3️⃣ Validate user exists
        cursor.execute(
            "SELECT id FROM users WHERE id = %s",
            (member_id,)
        )
        if not cursor.fetchone():
            invalid_users.append(member_id)
            continue

        # 4️⃣ Check membership
        cursor.execute("""
            SELECT 1 FROM group_members
            WHERE group_id = %s AND user_id = %s
        """, (data.group_id, member_id))

        if not cursor.fetchone():
            invalid_users.append(member_id)
            continue

        # 5️⃣ Remove member
        cursor.execute("""
            DELETE FROM group_members
            WHERE group_id = %s AND user_id = %s
        """, (data.group_id, member_id))

        removed_users.append(member_id)

    conn.commit()

    return response(
        True,
        "Members processed successfully",
        {
            "group_id": data.group_id,
            "removed_user_ids": removed_users,
            "invalid_user_ids": invalid_users
        },
        200
    )


class InviteMemberModel(BaseModel):
    group_id: int
    email: EmailStr

@app.post("/groups/invite-member")
def invite_member(
    data: InviteMemberModel,
    user=Depends(auth_user)
):
    # 1️⃣ Only group creator can invite
    cursor.execute("""
        SELECT group_name
        FROM groups
        WHERE id = %s AND created_by = %s
    """, (data.group_id, user["id"]))

    group_row = cursor.fetchone()
    if not group_row:
        return response(
            False,
            "Only group creator can invite members",
            None,
            403
        )

    group_name = group_row[0]

    # 2️⃣ If email already has CTS account
    cursor.execute(
        "SELECT id FROM users WHERE email = %s",
        (data.email,)
    )
    if cursor.fetchone():
        return response(
            False,
            "This email already has a CTS account. Add directly instead.",
            None,
            400
        )

    # 3️⃣ Check existing pending invite
    cursor.execute("""
        SELECT id
        FROM group_invites
        WHERE group_id = %s
          AND invited_email = %s
          AND status = 'pending'
    """, (data.group_id, data.email))

    invite_row = cursor.fetchone()
    if invite_row:
        return response(
            False,
            "Invite already pending for this email",
            {
                "invite_id": invite_row[0],
                "reinvite_allowed": True
            },
            400
        )

    # 4️⃣ Create invite
    cursor.execute("""
        INSERT INTO group_invites (group_id, invited_by, invited_email, status)
        VALUES (%s, %s, %s, 'pending')
        RETURNING id
    """, (data.group_id, user["id"], data.email))

    invite_id = cursor.fetchone()[0]
    conn.commit()

    send_invite_email(
        to_email=data.email,
        group_name=group_name,
        invited_by_name=user["name"],
        invite_id=invite_id,
    )

    return response(
        True,
        "Invitation email sent successfully",
        {
            "invite_id": invite_id,
            "email": data.email
        },
        200
    )



@app.get("/groups/{group_id}/pending-invites")
def get_pending_invites(group_id: int, user=Depends(auth_user)):

    # Only group creator can view pending invites
    cursor.execute("""
        SELECT 1 FROM groups
        WHERE id = %s AND created_by = %s
    """, (group_id, user["id"]))

    if not cursor.fetchone():
        return response(False, "Only group creator can view pending invites", None, 403)

    cursor.execute("""
        SELECT id, invited_email, created_at
        FROM group_invites
        WHERE group_id = %s AND status = 'pending'
        ORDER BY created_at DESC
    """, (group_id,))

    rows = cursor.fetchall()

    pending_invites = [
        {
            "invite_id": r[0],
            "email": r[1],
            "invited_at": r[2]
        }
        for r in rows
    ]

    return response(
        True,
        "Pending invited users fetched successfully",
        pending_invites,
        200
    )
class ReinviteModel(BaseModel):
    group_id: int
    invite_id: int

@app.post("/groups/reinvite")
def reinvite_member(
    data: ReinviteModel,
    user=Depends(auth_user)
):
    # 1️⃣ Only group creator can reinvite
    cursor.execute("""
        SELECT group_name
        FROM groups
        WHERE id = %s AND created_by = %s
    """, (data.group_id, user["id"]))

    group_row = cursor.fetchone()
    if not group_row:
        return response(
            False,
            "Only group creator can reinvite users",
            None,
            403
        )

    group_name = group_row[0]

    # 2️⃣ Fetch pending invite
    cursor.execute("""
        SELECT invited_email
        FROM group_invites
        WHERE id = %s
          AND group_id = %s
          AND status = 'pending'
    """, (data.invite_id, data.group_id))

    row = cursor.fetchone()
    if not row:
        return response(
            False,
            "Pending invite not found",
            None,
            404
        )

    invited_email = row[0]

    # 3️⃣ Send reinvite email
    send_invite_email(
        to_email=invited_email,
        group_name=group_name,
        invited_by_name=user["name"],
        invite_id=data.invite_id,
        custom_message=(
            f"You are again invited to join the group '{group_name}' "
            f"by {user['name']} on CTS."
        )
    )

    return response(
        True,
        "Invitation email resent successfully",
        {
            "invite_id": data.invite_id,
            "email": invited_email
        },
        200
    )




# -----------------------------
# PROMOTE MEMBER TO ADMIN
# -----------------------------
# @app.post("/groups/{group_id}/members/{user_id}/make-admin")
# def make_admin(group_id: int, user_id: int, user=Depends(auth_user)):

#     # requester must be admin
#     cursor.execute("""
#         SELECT role FROM group_members
#         WHERE group_id=%s AND user_id=%s
#     """, (group_id, user["id"]))
#     row = cursor.fetchone()
#     if not row or row[0] != "admin":
#         raise HTTPException(403, "Only group admins can promote members")

#     cursor.execute("""
#         UPDATE group_members
#         SET role='admin'
#         WHERE group_id=%s AND user_id=%s
#     """, (group_id, user_id))
#     conn.commit()

#     return response(
#     True,
#     "Member promoted to admin",
#     None,
#     200
#     )



# -----------------------------
# DELETE GROUP
# -----------------------------
@app.delete("/groups/{group_id}")
def delete_group(group_id: int, user=Depends(auth_user)):

    cursor.execute("""
        SELECT role FROM group_members
        WHERE group_id=%s AND user_id=%s
    """, (group_id, user["id"]))
    row = cursor.fetchone()

    if not row or row[0] != "admin":
        raise HTTPException(403, detail=response(False, "Only admins can delete the group", None, 403))

    cursor.execute("DELETE FROM group_members WHERE group_id=%s", (group_id,))
    cursor.execute("DELETE FROM group_invites WHERE group_id=%s", (group_id,))
    cursor.execute("DELETE FROM groups WHERE id=%s", (group_id,))
    conn.commit()

    return response(True, "Group deleted successfully", None,200)




from typing import List, Optional

class EditGroupMemberModel(BaseModel):
    user_id: int
    remove: bool = False



class UpdateGroupModel(BaseModel):
    group_id: int
    group_name: str | None = None
    group_description: str | None = None
    group_icon_base64: str | None = None
    members: list[EditGroupMemberModel] | None = None



@app.put("/groups/edit")
def edit_group(
    data: UpdateGroupModel,
    user=Depends(auth_user)
):
    # 1️⃣ Only group creator can edit
    cursor.execute("""
        SELECT id
        FROM groups
        WHERE id = %s AND created_by = %s
    """, (data.group_id, user["id"]))

    if not cursor.fetchone():
        return response(
            False,
            "Only group creator can edit this group",
            None,
            403
        )

    try:
        # -------------------------------
        # 2️⃣ Update group details
        # -------------------------------
        fields = []
        params = []

        if data.group_name is not None:
            fields.append("group_name = %s")
            params.append(data.group_name)

        if data.group_description is not None:
            fields.append("group_description = %s")
            params.append(data.group_description)

        if data.group_icon_base64:
            group_icon_path = save_base64_image(
                data.group_icon_base64,
                subdir="groups"
            )
            fields.append("group_icon = %s")
            params.append(group_icon_path)

        if fields:
            params.append(data.group_id)
            query = "UPDATE groups SET " + ", ".join(fields) + " WHERE id = %s"
            cursor.execute(query, tuple(params))

        # -------------------------------
        # 3️⃣ Remove members (if requested)
        # -------------------------------
        if data.members:
            for m in data.members:
                if m.remove:
                    cursor.execute("""
                        DELETE FROM group_members
                        WHERE group_id = %s AND user_id = %s
                    """, (data.group_id, m.user_id))

        conn.commit()

    except Exception as e:
        conn.rollback()
        raise HTTPException(500, f"Error while editing group: {e}")

    # -------------------------------
    # 4️⃣ Return updated group + members
    # -------------------------------
    cursor.execute("""
        SELECT id, group_name, group_description, group_icon
        FROM groups
        WHERE id = %s
    """, (data.group_id,))
    g = cursor.fetchone()

    cursor.execute("""
        SELECT u.id, u.name, u.email, u.profile_image
        FROM group_members gm
        JOIN users u ON u.id = gm.user_id
        WHERE gm.group_id = %s
    """, (data.group_id,))
    rows = cursor.fetchall()

    members = [
        {
            "user_id": r[0],
            "display_name": r[1],
            "email": r[2],
            "profile_image": r[3],
        }
        for r in rows
    ]

    return response(
        True,
        "Group updated successfully",
        {
            "group_id": g[0],
            "group_name": g[1],
            "group_description": g[2],
            "group_icon": g[3],
            "members": members,
        },
        200
    )


class ExitGroupModel(BaseModel):
    group_id: int


@app.post("/groups/exit")
def exit_group(
    data: ExitGroupModel,
    user=Depends(auth_user)
):
    # 1️⃣ Check membership
    cursor.execute("""
        SELECT 1
        FROM group_members
        WHERE group_id = %s AND user_id = %s
    """, (data.group_id, user["id"]))

    if not cursor.fetchone():
        return response(
            False,
            "You are not a member of this group",
            None,
            400
        )

    # 2️⃣ Check if user is group creator
    cursor.execute("""
        SELECT created_by
        FROM groups
        WHERE id = %s
    """, (data.group_id,))
    group_row = cursor.fetchone()

    if not group_row:
        return response(
            False,
            "Group not found",
            None,
            404
        )

    created_by = group_row[0]

    # 3️⃣ If creator → ensure no other members exist
    if created_by == user["id"]:
        cursor.execute("""
            SELECT COUNT(*)
            FROM group_members
            WHERE group_id = %s
        """, (data.group_id,))
        member_count = cursor.fetchone()[0]

        if member_count > 1:
            return response(
                False,
                "Group creator cannot exit while other members exist",
                None,
                400
            )

    # 4️⃣ Remove membership
    cursor.execute("""
        DELETE FROM group_members
        WHERE group_id = %s AND user_id = %s
    """, (data.group_id, user["id"]))

    conn.commit()

    return response(
        True,
        "You have exited the group successfully",
        None,
        200
    )



# @app.get("/notifications")
# def get_notifications(user=Depends(auth_user)):
#     notifications = []
 
#     # -------------------------------------------------
#     # 1️⃣ GROUP INVITE NOTIFICATIONS
#     # -------------------------------------------------
#     cursor.execute("""
#         SELECT
#             gi.id,
#             gi.group_id,
#             g.group_name,
#             gi.invited_by,
#             gi.created_at
#         FROM group_invites gi
#         JOIN groups g ON g.id = gi.group_id
#         WHERE gi.invited_email = %s
#           AND gi.status = 'pending'
#         ORDER BY gi.created_at DESC
#     """, (user["email"],))
 
#     invite_rows = cursor.fetchall()
 
#     for r in invite_rows:
#         invite_id = r[0]
#         group_id = r[1]
#         group_name = r[2]
#         inviter_id = r[3]
#         created_at = r[4]
 
#         # 🔒 Fetch inviter name + profile image
#         cursor.execute(
#             "SELECT name, profile_image FROM users WHERE id = %s",
#             (inviter_id,)
#         )
#         inviter_row = cursor.fetchone()
#         inviter_name = inviter_row[0] if inviter_row else "Unknown User"
#         inviter_profile_image = inviter_row[1] if inviter_row else None
 
#         notifications.append({
#             # 🔑 EXISTING KEYS (UNCHANGED)
#             "invite_id": invite_id,
#             "group_id": group_id,
#             "group_name": group_name,
#             "invited_by": inviter_name,
#             "created_at": created_at,
 
#             # ➕ ADDED (SAFE)
#             "profile_image": inviter_profile_image,
 
#             # ➕ EXTRA KEYS (SAFE)
#             "type": "invite",
#             "text_message": f"You were invited to join {group_name} by {inviter_name}"
#         })
 
#     # -------------------------------------------------
#     # 2️⃣ SYSTEM / AVAILABILITY NOTIFICATIONS
#     # -------------------------------------------------
#     cursor.execute("""
#         SELECT
#             n.id,
#             n.type,
#             n.message,
#             n.created_at,
#             n.reference_id,
#             u.profile_image
#         FROM notifications n
#         LEFT JOIN users u ON u.id = n.reference_id
#         WHERE n.user_id = %s
#         ORDER BY n.created_at DESC
#     """, (user["id"],))
 
#     system_rows = cursor.fetchall()
 
#     for r in system_rows:
#         notifications.append({
#             # 🔑 EXISTING KEYS (UNCHANGED)
#             "created_at": r[3],
 
#             # ➕ ADDED (SAFE)
#             "profile_image": r[5],
 
#             # ➕ EXTRA KEYS
#             "type": r[1],
#             "text_message": r[2]
#         })
 
#     # -------------------------------------------------
#     # 3️⃣ SORT ALL NOTIFICATIONS (LATEST FIRST)
#     # -------------------------------------------------
#     notifications.sort(
#         key=lambda x: x["created_at"],
#         reverse=True
#     )
 
#     return response(
#         True,
#         "Notifications fetched successfully",
#         notifications,
#         200
#     )



@app.get("/notifications")
def get_notifications(user=Depends(auth_user)):
    cursor.execute("""
        SELECT 
            gi.id AS invite_id,
            g.id AS group_id,
            g.group_name,
            g.group_icon,
            u.name AS invited_by_name,
            gi.created_at
        FROM group_invites gi
        JOIN groups g ON g.id = gi.group_id
        JOIN users u ON u.id = gi.invited_by
        WHERE gi.invited_email = %s
          AND gi.status = 'pending'
        ORDER BY gi.created_at DESC
    """, (user["email"],))

    rows = cursor.fetchall()

    notifications = [
        {
            "invite_id": r[0],
            "group_id": r[1],
            "group_name": r[2],
            "group_icon":r[3],
            "invited_by": r[4],
            "created_at": r[5]
        }
        for r in rows
    ]

    return response(
        True,
        "Notifications fetched successfully",
        notifications,
        200
    )
class NotificationInviteActionModel(BaseModel):
    invite_id: int

@app.post("/notifications/accept")
def accept_notification_invite(
    data: NotificationInviteActionModel,
    user=Depends(auth_user)
):
    cursor.execute("""
        SELECT group_id, invited_email, status
        FROM group_invites
        WHERE id = %s
    """, (data.invite_id,))
    invite = cursor.fetchone()

    if not invite:
        return response(
            False,
            "Invite not found",
            None,
            404
        )

    group_id, invited_email, status = invite

    if invited_email.lower() != user["email"].lower():
        return response(
            False,
            "This invite is not for you",
            None,
            403
        )

    if status != "pending":
        return response(
            False,
            f"Invite already {status}",
            None,
            400
        )

    # Add user to group
    cursor.execute("""
        INSERT INTO group_members (group_id, user_id)
        VALUES (%s, %s)
        ON CONFLICT DO NOTHING
    """, (group_id, user["id"]))

    # Update invite status
    cursor.execute("""
        UPDATE group_invites
        SET status = 'accepted',
            invited_user_id = %s
        WHERE id = %s
    """, (user["id"], data.invite_id))

    conn.commit()

    return response(
        True,
        "Invitation accepted successfully",
        None,
        200
    )


class NotificationInviteActionModel(BaseModel):
    invite_id: int

@app.post("/notifications/reject")
def reject_notification_invite(
    data: NotificationInviteActionModel,
    user=Depends(auth_user)
):
    cursor.execute("""
        SELECT invited_email, status
        FROM group_invites
        WHERE id = %s
    """, (data.invite_id,))
    invite = cursor.fetchone()

    if not invite:
        return response(
            False,
            "Invite not found",
            None,
            404
        )
    invited_email, status = invite

    if invited_email.lower() != user["email"].lower():
        return response(
            False,
            "This invite is not for you",
            None,
            403
        )

    if status != "pending":
        return response(
            False,
            f"Invite already {status}",
            None,
            400
        )

    cursor.execute("""
        UPDATE group_invites
        SET status = 'rejected'
        WHERE id = %s
    """, (data.invite_id,))

    conn.commit()

    return response(
        True,
        "Invitation rejected successfully",
        None,
        200
    )

class UpdateStatusModel(BaseModel):
    status: str  # available | busy | dnd

# @app.put("/user/status")
# def update_user_status(data: UpdateStatusModel, user=Depends(auth_user)):
#     try:
#         # normalize + validate
#         raw_status = data.status
#         status_map = {
#             0: "available",
#             1: "busy",
#             2: "dnd",
#             "available": "available",
#             "busy": "busy",
#             "dnd": "dnd",
#             "do not disturb": "dnd"
#         }

#         if isinstance(raw_status, str):
#             raw_status = raw_status.strip().lower()

#         if raw_status not in status_map:
#             return response(False, "Invalid status", None, 400)

#         status_str = status_map[raw_status]

#         # upsert status
#         cursor.execute("""
#             INSERT INTO user_status (user_id, status)
#             VALUES (%s, %s)
#             ON CONFLICT (user_id)
#             DO UPDATE SET status = EXCLUDED.status,
#                           updated_at = CURRENT_TIMESTAMP
#         """, (user["id"], status_str))

#         # notify only if available
#         if status_str == "available":
#             cursor.execute("""
#                 SELECT DISTINCT gm2.user_id
#                 FROM group_members gm1
#                 JOIN group_members gm2
#                   ON gm1.group_id = gm2.group_id
#                 WHERE gm1.user_id = %s
#                   AND gm2.user_id != %s
#             """, (user["id"], user["id"]))

#             members = cursor.fetchall()
#             message = f"{user['email']} is now available"

#             for (member_id,) in members:
#                 cursor.execute("""
#                     INSERT INTO notifications (user_id, type, reference_id, message)
#                     VALUES (%s, 'availability', %s, %s)
#                 """, (member_id, user["id"], message))

#         conn.commit()

#         return response(True, "Status updated successfully", None, 200)

#     except Exception as e:
#         conn.rollback()  # 🔥 THIS FIXES YOUR ERROR
#         return response(False, f"DB error: {str(e)}", None, 500)

def send_status_change_email(to_email: str, user_email: str):
    msg = EmailMessage()
    msg["Subject"] = "User Availability Update"
    msg["From"] = MAIL_FROM
    msg["To"] = to_email
 
    msg.set_content(
        f"""
Hello,
 
{user_email} is now AVAILABLE.
 
Regards,
CTS Team
"""
    )
 
    with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
        server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.send_message(msg)
 
@app.put("/user/status")
def update_user_status(data: UpdateStatusModel, user=Depends(auth_user)):
    try:
        # 1️⃣ Normalize + validate
        raw_status = data.status
 
        status_map = {
            0: "available",
            1: "busy",
            2: "dnd",
            "available": "available",
            "busy": "busy",
            "dnd": "dnd",
            "do not disturb": "dnd"
        }
 
        if isinstance(raw_status, str):
            raw_status = raw_status.strip().lower()
 
        if raw_status not in status_map:
            return response(False, "Invalid status", None, 400)
 
        status_str = status_map[raw_status]
 
        # 2️⃣ Get previous status
        cursor.execute(
            "SELECT status FROM user_status WHERE user_id=%s",
            (user["id"],)
        )
        row = cursor.fetchone()
        previous_status = row[0] if row else None
 
        # 3️⃣ Upsert status
        cursor.execute("""
            INSERT INTO user_status (user_id, status)
            VALUES (%s, %s)
            ON CONFLICT (user_id)
            DO UPDATE SET
                status = EXCLUDED.status,
                updated_at = CURRENT_TIMESTAMP
        """, (user["id"], status_str))
 
        conn.commit()  # ✅ commit first
 
        # 4️⃣ Only when status changes TO available
        if status_str == "available" and previous_status != "available":
 
            cursor.execute("""
                SELECT DISTINCT u.id, u.email
                FROM group_members gm1
                JOIN group_members gm2
                  ON gm1.group_id = gm2.group_id
                JOIN users u
                  ON u.id = gm2.user_id
                WHERE gm1.user_id = %s
                  AND gm2.user_id != %s
            """, (user["id"], user["id"]))
 
            members = cursor.fetchall()
 
            message = f"{user['email']} is now available"
 
            for member_id, email in members:
                # 🔔 INSERT IN-APP NOTIFICATION
                cursor.execute("""
                    INSERT INTO notifications (user_id, type, reference_id, message)
                    VALUES (%s, 'availability', %s, %s)
                """, (member_id, user["id"], message))
 
                # 📩 SEND EMAIL (non-blocking)
                try:
                    send_status_change_email(
                        to_email=email,
                        user_email=user["email"]
                    )
                except Exception as mail_err:
                    print(f"Email failed for {email}: {mail_err}")
 
            conn.commit()  # commit notifications
 
        return response(
            True,
            "Status updated successfully",
            {"status": status_str},
            200
        )
 
    except Exception as e:
        conn.rollback()
        return response(False, f"DB error: {str(e)}", None, 500)

@app.get("/user/status")
def get_user_status(user=Depends(auth_user)):
    cursor.execute("""
        SELECT status
        FROM user_status
        WHERE user_id = %s
    """, (user["id"],))

    row = cursor.fetchone()

    return response(
        True,
        "Status fetched successfully",
        {"status": row[0] if row else "available"},
        200
    )


from pydantic import BaseModel
from typing import Optional
 
class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    profile_image_base64: Optional[str] = None
 
import os
 
def delete_file_if_exists(path: str):
    if path and os.path.exists(path):
        os.remove(path)
 
 
@app.put("/profile/update")
def update_profile(data: UpdateProfileRequest, user=Depends(auth_user)):
 
    if data.name is None and data.profile_image_base64 is None:
        return response(False, "No fields provided to update", None, 400)
 
    try:
        # Fetch existing profile image
        cursor.execute(
            "SELECT profile_image FROM users WHERE id=%s",
            (user["id"],)
        )
        row = cursor.fetchone()
        existing_image = row[0] if row else None
 
        update_fields = []
        values = []
 
        # 1️⃣ Update name
        if data.name is not None:
            update_fields.append("name = %s")
            values.append(data.name)
 
        # 2️⃣ Profile image logic
        if data.profile_image_base64 is not None:
 
            # CASE A: Delete profile image
            if data.profile_image_base64.strip() == "":
                if existing_image:
                    delete_file_if_exists(existing_image)
 
                update_fields.append("profile_image = NULL")
 
            # CASE B: Upload new profile image
            else:
                new_image_path = save_base64_image(
                    data.profile_image_base64,
                    subdir="users"
                )
 
                # delete old image
                if existing_image:
                    delete_file_if_exists(existing_image)
 
                update_fields.append("profile_image = %s")
                values.append(new_image_path)
 
        if not update_fields:
            return response(False, "Nothing to update", None, 400)
 
        query = f"""
            UPDATE users
            SET {', '.join(update_fields)}
            WHERE id = %s
        """
        values.append(user["id"])
 
        cursor.execute(query, tuple(values))
        conn.commit()
 
        # Fetch updated profile
        cursor.execute("""
            SELECT name, email, profile_image
            FROM users
            WHERE id = %s
        """, (user["id"],))
        updated = cursor.fetchone()
 
        return response(
            True,
            "Profile updated successfully",
            {
                "name": updated[0],
                "email": updated[1],
                "profile_image": updated[2]
            },
            200
        )
 
    except Exception as e:
        conn.rollback()
        return response(
            False,
            f"Failed to update profile: {str(e)}",
            None,
            500
        )
 
 
class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str
 
@app.put("/profile/change-password")
def change_password(data: ChangePasswordRequest, user=Depends(auth_user)):
 
    # 1️⃣ New & confirm password check
    if data.new_password != data.confirm_password:
        return response(False, "New password and confirm password do not match", None, 400)
 
    # 2️⃣ Fetch current password hash
    cursor.execute("""
        SELECT password
        FROM users
        WHERE id = %s
    """, (user["id"],))
    row = cursor.fetchone()
 
    if not row:
        return response(False, "User not found", None, 404)
 
    stored_password_hash = row[0]
 
    # 3️⃣ Validate old password
    if not pwd_context.verify(data.old_password, stored_password_hash):
        return response(False, "Old password is incorrect", None, 400)
 
    # 4️⃣ Prevent same password reuse
    if pwd_context.verify(data.new_password, stored_password_hash):
        return response(False, "New password cannot be same as old password", None, 400)
 
    # 5️⃣ Hash new password
    new_hashed_password = pwd_context.hash(data.new_password)
 
    try:
        cursor.execute("""
            UPDATE users
            SET password = %s
            WHERE id = %s
        """, (new_hashed_password, user["id"]))
        conn.commit()
    except Exception as e:
        conn.rollback()
        return response(False, f"Failed to change password: {str(e)}", None, 500)
 
    return response(
        True,
        "Password changed successfully",
        None,
        200
    )
 
 
class MarkReadModel(BaseModel):
    notification_id: int


@app.post("/notifications/read")
def mark_notification_read(
    data: MarkReadModel,
    user=Depends(auth_user)
):
    cursor.execute("""
        UPDATE notifications
        SET is_read = TRUE
        WHERE id = %s AND user_id = %s
    """, (data.notification_id, user["id"]))

    conn.commit()

    return response(
        True,
        "Notification marked as read",
        None,
        200
    )




@app.get("/user/availability")
def get_availability(user=Depends(auth_user)):
    cursor.execute("""
        SELECT id, from_time, to_time
        FROM user_availability
        WHERE user_id = %s
        ORDER BY from_time
    """, (user["id"],))

    rows = cursor.fetchall()

    availability = [
        {
            "id": r[0],
            "from_time": str(r[1]),
            "to_time": str(r[2])
        }
        for r in rows
    ]

    return response(
        True,
        "Availability fetched successfully",
        availability,
        200
    )

class SetAvailabilityModel(BaseModel):
    from_time: str   # "12:00"
    to_time: str     # "13:00"


def send_availability_email(to_email: str, message: str):
    subject = "User Availability Update"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM
    msg["To"] = to_email
    msg.set_content(message)

    with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as s:
        s.starttls()
        s.login(MAIL_USERNAME, MAIL_PASSWORD)
        s.send_message(msg)
# @app.post("/user/availability")
# def set_user_availability(
#     data: SetAvailabilityModel,
#     user=Depends(auth_user)
# ):
#     try:
#         # -------------------------------------------------
#         # 1️⃣ Resolve user timezone (default UTC)
#         # -------------------------------------------------
#         user_tz = user.get("timezone")
#         if not isinstance(user_tz, str) or not user_tz.strip():
#             user_tz = "UTC"

#         user_timezone = pytz.timezone(user_tz)

#         # -------------------------------------------------
#         # 2️⃣ Parse local times (user timezone)
#         # -------------------------------------------------
#         today = date.today()

#         from_local = user_timezone.localize(
#             datetime.combine(
#                 today,
#                 datetime.strptime(data.from_time, "%H:%M").time()
#             )
#         )

#         to_local = user_timezone.localize(
#             datetime.combine(
#                 today,
#                 datetime.strptime(data.to_time, "%H:%M").time()
#             )
#         )

#         # Handle overnight availability (e.g. 22:00 → 02:00)
#         if to_local <= from_local:
#             to_local += timedelta(days=1)

#         # -------------------------------------------------
#         # 3️⃣ Convert to UTC (single source of truth)
#         # -------------------------------------------------
#         from_utc = from_local.astimezone(pytz.utc)
#         to_utc = to_local.astimezone(pytz.utc)

#         # -------------------------------------------------
#         # 4️⃣ Remove previous active availability
#         # -------------------------------------------------
#         cursor.execute("""
#             DELETE FROM user_availability
#             WHERE user_id = %s
#               AND available_to_utc > NOW()
#         """, (user["id"],))

#         # -------------------------------------------------
#         # 5️⃣ Insert new availability
#         # -------------------------------------------------
#         cursor.execute("""
#             INSERT INTO user_availability (
#                 user_id,
#                 from_time,
#                 to_time,
#                 available_from_utc,
#                 available_to_utc,
#                 initial_notification_sent,
#                 reminder_sent,
#                 confirmation_status,
#                 created_at,
#                 updated_at
#             )
#             VALUES (%s, %s, %s, %s, %s, FALSE, FALSE, 'PENDING', NOW(), NOW())
#         """, (
#             user["id"],
#             data.from_time,
#             data.to_time,
#             from_utc,
#             to_utc
#         ))

#         # -------------------------------------------------
#         # 6️⃣ Fetch shared group members (EMAIL ONLY)
#         # -------------------------------------------------
#         cursor.execute("""
#             SELECT DISTINCT u.id, u.email, u.timezone
#             FROM group_members gm1
#             JOIN group_members gm2 ON gm1.group_id = gm2.group_id
#             JOIN users u ON u.id = gm2.user_id
#             WHERE gm1.user_id = %s
#               AND gm2.user_id != %s
#         """, (user["id"], user["id"]))

#         members = cursor.fetchall()

#         # -------------------------------------------------
#         # 7️⃣ Send availability EMAIL (timezone-aware)
#         # -------------------------------------------------
#         for member_id, member_email, member_tz in members:
#             if not isinstance(member_tz, str) or not member_tz.strip():
#                 member_tz = "UTC"

#             member_timezone = pytz.timezone(member_tz)

#             member_from = from_utc.astimezone(member_timezone)
#             member_to = to_utc.astimezone(member_timezone)

#             message = (
#                 f"{user['email']} is available from "
#                 f"{member_from.strftime('%H:%M')} to "
#                 f"{member_to.strftime('%H:%M')} ({member_tz})"
#             )

#             send_availability_email(
#                 to_email=member_email,
#                 message=message
#             )

#         conn.commit()

#         return response(
#             True,
#             "Availability set successfully",
#             {
#                 "from_time": data.from_time,
#                 "to_time": data.to_time,
#                 "timezone": user_tz
#             },
#             200
#         )

#     except Exception as e:
#         conn.rollback()
#         return response(
#             False,
#             f"DB error: {str(e)}",
#             None,
#             500
#         )
from datetime import datetime, timedelta
import pytz

@app.post("/user/availability")
def set_user_availability(data: SetAvailabilityModel, user=Depends(auth_user)):
    try:
        # 1️⃣ Get user timezone
        cursor.execute("SELECT timezone FROM users WHERE id = %s", (user["id"],))
        user_timezone = cursor.fetchone()[0]
        tz = pytz.timezone(user_timezone)

        # 2️⃣ Parse LOCAL times from frontend
        local_from = tz.localize(
            datetime.combine(date.today(), data.from_time)
        )
        local_to = tz.localize(
            datetime.combine(date.today(), data.to_time)
        )

        # 3️⃣ Handle overnight availability (e.g. 22:00 → 02:00)
        if local_to <= local_from:
            local_to += timedelta(days=1)

        # 4️⃣ Convert LOCAL → UTC (🔥 THIS IS THE FIX 🔥)
        available_from_utc = local_from.astimezone(pytz.UTC)
        available_to_utc = local_to.astimezone(pytz.UTC)

        # 5️⃣ Remove previous availability
        cursor.execute("""
            DELETE FROM user_availability WHERE user_id = %s
        """, (user["id"],))

        # 6️⃣ Insert availability (UTC only)
        cursor.execute("""
            INSERT INTO user_availability (
                user_id,
                from_time,
                to_time,
                available_from_utc,
                available_to_utc
            )
            VALUES (%s, %s, %s, %s, %s)
        """, (
            user["id"],
            data.from_time,
            data.to_time,
            available_from_utc,
            available_to_utc
        ))

        conn.commit()
        return response(True, "Availability set successfully")

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))



from email.message import EmailMessage
import smtplib

def send_email(to_email: str, subject: str, body: str):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM
    msg["To"] = to_email
    msg.set_content(body)

    with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as s:
        s.starttls()
        s.login(MAIL_USERNAME, MAIL_PASSWORD)
        s.send_message(msg)


from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
import pytz

scheduler = BackgroundScheduler(timezone=pytz.utc)

def send_availability_notifications():
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                ua.id,
                ua.user_id,
                ua.available_from_utc,
                ua.available_to_utc,
                u.email
            FROM user_availability ua
            JOIN users u ON u.id = ua.user_id
            WHERE ua.available_from_utc <= NOW()
              AND ua.initial_notification_sent = FALSE
        """)

        rows = cursor.fetchall()
        print(rows)
        if not rows:
            return

        for availability_id, user_id, from_utc, to_utc, owner_email in rows:

            cursor.execute("""
                SELECT DISTINCT u.email, u.timezone
                FROM group_members gm1
                JOIN group_members gm2 ON gm1.group_id = gm2.group_id
                JOIN users u ON u.id = gm2.user_id
                WHERE gm1.user_id = %s
                  AND gm2.user_id != %s
            """, (user_id, user_id))

            members = cursor.fetchall()

            for member_email, member_tz in members:
                tz = pytz.timezone(member_tz or "UTC")
                local_from = from_utc.astimezone(tz)
                local_to = to_utc.astimezone(tz)

                send_email(
                    member_email,
                    "User Availability",
                    f"{owner_email} is available from "
                    f"{local_from.strftime('%H:%M')} to "
                    f"{local_to.strftime('%H:%M')} ({member_tz or 'UTC'})"
                )

            cursor.execute("""
                UPDATE user_availability
                SET initial_notification_sent = TRUE
                WHERE id = %s
            """, (availability_id,))

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("❌ Availability notification error:", e)

def send_availability_reminders():
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                ua.id,
                u.email,
                ua.available_from_utc
            FROM user_availability ua
            JOIN users u ON u.id = ua.user_id
            WHERE ua.reminder_sent = FALSE
              AND (ua.available_from_utc - INTERVAL '5 minutes')
                  <= (NOW() AT TIME ZONE 'UTC')
              AND ua.available_from_utc > (NOW() AT TIME ZONE 'UTC')
        """)

        rows = cursor.fetchall()
        print("🔔 Reminder candidates:", rows)

        for availability_id, email, start_time in rows:
            send_email(
                email,
                "Availability Reminder",
                "Your availability starts in 5 minutes."
            )

            cursor.execute("""
                UPDATE user_availability
                SET reminder_sent = TRUE
                WHERE id = %s
            """, (availability_id,))

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("❌ Availability reminder error:", e)




# def auto_decline_availability():
#     try:
#         cursor.execute("""
#             SELECT
#                 ua.id,
#                 ua.user_id,
#                 u.email
#             FROM user_availability ua
#             JOIN users u ON u.id = ua.user_id
#             WHERE ua.available_from_utc <= NOW()
#               AND ua.confirmation_status = 'PENDING'
#               AND ua.auto_declined = FALSE
#         """)

#         rows = cursor.fetchall()
#         if not rows:
#             return

#         for availability_id, user_id, owner_email in rows:

#             cursor.execute("""
#                 UPDATE user_availability
#                 SET confirmation_status = 'AUTO_DECLINED',
#                     auto_declined = TRUE
#                 WHERE id = %s
#             """, (availability_id,))

#             cursor.execute("""
#                 SELECT DISTINCT u.email
#                 FROM group_members gm1
#                 JOIN group_members gm2 ON gm1.group_id = gm2.group_id
#                 JOIN users u ON u.id = gm2.user_id
#                 WHERE gm1.user_id = %s
#                   AND gm2.user_id != %s
#             """, (user_id, user_id))

#             members = cursor.fetchall()

#             for (member_email,) in members:
#                 send_email(
#                     member_email,
#                     "Availability Update",
#                     f"{owner_email} did not confirm availability."
#                 )

#         conn.commit()

#     except Exception as e:
#         conn.rollback()
#         print("❌ Auto decline error:", e)









scheduler.add_job(send_availability_notifications, "interval", minutes=1)
scheduler.add_job(send_availability_reminders, "interval", minutes=1)
# scheduler.add_job(auto_decline_availability, "interval", minutes=1)
scheduler.start()


class ConfirmAvailabilityModel(BaseModel):
    availability_id: int
    confirm: bool

@app.post("/user/availability/confirm")
def confirm_availability(data: ConfirmAvailabilityModel, user=Depends(auth_user)):
    cursor.execute("""
        SELECT user_id FROM user_availability WHERE id = %s
    """, (data.availability_id,))
    row = cursor.fetchone()

    if not row or row[0] != user["id"]:
        return response(False, "Unauthorized", None, 403)

    status = "CONFIRMED" if data.confirm else "DECLINED"

    cursor.execute("""
        UPDATE user_availability
        SET confirmation_status = %s,
            confirmation_responded_at = NOW()
        WHERE id = %s
    """, (status, data.availability_id))

    conn.commit()

    return response(True, "Availability updated", None, 200)

