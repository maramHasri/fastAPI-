from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
import sqlite3
import bcrypt
import jwt
import datetime
from fastapi.middleware.cors import CORSMiddleware

# إعداد التطبيق
app = FastAPI(
    title="My First API",
    description="This is my first FastAPI application with authentication",
    version="1.0.0",
    debug=True
)

# إضافة CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# مفتاح التوقيع الخاص بـ JWT (يُفضل وضعه في .env)
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"

# إعداد OAuth2 لحماية المسارات
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# قاعدة البيانات
DATABASE_URL = "users.db"

# إنشاء قاعدة البيانات للمستخدمين والعناصر
def init_db():
    try:
        conn = sqlite3.connect(DATABASE_URL)
        c = conn.cursor()
        # جدول المستخدمين
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        # جدول العناصر
        c.execute('''
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                price REAL NOT NULL,
                tax REAL
            )
        ''')
        conn.commit()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
    finally:
        conn.close()

# تهيئة قاعدة البيانات عند بدء التطبيق
init_db()

# نموذج المستخدم للتسجيل
class UserSignup(BaseModel):
    username: str
    password: str

# نموذج العناصر
class Item(BaseModel):
    name: str
    description: Optional[str] = None
    price: float
    tax: Optional[float] = None

# دالة لتشفير كلمة المرور
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

# دالة للتحقق من كلمة المرور
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# دالة لإنشاء توكن JWT
def create_jwt_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        to_encode["exp"] = datetime.datetime.utcnow() + expires_delta
    else:
        to_encode["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# نقطة نهاية لتسجيل مستخدم جديد
@app.post("/signup/")
async def signup(user: UserSignup):
    try:
        conn = sqlite3.connect(DATABASE_URL)
        c = conn.cursor()
        hashed_password = hash_password(user.password)
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user.username, hashed_password))
        conn.commit()
        conn.close()
        return {"message": "تم إنشاء الحساب بنجاح!"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="اسم المستخدم مستخدم بالفعل")

# نقطة نهاية لتسجيل الدخول والحصول على توكن
@app.post("/login/")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = sqlite3.connect(DATABASE_URL)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (form_data.username,))
    user = c.fetchone()
    conn.close()

    if user is None or not verify_password(form_data.password, user[2]):
        raise HTTPException(status_code=400, detail="اسم المستخدم أو كلمة المرور غير صحيحة")

    token = create_jwt_token({"sub": user[1]})
    return {"access_token": token, "token_type": "bearer"}

# دالة استخراج بيانات المستخدم من التوكن
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="توكن غير صالح")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="انتهت صلاحية التوكن")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="توكن غير صالح")

# نقطة نهاية محمية (مثال)
@app.get("/protected-route/")
async def protected_route(user: str = Depends(get_current_user)):
    return {"message": f"مرحباً {user}, لقد دخلت إلى منطقة محمية!"}

# نقطة نهاية GET للصفحة الرئيسية
@app.get("/")
async def root():
    return {"message": "مرحباً بك في واجهة برمجة التطبيقات الخاصة بي"}

# تشغيل التطبيق
if __name__ == "__main__":
    try:
        import uvicorn
        print("Starting the application...")
        print("Database URL:", DATABASE_URL)
        print("Server will run on http://localhost:8080")
        uvicorn.run(
            app,
            host="localhost",
            port=8080,
            log_level="info",
            reload=False  # Disable reload for stability
        )
    except Exception as e:
        print(f"Error starting the application: {e}")
        print("Please check if:")
        print("1. Port 8001 is not already in use")
        print("2. You have all required packages installed")
        print("3. You have proper permissions to run the server")
