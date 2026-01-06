import os
import json
import datetime
import requests
import jwt
import tornado.ioloop
import tornado.web
import asyncpg

# ===================== ENV VARIABLES =====================
DATABASE_URL = os.environ.get("DATABASE_URL")
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret")
RAPIDAPI_KEY = os.environ.get("RAPIDAPI_KEY")

# ===================== JWT =====================
ALGORITHM = "HS256"

def create_jwt(payload):
    payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

def verify_jwt(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        return {"status": "Session expired, please login again"}
    except jwt.InvalidTokenError:
        return {"status": "Invalid token"}

# ===================== HANDLERS =====================
class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type"
        )
        self.set_header(
            "Access-Control-Allow-Methods",
            "POST, GET, OPTIONS"
        )

    def options(self):
        self.set_status(204)
        self.finish()


class Register(BaseHandler):
    async def post(self):
        data = json.loads(self.request.body)
        student_id = data.get("id")
        name = data.get("name")
        password = data.get("password")

        pool = self.application.db
        async with pool.acquire() as conn:
            existing = await conn.fetchrow(
                "SELECT id FROM student_details WHERE id=$1",
                student_id
            )
            if existing:
                self.write({"status": "User already exists"})
                return

            await conn.execute(
                "INSERT INTO student_details VALUES ($1, $2, $3)",
                student_id, name, password
            )

        self.write({"status": "Registered successfully"})


class Login(BaseHandler):
    async def post(self):
        data = json.loads(self.request.body)
        student_id = data.get("id")
        password = data.get("password")

        pool = self.application.db
        async with pool.acquire() as conn:
            user = await conn.fetchrow(
                "SELECT * FROM student_details WHERE id=$1",
                student_id
            )

        if not user:
            self.write({"status": "User not found"})
            return

        if password != user["password"]:
            self.write({"status": "Wrong username or password"})
            return

        token = create_jwt({"id": student_id, "name": user["name"]})
        self.write({"token": token, "status": "Token generated"})


class MainHandler(BaseHandler):
    async def post(self):
        auth_header = self.request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            self.write({"status": "Authorization token missing"})
            return

        token = auth_header.split(" ")[1]
        result = verify_jwt(token)

        if "status" in result:
            self.write(result)
            return

        data = json.loads(self.request.body)
        month = data.get("month")
        day = data.get("day")

        url = f"https://numbersapi.p.rapidapi.com/{month}/{day}/date"
        headers = {
            "x-rapidapi-key": RAPIDAPI_KEY,
            "x-rapidapi-host": "numbersapi.p.rapidapi.com"
        }

        response = requests.get(url, headers=headers)
        self.write({"result": response.text})


# ===================== APP =====================
def make_app(db_pool):
    app = tornado.web.Application([
        (r"/", MainHandler),
        (r"/register", Register),
        (r"/login", Login),
    ])
    app.db = db_pool
    return app


# ===================== SERVER =====================
async def main():
    if not DATABASE_URL:
        raise Exception("DATABASE_URL not set")

    port = int(os.environ.get("PORT", 8888))

    db_pool = await asyncpg.create_pool(DATABASE_URL)
    app = make_app(db_pool)

    app.listen(port)
    print(f"Server running on port {port}")

    await tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
