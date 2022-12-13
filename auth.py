import sqlite3
import bcrypt
import string

# Primary conditions for name
# Not Empty
# Maximum 255 characters

# Primary conditions for email
# Not Empty
# Maximum 255 characters
# Must contains @

# Primary conditions for password
# Minimum 8 characters
# Maximum 255 characters
# The alphabet must be between [a-z]
# At least one alphabet should be [A-Z]
# At least one number or digit between [0-9]
# At least one special character from [!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~]

# Remarks
# Current email validation only cover small cases and should not be used for serious case.

class Auth:
    conn: sqlite3.Connection = None

    def __init__(self) -> None:
        # Initialize database and schema
        self.conn = sqlite3.Connection("database.sqlite3")
        cur = self.conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users(
			name TEXT NOT NULL,
			email TEXT NOT NULL,
			password TEXT NOT NULL,
            PRIMARY KEY (email)
        )""")

    def login(self, email: str, password: str) -> tuple[tuple[str, str, str], str]:
        res = self.conn.cursor().execute("SELECT name, email, password FROM users WHERE email = ? LIMIT 1", (email, ))
        user = res.fetchone()
        if not user:
            # wrong email but do not show sensitive information to user
            return (("", "", ""), "invalid credentials")
        name, email, hashed = user
        if not bcrypt.checkpw(bytes(password, "utf-8"), hashed):
            # wrong password but do not show sensitive information to user
            return (("", "", ""), "invalid credentials")

        return ((name, email, hashed), "")

    def signup(self, name: str, email: str, password: str) -> dict[str, any]:
        def validateName(value: str) -> list[str]:
            errors = list()

            if len(value) <= 0:
                errors.append("is required")
            if len(value) > 255:
                errors.append("must be at most 255 characters")
            
            return errors
        
        def validateEmail(value: str, conn: sqlite3.Connection) -> list[str]:
            errors = list()
            
            if len(value) <= 0:
                errors.append("is required")
            if len(value) > 255:
                errors.append("must be at most 255 characters")
            if value.count("@") < 1:
                errors.append("invalid email address")
            res = conn.cursor().execute("SELECT EXISTS (SELECT 1 FROM users WHERE email = ? LIMIT 1)", (value,))
            exists, = res.fetchone()
            if exists:
                errors.append("already exists")

            return errors

        def validatePassword(value: str) -> list[str]:
            errors = list()

            lower = 0
            upper = 0
            digit = 0
            specialChar = 0
            for i in value:
                if (i.islower()):
                    lower += 1
                if (i.isupper()):
                    upper += 1
                if (i.isdigit()):
                    digit += 1
                if (i in string.punctuation):
                    specialChar += 1
                # not using built-in function
                # if (i in string.ascii_lowercase):
                #     lower += 1
                # if (i in string.ascii_uppercase):
                #     upper += 1
                # if (i in string.digits):
                #     digit += 1
                # if (i in string.punctuation):
                #     specialChar += 1

            total = lower + upper + digit + specialChar
            if total <= 0:
                errors.append("is required")
            if total > 255:
                errors.append("must be at most 255 characters")
            if upper < 1:
                errors.append("must contains at least one uppercase alphabet")
            if digit < 1:
                errors.append("must contains at least one number or digit")
            if specialChar < 1:
                errors.append("""must contains at least one special character from !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~""")

            return errors

        def insert(conn: sqlite3.Connection, name: str, email: str, password: str) -> None:
            hashed = bcrypt.hashpw(bytes(password, "utf-8"), bcrypt.gensalt())
            conn.cursor().execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed))
            conn.commit()
        # basic normalization
        name, email, password = name.strip(), email.strip(), password.strip()
        errors = dict()
        errors["name"] = validateName(name)
        errors["email"] = validateEmail(email, self.conn)
        errors["password"] = validatePassword(password)

        if not errors["name"] and not errors["email"] and not errors["password"]:
            insert(self.conn, name, email, password)

        return errors

        