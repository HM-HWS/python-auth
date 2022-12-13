import auth

auth = auth.Auth()

if __name__ == "__main__":
    loginOrSignup = input("0 to login, 1 to signup: ")
    if loginOrSignup == "0":
        email = input("Email: ")
        password = input("Password: ")

        user, error = auth.login(email, password)
        if error:
            print(error)
        else:
            name, email, hashed = user
            print("Hello " + name)
    elif loginOrSignup == "1":
        name = input("Name: ")
        email = input("Email: ")
        password = input("Password: ")

        errors = auth.signup(name, email, password)
        nameErrors, emailErrors, passwordErrors = errors.get("name"), errors.get("email"), errors.get("password")
        if nameErrors:
            print("Name: ", end="")
            print(nameErrors)
        if emailErrors:
            print("Email: ", end="")
            print(emailErrors)
        if (passwordErrors):
            print("Password: ", end="")
            print(passwordErrors)
    else:
        print("Good Bye")