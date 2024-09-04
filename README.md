# pg_simple_auth

A lightweight and easy-to-integrate authentication module for asynchronous Python applications using PostgreSQL and Quart. `pg_simple_auth` offers essential user authentication features such as signup, login, email verification, and password management, all built on secure and modern standards.

## Features

- **Asynchronous Design:** Fully asynchronous using `asyncio` and `asyncpg` to ensure non-blocking I/O operations.
- **Seamless Integration:** Designed to work effortlessly with the Quart ASGI web framework.
- **Secure Password Management:** Passwords are securely hashed using `argon2`, one of the most secure hashing algorithms available.
- **JWT-Based Authentication:** Implements JSON Web Tokens (JWT) for stateless, secure user authentication.
- **Built-in Email Verification:** Provides token-based email verification out of the box to ensure user identity.

pg_simple_auth lets you choose your framework, email sender, and app server while staying simple and easy to understand.

## Installation

Install the necessary dependencies via pip:

```sh
pip install pg_simple_auth
```

## Usage

### Setting Up the Application

In your Quart application, initialize the `pg_simple_auth` module with the database configuration and secret key:

```python
from quart import Quart
import asyncpg
import pg_simple_auth as auth

app = Quart(__name__)

DATABASE_URL = "postgresql://user:password@localhost/dbname"
SECRET_KEY = "your_secret_key"
TABLE_NAME = "users"

@app.before_serving
async def setup_db():
    app.db_pool = await asyncpg.create_pool(DATABASE_URL)
    await auth.initialize(app.db_pool, SECRET_KEY, TABLE_NAME)

# Add your routes and other configurations

if __name__ == '__main__':
    app.secret_key = SECRET_KEY
    app.run()
```

### Implementing Authentication Routes

The module provides easy-to-use methods for signup, login, and user session management:

```python
@app.route('/signup', methods=['POST'])
async def signup():
    user = ...
    password = ...
    user_info = await auth.signup(user, password)
    await auth.verify(user_info['verification_token'])
    # auto verification, you may want to send an email here
    ...

@app.route('/login', methods=['POST'])
async def login():
    user = ...
    password = ...
    await auth.login(user, password)
    user_info = await auth.login(email, password)
    if user_info:
        session['token'] = user_info['token']
    ...

@app.route('/forgot_password', methods=['POST'])
async def forgot_password():
    reset_token = await auth.forgot_password(email)
    # generate an email with the reset_token

@app.route('/change_password', methods=['GET', 'POST'])
async def change_password(token):
    ...
    if method == 'POST':
        await auth.reset_password(token, new_password)
    ...

@app.route('/signout')
async def signout():
    session.pop('token', None)
    return redirect(url_for('login'))
```

### Example

Check the `examples/1-quart.py` file in this repository for a full example of how to set up and use `pg_simple_auth` in a Quart application.

## Requirements

- Python 3.8+
- PostgreSQL 10+ (for proper `asyncpg` compatibility)
- `asyncpg` library
- `Quart` ASGI framework

## Author

Developed by [255labs.xyz](https://255labs.xyz), an AI product and consulting startup committed to helping people navigate the AI era through innovative products and open-source contributions.

## Changelog

* 09/03/24 - 0.1.1, add oauth support, `login_oauth(provider, oauth_id)` and `signup_oauth(provider, oauth_id, **insert_args)`

## Contributing

Contributions are highly encouraged! Please open an issue to discuss potential changes or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Acknowledgements

- `asyncpg` for providing a robust asynchronous PostgreSQL driver.
- The developers of `Quart` for creating an excellent ASGI framework for Python.
- The PostgreSQL community for their powerful and reliable database system.
