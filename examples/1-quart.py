from quart import Quart, request, render_template_string, session, redirect, url_for
import asyncpg
import asyncio

# Import the auth module
import pg_simple_auth as auth

app = Quart(__name__)

# Configuration for the database and JWT
DATABASE_URL = "postgresql://dev:dev@localhost/dev"
SECRET_KEY = "your_secret_key"
TABLE_NAME = "users"

@app.before_serving
async def setup_db():
    # Initialize the database pool
    app.db_pool = await asyncpg.create_pool(DATABASE_URL)
    
    # Initialize the authentication system
    await auth.initialize(app.db_pool, SECRET_KEY, TABLE_NAME)

@app.route('/signup', methods=['GET', 'POST'])
async def signup():
    if request.method == 'POST':
        data = await request.form
        email = data.get('email')
        password = data.get('password')
        
        try:
            user_info = await auth.signup(email, password)
            await auth.verify(user_info['verification_token'])
            return await render_template_string('''
                <h2>Signup Successful!</h2>
                <p>Your account has been created. Please <a href="{{ url_for('signin') }}">signin</a> now.</p>
            ''')
        except ValueError as e:
            return await render_template_string('''
                <h2>Signup</h2>
                <form method="post">
                    <p>{{ error }}</p>
                    <label>Email:</label><br>
                    <input type="email" name="email" required><br>
                    <label>Password:</label><br>
                    <input type="password" name="password" required><br><br>
                    <input type="submit" value="Sign Up">
                </form>
            ''', error=str(e))
    
    return await render_template_string('''
        <h2>Signup</h2>
        <form method="post">
            <label>Email:</label><br>
            <input type="email" name="email" required><br>
            <label>Password:</label><br>
            <input type="password" name="password" required><br><br>
            <input type="submit" value="Sign Up">
        </form>
    ''')

@app.route('/signin', methods=['GET', 'POST'])
async def signin():
    if request.method == 'POST':
        data = await request.form
        email = data.get('email')
        password = data.get('password')
        
        user = await auth.login(email, password)
        if user:
            if "error" in user:
                return await render_template_string('''
                    <h2>Signin</h2>
                    <form method="post">
                        <p>{{ error }}</p>
                        <label>Email:</label><br>
                        <input type="email" name="email" required><br>
                        <label>Password:</label><br>
                        <input type="password" name="password" required><br><br>
                        <input type="submit" value="Sign In">
                    </form>
                ''', error=user['error'])
            session['token'] = user['token']
            return redirect(url_for('welcome'))
        
        return await render_template_string('''
            <h2>Signin</h2>
            <form method="post">
                <p>Invalid credentials</p>
                <label>Email:</label><br>
                <input type="email" name="email" required><br>
                <label>Password:</label><br>
                <input type="password" name="password" required><br><br>
                <input type="submit" value="Sign In">
            </form>
        ''')
    
    return await render_template_string('''
        <h2>Signin</h2>
        <form method="post">
            <label>Email:</label><br>
            <input type="email" name="email" required><br>
            <label>Password:</label><br>
            <input type="password" name="password" required><br><br>
            <input type="submit" value="Sign In">
        </form>
    ''')

@app.route('/')
async def welcome():
    token = session.get('token')
    if not token:
        return redirect(url_for('signin'))

    user_data = auth.decode_token(token)
    if not user_data:
        return redirect(url_for('signin'))

    return await render_template_string('''
        <h2>Welcome, {{ email }}!</h2>
        <p>You are successfully signed in.</p>
        <a href="{{ url_for('signout') }}">Sign Out</a>
    ''', email=user_data['email'])

@app.route('/signout')
async def signout():
    session.pop('token', None)
    return redirect(url_for('signin'))

@app.after_serving
async def close_db():
    # Close the database pool when the app shuts down
    await app.db_pool.close()

if __name__ == '__main__':
    app.secret_key = SECRET_KEY
    app.run()
