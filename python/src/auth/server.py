import jwt, datetime, os
from flask import Flask, request
from flask_mysqldb import MySQL

server = Flask(__name__)
mysql = MySQL(server)

# config
server.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
server.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
server.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
server.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
server.config['MYSQL_PORT'] = os.getenv('MYSQL_PORT')


@server.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth:
        return 'Missing authorization header.', 401

    # check db for username and password
    cur = mysql.connection.cursor()
    res = cur.execute(
        'SELECT email, password FROM user WHERE email = %s', (auth.username,)
    )

    if res > 0:
        user_row = cur.fetchone()
        email = user_row[0]
        password = user_row[1]

        if auth.username == email and auth.password == password:
            return create_jwt(auth.username, os.environ.get('JWT_SECRET'), True)
        else:
            return 'Invalid username or password.', 401

    else:
        return 'Invalid authorization header.', 401


def create_jwt(username, secret, isAdmin=False):
    return jwt.encode(
        {
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
            'iat': datetime.datetime.utcnow(),
            'isAdmin': isAdmin
        },
        secret,
        algorithm='HS256'
    )


@server.route('/validate', methods=['POST'])
def validate():
    encoded_jwt = request.headers['Authorization']

    if not encoded_jwt:
        return 'Missing authorization header.', 401

    encoded_jwt = encoded_jwt.split(' ')[1]

    try:
        decoded_jwt = jwt.decode(encoded_jwt, os.environ.get('jwt_secret'), algorithms=['HS256'])
    except:
        return 'Not authorized.', 403

    return decoded_jwt, 200


if __name__ == '__main__':
    server.run(host='0.0.0.0', port=5000)
