##Pedro Ramalho nº 2019248594
##André Pinto nº 20121213497
##Bernardo Portugal nº 2021238317
## =============================================
## ============== Bases de Dados ===============
## ============== LEI  2022/2023 ===============
## =============================================
## =================ODAGORDIFY==================
## =============================================
## =============================================
## === Department of Informatics Engineering ===
## =========== University of Coimbra ===========
## =============================================

import flask
import logging
import psycopg2
import time
import jwt
from functools import wraps
from flask import request, jsonify, Response
import bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from datetime import date

app = flask.Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'secret_key'
jwt = JWTManager(app)

StatusCodes = {
    'success': 200,
    'api_error': 400,
    'internal_error': 500
}

##########################################################
## DATABASE ACCESS
##########################################################

def db_connection():
    db = psycopg2.connect(
        user='aulaspl',
        password='aulaspl',
        host='127.0.0.1',
        port='5432',
        database='bdprojeto'
    )

    return db
##########################################################
## ENDPOINTS
##########################################################

data_today = date.today()

# POST - http://localhost:8080/dbproj1/user/
# Request body - {"user_name": "Pedro Ramalho", "email": "pedroptramalho@gmail.com", "password":"password"}
@app.route('/bdprojeto/user/', methods=['POST'])
def user_registration():
    auth_header = request.headers.get('Authorization')

    if auth_header and auth_header.startswith('Bearer '):
        # Token provided in authorization header
        # Perform action for authenticated users

        token = auth_header.split()[1]
        #print(token)
        #print(decode_token(token))
        decoded_token = decode_token(token).get("sub")  # Função para decodificar o token JWT e obter os dados do user
        #print(decoded_token)
        #print(decoded_token["user_type"])

        # Verify if the user type is admin
        if decoded_token["user_type"] == "admin":
            payload = request.get_json()

            # Validation:
            if 'user_name' not in payload:
                response = {'status': StatusCodes['api_error'], 'results': 'user_name value not in payload'}
                return flask.jsonify(response)

            if 'email' not in payload:
                response = {'status': StatusCodes['api_error'], 'results': 'email value not in payload'}
                return flask.jsonify(response)

            if 'password' not in payload:
                response = {'status': StatusCodes['api_error'], 'results': 'password value not in payload'}
                return flask.jsonify(response)

            user_name = payload["user_name"]
            email = payload["email"]
            password = payload["password"]
            user_type = "artist"

            # Hash da password before storing it in the database
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            conn = db_connection()
            cur = conn.cursor()

            try:
                # Insert the user details in the table "user"
                cur.execute('INSERT INTO utilizador (user_name, email, password, user_type) VALUES (%s, %s, %s, %s)',(user_name, email, hashed_password, user_type))
                conn.commit()

                response = jsonify({'message': 'Artist successfully created'})
                response.status_code = StatusCodes['success']
                return response
            except (Exception, psycopg2.DatabaseError) as error:
                # Deal with the insertion error in the database
                response = jsonify({'message': f'Error inserting artist into database: {str(error)}'})
                response.status_code = StatusCodes['internal_error']
                return response
            finally:
                if conn is not None:
                    conn.close()

        else:
            response = jsonify({'message': 'Cant add an artist because you are not an admin'})
            response.status_code = StatusCodes['api_error']
            return response

    else:
        # Token não fornecido
        # Execute the action for the not autenticated users
        payload = request.get_json()

        # Validation for each not null argument:
        if 'user_name' not in payload:
            response = {'status': StatusCodes['api_error'], 'results': 'user_name value not in payload'}
            return flask.jsonify(response)

        if 'email' not in payload:
            response = {'status': StatusCodes['api_error'], 'results': 'email value not in payload'}
            return flask.jsonify(response)

        if 'password' not in payload:
            response = {'status': StatusCodes['api_error'], 'results': 'password value not in payload'}
            return flask.jsonify(response)

        user_name = payload["user_name"]
        email = payload["email"]
        password = payload["password"]
        user_type ="regular"

        # Hash da password antes de armazená-la na base de dados
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = db_connection()
        cur = conn.cursor()
        try:
            cur.execute('INSERT INTO utilizador (user_name, email, password, user_type) VALUES (%s, %s, %s, %s)',
                        (user_name, email, hashed_password, user_type))
            conn.commit()

            response = jsonify({'message': 'Regular user successfully created'})
            response.status_code = StatusCodes['success']
            return response
        except (Exception, psycopg2.DatabaseError) as error:
            conn.rollback()
            response = jsonify({'message': f'Error entering user in database: {str(error)}'})
            response.status_code = StatusCodes['internal_error']
            return response
        finally:
            if conn is not None:
                conn.close()




# PUT - http://localhost:8080/user/
# Request body - {"name": "Pedro Ramalho","password":"password"}
@app.route('/bdprojeto/user/', methods=['PUT'])
def user_authentication():
    data = request.get_json()
    user_name = data['user_name']
    password = data['password']

    # Check if the user exists in the database
    conn = db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM utilizador WHERE user_name = %s', (user_name,))
    user = cur.fetchone()
    conn.close()

    if user is None:
        response = jsonify({'message': 'User not found'})
        response.status_code = StatusCodes['api_error']
        return response

    # Verify the password
    stored_password = user[3]  # Assuming the password is in the fourth column (index 3)
    if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
        user_type = user[4]  # Assuming the user_type is in the fifth column (index 4)
        user_id = user[0]
        payload = {
            'user_type': user_type,
            'user_id': user_id
        }
        # Generate an access token with user_type
        access_token = create_access_token(identity=payload)
        response = jsonify({'auth_token': access_token})
        response.status_code = StatusCodes['success']
        return response
    else:
        response = jsonify({'message': 'Invalid password'})
        response.status_code = StatusCodes['api_error']
        return response




@app.route('/bdprojeto/<song>/', methods=['PUT'])
@jwt_required()
def play_song(song):
    payload = request.get_json()
    current_user = get_jwt_identity()
    user_id = current_user["user_id"]
    user_type = current_user["user_type"]

    if current_user["user_type"] in ['regular', 'premium']:
        logger.info(f'PUT / {song}')

        conn = db_connection()
        cur = conn.cursor()

        logger.debug(f'song_id: {song}')

        try:
            cur.execute('SELECT song_id FROM song WHERE song_id = %s',(song,))
            row = cur.fetchone()

            if row != None:

                cur.execute('INSERT INTO playlist () VALUES (%s)', )

                conn.commit()
                response = {'status': StatusCodes['success'], 'results': "sucess"}
            else:
                response = {'status': StatusCodes['api_error'], 'results': 'Song_id given does not exist'}
                conn.rollback()
                return flask.jsonify(response)




        except (Exception, psycopg2.DatabaseError) as error:
            logger.error(f'PUT /{song} - error: {error}')
            response = {'status': StatusCodes['internal_error'], 'errors': str(error)}
            conn.rollback()

        finally:
            if conn is not None:
                conn.close()

        return flask.jsonify(response)

    else:
        response = {'status': StatusCodes['api_error'], 'results': 'Only consumers can play a song'}
        return flask.jsonify(response)





# POST - http://localhost:8080/song
# Request body - {"number": "3", "title": "tatuagem do Tomé", "genre": "pimba","duration": "5", "other_artists": [18, 4]}
@app.route('/bdprojeto/song/', methods=['POST'])
@jwt_required()
def add_song():
    logger.info('POST/bdprojeto/song/')

    payload = request.get_json()

    # validation of every argument not NULL:
    if 'song_name' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'song_name value not in payload'}
        return flask.jsonify(response)

    if 'release_date' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'release_date value not in payload'}
        return flask.jsonify(response)

    if 'genre' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'genre value not in payload'}
        return flask.jsonify(response)

    if 'duration' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'duration value not in payload'}
        return flask.jsonify(response)

    if 'other_artists' not in payload:
        other_artists_formatted = None
        other_artists = None
    else:
        other_artists = payload.get('other_artists', [])
        other_artists_formatted = "{" + ",".join(str(artist_id) for artist_id in other_artists) + "}"


    song_name = payload['song_name']
    genre = payload['genre']
    duration = payload['duration']
    release_date = payload['release_date']

    # Get the current user from the token
    current_user = get_jwt_identity()
    user_id = current_user["user_id"]
    user_type=current_user["user_type"]

    # artist verification
    if "artist" != user_type:
        response = {'status': StatusCodes['api_error'], 'results': 'user is not a artist'}
        return flask.jsonify(response)

    # Insert the song into the database
    conn = db_connection()
    cur = conn.cursor()

    # parameterized queries, good for security and performance
    statement = 'INSERT INTO song (song_name, genre, duration, other_artists, release_date,publisher) VALUES (%s, %s, %s, %s, %s,%s)'
    values = (song_name, genre, duration, other_artists_formatted, release_date,user_id)

    try:

        if other_artists is not None:
            for artist in other_artists:
                cur.execute('SELECT user_type FROM utilizador WHERE user_id = %s', (artist, ))
                tipo = cur.fetchone()[0]
                if tipo != "artist" or tipo is None:
                    raise Exception("user_id "+str(artist)+" in other_artists is not a artist")

        cur.execute(statement, values)
        cur.execute('SELECT LASTVAL()')
        id_inserido = cur.fetchone()[0]

        #cur.execute('INSERT INTO users_song(users_user_id,song_song_id) VALUES (%s,%s)', (user_id,id_inserido))

        # commit the transaction
        conn.commit()
        response = {'status': StatusCodes['success'], 'results': f'Song ID : {id_inserido}'}

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'POST /bdprojeto/song - error: {error}')
        response = {'status': StatusCodes['internal_error'], 'errors': str(error)}

        # an error occurred, rollback
        conn.rollback()

    finally:
        if conn is not None:
            conn.close()

    return flask.jsonify(response)


# POST - http://localhost:8080/bdprojeto/album
# Request body - {"name": "album_name", "release_date": "date", "publisher": publisher_id, "songs": [{song_info}, song_id, (...)]}
@app.route('/bdprojeto/album', methods=['POST'])
@jwt_required()
def add_album():
    logger.info('POST /bdprojeto/album/')

    payload = request.get_json()

    # validation of every argument not NULL:
    if 'album_name' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': ' value not in payload'}
        return flask.jsonify(response)

    if 'songs' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'songs array not in payload'}
        return flask.jsonify(response)

    if 'release_date' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'release_date value not in payload'}
        return flask.jsonify(response)


    album_name = payload['album_name']
    release_date = payload['release_date']
    songs = payload.get('songs', [])
    songs_formatted = []

    # Get the current user from the token
    current_user = get_jwt_identity()
    publisher_id = current_user["user_id"]

    # artist verification
    if current_user["user_type"] != "artist":
        response = {'status': StatusCodes['api_error'], 'results': 'user is not a artist'}
        return flask.jsonify(response)

    # Insert the album into the database
    conn = db_connection()
    cur = conn.cursor()

    # parameterized queries, good for security and performance
    statement = 'INSERT INTO album (album_name, release_date, publisher, songs) VALUES (%s, %s, %s, %s)'
    values = (album_name, release_date, publisher_id, songs_formatted)



    try:
        #cur.execute('SELECT song_id FROM song WHERE song_id = %s', (song,))


        # existing songs verification
        for song in songs:
            if isinstance(song, dict):
                if 'song_name' not in song:
                    raise Exception('song_name value not in new song')

                if 'release_date' not in song:
                    raise Exception('release_date value not in new song ')

                if 'genre' not in song:
                    raise Exception('genre value not in new song ')

                if 'duration' not in song:
                    raise Exception('duration value not in new song ')

                if 'other_artists' not in song:
                    other_artists_formatted = None

                else:
                    other_artists = payload.get('other_artists', [])
                    other_artists_formatted = "{" + ",".join(str(artist_id) for artist_id in other_artists) + "}"
                    for artist in other_artists:
                        cur.execute('SELECT user_type FROM utilizador WHERE user_id = %s', (artist,))
                        tipo = cur.fetchone()[0]
                        if tipo != "artist" or tipo is None:
                            raise Exception("user_id " + str(artist) + " in other_artists is not a artist")

                song_name = song['song_name']
                genre = song['genre']
                duration = song['duration']
                date = song['release_date']

                cur.execute('INSERT INTO song (song_name, genre, duration, other_artists, publisher, release_date) VALUES (%s, %s, %s, %s, %s, %s)'
                            , (song_name, genre, duration, other_artists_formatted, publisher_id, date))
                cur.execute('SELECT LASTVAL()')
                song_id = cur.fetchone()[0]
                songs_formatted.append(song_id)

            else:
                cur.execute('SELECT song_id FROM song WHERE song_id = %s', (song, ))
                if cur.fetchone()[0] is None:
                    raise Exception("song_id "+str(song)+" nonexistent")
                songs_formatted.append(song)


        cur.execute(statement, values)
        cur.execute('SELECT LASTVAL()')
        id_inserido = cur.fetchone()[0]

        cur.execute('INSERT INTO song_album(song_song_id,album_album_id) VALUES (%s,%s)',
                    (song_id, id_inserido))

        # commit the transaction
        conn.commit()
        response = {'status': StatusCodes['success'], 'results': f'Album ID : {id_inserido}'}

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'POST /bdprojeto/album - error: {error}')
        response = {'status': StatusCodes['internal_error'], 'errors': str(error)}

        # an error occurred, rollback
        conn.rollback()

    finally:
        if conn is not None:
            conn.close()

    return flask.jsonify(response)




# POST - http://localhost:8080/bdprojeto/subscription
# Request body - {“period”: “month” | “quarter” | “semester”, “cards”: [card_number1, …]}
@app.route('/bdprojeto/subscription', methods=['POST'])
@jwt_required()
def subscribe_to_premium():
    logger.info('POST/bdprojeto/subscription/')

    payload = request.get_json()

    # validation of every argument not NULL:
    if 'period' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'period value not in payload'}
        return flask.jsonify(response)

    if payload['period'] not in ['month', 'quarter', 'semester']:
        response = {'status': StatusCodes['api_error'], 'results': 'period needs to be month, quarter or semester'}
        return flask.jsonify(response)

    if 'cards' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'cards value not in payload'}
        return flask.jsonify(response)

    cards = payload.get('cards', [])
    period = payload['period']

    if period not in ['month', 'quarter', 'semester']:
        response = {'status': StatusCodes['api_error'], 'results': 'period: month, quarter, semester'}
        return flask.jsonify(response)

    pagar = 0
    months = '1 MONTH'
    if period == 'month':
        pagar = 7
        months = '1 MONTH'
    elif period == 'quarter':
        pagar = 21
        months = '3 MONTHS'
    elif period == 'semester':
        pagar = 42
        months = '6 MONTHS'

    # Get the current user from the token
    current_user = get_jwt_identity()
    user_id = current_user["user_id"]
    user_type = current_user["user_type"]

    # user premium or regular verification
    if user_type not in ['premium', 'regular']:
        response = {'status': StatusCodes['api_error'], 'results': 'user needs to be consumer'}
        return flask.jsonify(response)


    conn = db_connection()
    cur = conn.cursor()

    try:

        # Transaction
        cur.execute('SELECT card_price FROM prepaid_card WHERE card_id IN %s AND (consumer_id = %s OR consumer_id IS NULL)', (tuple(cards), user_id))
        rows = cur.fetchall()
        values = [row[0] for row in rows]

        if len(values) == 0:
            raise Exception("One of the ids is not a card_id or the card is owned by other consumer")

        i = 0
        for price in values:
            pagar -= price
            if pagar <= 0:
                break
            i += 1

        if pagar > 0:
            raise Exception('Transaction aborted insufficient balance')

        values[:i] = [0] * i
        values[i] = abs(pagar)

        # makes every card in cards controled by the consumer and implements the period
        cur.execute('UPDATE prepaid_card SET consumer_id = %s, periods = %s || periods  WHERE card_id IN %s', (user_id, period, tuple(cards),))

        for i in range(len(values)):
            cur.execute('UPDATE prepaid_card SET card_price = %s WHERE card_id = %s', (values[i], cards[i],))

        # Subscription
        if user_type == 'premium':
            history = "Update premium, expire date with a " + period + " more. "
            cur.execute('UPDATE subscription SET expire_date = expire_date + INTERVAL %s, subscription_history = subscription_history || %s WHERE consumer_id = %s'
                        , (months, history, user_id,))
            cur.execute('SELECT LASTVAL()')
            sub_id = cur.fetchone()[0]
        else:
            history = "Update regular to premium on todays date " + str(data_today) + " to a " + period + " period. "
            cur.execute('SELECT consumer_id FROM subscription WHERE consumer_id = %s', (user_id,))
            row = cur.fetchone()
            if row is not None:
                cur.execute('UPDATE subscription SET expire_date = %s + INTERVAL %s, subscription_history = subscription_history || %s WHERE consumer_id = %s'
                    , (data_today, months, history, user_id,))
                cur.execute('SELECT LASTVAL()')
                sub_id = cur.fetchone()[0]
            else:
                cur.execute(
                    'INSERT INTO subscription (expire_date, subscription_history, consumer_id) VALUES (%s + INTERVAL %s, %s, %s)',
                    (data_today, months, history, user_id))

                cur.execute('SELECT LASTVAL()')
                sub_id = cur.fetchone()[0]

            cur.execute('UPDATE utilizador SET user_type = %s WHERE user_id = %s', ("premium", user_id,))

        # commit the transaction
        conn.commit()
        response = {'status': StatusCodes['success'], 'results': f'Subscription ID : { sub_id }'}

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'POST /bdprojeto/subscription - error: {error}')
        response = {'status': StatusCodes['internal_error'], 'errors': str(error)}

        # an error occurred, rollback
        conn.rollback()

    finally:
        if conn is not None:
            conn.close()

    return flask.jsonify(response)



# POST - http://localhost:8080/bdprojeto/playlist
# Request body {“playlist_name”: “name”, “visibility”: “public” | “private”, “songs”: [song_id, song_id2, (…)]}
@app.route('/bdprojeto/playlist', methods=['POST'])
@jwt_required()
def create_playlist():
    logger.info('POST/bdprojeto/playlist/')

    payload = request.get_json()

    # validation of every argument not NULL:
    if 'playlist_name' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'playlist_name value not in payload'}
        return flask.jsonify(response)

    if 'visibility' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'visibility value not in payload'}
        return flask.jsonify(response)

    if 'songs' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'songs value not in payload'}
        return flask.jsonify(response)

    playlist_name = payload['playlist_name']
    songs = payload.get('songs', [])
    visibility = payload['visibility']

    # Get the current user from the token
    current_user = get_jwt_identity()
    user_id = current_user["artist"]
    user_type = current_user["user_type"]

    # user premium verification
    if user_type != "premium":
        response = {'status': StatusCodes['api_error'], 'results': 'user doesnt have a premium subscription'}
        return flask.jsonify(response)

    conn = db_connection()
    cur = conn.cursor()
    statement = 'INSERT INTO playlist (playlist_name,songs,visibility,user_id) VALUES (%s,%s,%s,%s)'
    values = (playlist_name, songs, visibility, user_id)

    try:
        cur.execute(statement, values)
        cur.execute('SELECT LASTVAL()')
        paylist_id = cur.fetchone()[0]
        conn.commit()
        response = {'status': StatusCodes['success'], 'results': f'Playlist ID : { paylist_id}'}

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'POST /dbproj/playlist - error: {error}')
        response = {'status': StatusCodes['internal_error'], 'errors': str(error)}

        # an error occurred, rollback
        conn.rollback()

    finally:
        if conn is not None:
            conn.close()

    return flask.jsonify(response)



# POST - http://localhost:8080/dbproj/card
# Request body {“number_cards”: “number”, “card_price”: 10 | 25 | 50}
@app.route('/bdprojeto/card', methods=['POST'])
@jwt_required()
def generate_prepaid_card():
    logger.info('POST/bdprojeto/card/')

    payload = request.get_json()

    if 'card_price' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'card_price value not in payload'}
        return flask.jsonify(response)

    card_price = payload['card_price']

    if not (int(card_price) == 10 or int(card_price) == 25 or int(card_price) == 50):
        response = {'status': StatusCodes['api_error'], 'results': 'card_price value is not 10, 25 or 50'}
        return flask.jsonify(response)

    # Get the current user from the token
    current_user = get_jwt_identity()
    admin_id = current_user["user_id"]
    user_type = current_user["user_type"]

    # user admin verification
    if "admin" != user_type:
        response = {'status': StatusCodes['api_error'], 'results': 'user is not a administrator'}
        return flask.jsonify(response)

    conn = db_connection()
    cur = conn.cursor()
    statement = 'INSERT INTO prepaid_card (card_price,admin_id) VALUES (%s,%s)'
    values = (card_price, admin_id,)


    try:
        cur.execute(statement,values)
        cur.execute('SELECT LASTVAL()')
        card_id = cur.fetchone()[0]

        # commit the transaction
        conn.commit()
        response = {'status': StatusCodes['success'], 'results': f'Card IDs: {card_id}'}

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'POST /dbproj/card - error: {error}')
        response = {'status': StatusCodes['internal_error'], 'errors': str(error)}

        # an error occurred, rollback
        conn.rollback()

    finally:
        if conn is not None:
            conn.close()

    return flask.jsonify(response)





@app.route('/bdprojeto/comments/<song_id>', methods=['POST'])
@app.route('/bdprojeto/comments/<song_id>/<parent_comment_id>', methods=['POST'])
@jwt_required()
def leave_comment(song_id, parent_comment_id=None):
    logger.info('POST/dbproj/comments/<song_id>/<parent_comment_id>')
    logger.debug(f'keyword: {song_id}')
    logger.debug(f'keyword: {parent_comment_id}')

    payload = request.get_json()

    # Get the user current token
    current_user = get_jwt_identity()
    user_id = current_user["user_id"]
    user_type = current_user["user_type"]

    # Validation of all arguments not null:
    if 'comment' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'comment value not in payload'}
        return flask.jsonify(response)

    comment = payload['comment']

    conn = db_connection()
    cur = conn.cursor()

    try:
        if parent_comment_id:
            # Answer to an existent comment
            statement = 'INSERT INTO comments (song_song_id, comment, comments_comment_id, user_id) VALUES (%s, %s, %s, %s) RETURNING comment_id'
            values = (song_id, comment, parent_comment_id, user_id)
        else:
            # New comment
            statement = 'INSERT INTO comments (song_song_id, comment, user_id) VALUES (%s, %s, %s) RETURNING comment_id'
            values = (song_id, comment, user_id)

        cur.execute(statement, values)
        comment_id = cur.fetchone()[0]
        conn.commit()

        response = {'status': StatusCodes['success'], 'results': f'Comment ID: {comment_id}'}

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'POST /bdprojeto/comments/<song_id>/<parent_comment_id> - error: {error}')
        response = {'status': StatusCodes['internal_error'], 'errors': str(error)}

        conn.rollback()

    finally:
        if conn is not None:
            conn.close()

    return flask.jsonify(response)





# GET - http://localhost:8080/bdprojeto/song/{keyword}
@app.route('/bdprojeto/song/<keyword>', methods=['GET'])
@jwt_required()
def search_song(keyword):
    # Get the current user from the token
    current_user = get_jwt_identity()

    # Search for the song in the database
    logger.info('GET /bdprojeto/song/<keyword>')

    logger.debug(f'keyword: {keyword}')

    conn = db_connection()
    cur = conn.cursor()

    try:
        cur.execute('SELECT * FROM song where song_id = %s', (keyword,))
        rows = cur.fetchall()

        row = rows[0]

        logger.debug('GET bdprojeto/song/<keyword> - parse')
        logger.debug(row)
        content = {'song_id': int(row[0]), 'song_name': row[1], 'genre': row[2],'duration': row[3], 'other_artist': row[4],
                   'release_date': row[5], 'publisher': row[6]}
        response = {'status': StatusCodes['success'], 'results': content}

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'GET /song/<keyword> - error: {error}')
        response = {'status': StatusCodes['internal_error'], 'errors': str(error)}

    finally:
        if conn is not None:
            conn.close()

    return flask.jsonify(response)



# GET - http://localhost:8080/bdprojeto/artist_info/{artist_id}
@app.route('/bdprojeto/artist_info/<artist_id>', methods=['GET'])
@jwt_required()
def detail_artist(artist_id):
    # Search for the song in the database
    logger.info('GET /bdprojeto/artist_info/{artist_id}')

    logger.debug(f'keyword: {artist_id}')

    conn = db_connection()
    cur = conn.cursor()

    try:
        # artist name, id, and email
        cur.execute("SELECT * FROM utilizador WHERE user_type = 'artist' AND user_id = %s", (artist_id,))
        row = cur.fetchone()

        # artist songs
        cur.execute("SELECT song_id FROM song WHERE publisher = %s", (artist_id,))
        row2 = [row[0] for row in cur.fetchall()]

        # artist albums
        cur.execute("SELECT album_id FROM album WHERE publisher = %s", (artist_id,))
        row3 = [row[0] for row in cur.fetchall()]

        # artist playlists
        cur.execute("SELECT playlist_id FROM playlist WHERE user_id = ANY(%s)", (row2,))
        row4 = [row[0] for row in cur.fetchall()]

        logger.debug('GET artist_info/<artist_id> - parse')
        logger.debug(row)

        if row is None:
            response = {'status': StatusCodes['api_error'], 'results': 'artist does not exist'}
            conn.close()
            return flask.jsonify(response)

        content = {
            'artist_id': int(row[0]),
            'artist_name': row[1],
            'artist_email': row[2],
            'songs': row2,
            'albums': row3,
            'playlists': row4
        }

        response = {'status': StatusCodes['success'], 'results': content}

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'GET /artist_info/<artist_id> - error: {error}')
        response = {'status': StatusCodes['internal_error'], 'errors': str(error)}

    finally:
        if conn is not None:
            conn.close()

    return flask.jsonify(response)


# GET - http://localhost:8080/bdprojeto/report/{year-moth}
@app.route('/dbproj/report/<year_moth>', methods=['GET'])
@jwt_required()
def generate_monthly_report(year_moth):
    # Get the current user from the token
    current_user = get_jwt_identity()

    # Search for the song in the database
    logger.info('GET /dbproj/report/<year_moth>')

    logger.debug(f'keyword: {year_moth}')

    conn = db_connection()
    cur = conn.cursor()

    try:
        cur.execute('SELECT * FROM song where song_id = %s', (year_moth,))
        rows = cur.fetchall()

        row = rows[0]

        logger.debug('GET bdprojeto/song/<keyword> - parse')
        logger.debug(row)
        content = {'song_id': int(row[0]), 'song_name': row[1], 'genre': row[2], 'publisher': row[3], 'duration': row[4],
                   'release_date': row[5], 'other_artist': row[6]}
        response = {'status': StatusCodes['success'], 'results': content}

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'GET /report/<year_moth> - error: {error}')
        response = {'status': StatusCodes['internal_error'], 'errors': str(error)}

    finally:
        if conn is not None:
            conn.close()

    return flask.jsonify(response)




if __name__ == '__main__':

    # set up logging
    logging.basicConfig(filename='C:\\Users\\Pedro Ramalho\\OneDrive - Universidade de Coimbra\\LEI-PedroRamalho\\2º Ano\\2º Semestre\\BD\\Projeto\\bd-python-demo-api-main\\python\\log_file.log')
    logger = logging.getLogger('logger')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter('%(asctime)s [%(levelname)s]:  %(message)s', '%H:%M:%S')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    host = '127.0.0.1'
    port = 8080
    # Start the Flask app
    with app.app_context():
        logger.info(f'API v1.0 online: http://{host}:{port}')


    @app.after_request
    def log_response(response):
        logger.info(f'Response - Status: {response.status_code}, Body: {response.data.decode("utf-8")}')
        return response


    app.run(host=host, debug=True, threaded=True, port=port)



