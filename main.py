######################################################################
#  Skylar Posler
# CS 493 Cloud App Development
# Oregon State University
# Tarpaulin Course Management RESTful API
######################################################################


from flask import Flask, request, jsonify, send_file
from google.cloud import datastore
from google.cloud import storage
from google.cloud.datastore.query import PropertyFilter


import requests
import json
import io

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
PHOTO_BUCKET ='assignment6_poslert'

client = datastore.Client()

USERS = "users"
COURSES = "courses"
ENROLLMENT = "enrollment"

CLIENT_ID = 'leFQCYbupbJ3HZK1rqjREfPSL9UtADVI'
CLIENT_SECRET = 't3xkVLO1SEd_YMNXlpCVg4f9k0j-4ALUfNml_R-LCFw8N4HwkNpTABCl0ug92tI-'
DOMAIN = '493-hwk-5.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]

ERROR_400 = {"Error": "The request body is invalid"}
ERROR_403 = {"Error": "You don't have permission on this resource"}
ERROR_401 = {"Error": "Unauthorized"}
ERROR_404 = {"Error": "Not found"}
ERROR_409 = {"Error": "Enrollment data is invalid"}

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)
    
@app.route('/')
def index():
    return "Please navigate to /users or /courses to use this API"

######################################################################
# AVATARS
######################################################################

@app.route('/' + USERS + "/<int:user_id>/avatar", methods=['POST'])
def create_update_avatar(user_id):
    """
    Uploads the .png in the request as the avatar of the user's avatar. If there is already an avatar for the
    user, it gets updated with the new file. The file must be uploaded to Google Cloud Storage.
    Auth0: User that belongs to user_id
    """

    if 'file' not in request.files:
        return ERROR_400, 400
    
    # check if JWT is valid
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401

    query = client.query(kind=USERS)
    query.add_filter(filter=PropertyFilter('sub', '=', payload['sub']))
    requestor = list(query.fetch())

    # check if JWT matches user
    if requestor[0].key.id != user_id:
        return ERROR_403, 403

    if requestor is not None:
        file_obj = request.files['file']
        file_obj.filename = str(user_id) + ".png"
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(file_obj.filename)
        file_obj.seek(0)
        blob.upload_from_file(file_obj)

        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)
        user.update({'avatar_url': True})
        client.put(user)
        return jsonify({'avatar_url': request.url}), 200
    
@app.route('/' + USERS + '/<int:user_id>/avatar', methods=['GET'])
def get_avatar(user_id):
    """
    Return the file stored in Google Cloud Storage as the user's avatar.
    Auth0: User that belongs to user_id
    """

        # check if JWT is valid
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401

    query = client.query(kind=USERS)
    query.add_filter(filter=PropertyFilter('sub', '=', payload['sub']))
    requestor = list(query.fetch())

    # check if JWT matches user
    if requestor[0].key.id != user_id:
        return ERROR_403, 403
    
    # if avatar exists at all
    if 'avatar_url' not in requestor[0]:
        return ERROR_404, 404
    
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(str(user_id) + ".png")
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)

    return send_file(file_obj, mimetype='image/x-png', download_name=str(user_id) + ".png"), 200

@app.route('/' + USERS + '/<int:user_id>/avatar', methods=['DELETE'])
def delete_avatar(user_id):
    """
    Delete the file stored in Google Cloud Storage as the user's avatar.
    Auth0: User that belongs to user_id
    """

    # check if JWT is valid
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401

    query = client.query(kind=USERS)
    query.add_filter(filter=PropertyFilter('sub', '=', payload['sub']))
    requestor = list(query.fetch())

    # check if JWT matches user
    if requestor[0].key.id != user_id:
        return ERROR_403, 403
    
    # if avatar exists at all
    if 'avatar_url' not in requestor[0]:
        return ERROR_404, 404
    
    # delete from storage
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(str(user_id) + ".png")
    blob.delete()

    # delete from db
    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)
    del user['avatar_url']
    client.put(user)
    return '',204

######################################################################
# USERS
######################################################################

@app.route('/' + USERS + "/<int:user_id>", methods=['GET'])
def get_user(user_id):
    """
    Returns the details of a user.
    Auth0: Admin role or User that belongs to user_id
    """

    if request.method == 'GET':
        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)

        # JWT is invalid
        try:
            payload = verify_jwt(request)
        except AuthError:
            return ERROR_401, 401

        # user doesn't exist
        if user == None:
            return ERROR_403, 403
        
        payload = verify_jwt(request)

        # JWT belongs to user id or user is admin
        if user['sub'] == payload['sub']:
            # query for instructor details
            if user['role'] == 'instructor':
                user['id'] = user_id
                query = client.query(kind=COURSES)
                query.add_filter(filter=PropertyFilter('instructor_id', '=', user_id))
                courses = list(query.fetch())

                taught = []
                for c in courses:
                    course_id = c.key.id
                    course_url = request.host_url + "courses" + "/" + str(course_id)
                    taught.append(course_url)

                user['courses'] = taught

                if 'avatar_url' in user:
                    user['avatar_url'] = request.url + "/avatar"
                return jsonify(user), 200
            
            # query for student and student details
            if user['role'] == 'student':               
                user['courses'] = [] 
                user['id'] = user_id

                if 'avatar_url' in user:
                    user['avatar_url'] = request.url + "/avatar"
                return jsonify(user), 200
            
        if user['role'] == 'admin':
            user['id'] = user_id
            if 'avatar_url' in user:
                user['avatar_url'] = request.url + "/avatar"
            return jsonify(user), 200
        else:
            return ERROR_403, 403
        
    
@app.route('/' + USERS, methods=['GET'])
def get_all_users():
    """
    Returns an array with all 9 pre-created users from the kind “users” in Datastore.
    Auth0: Admin role
    """

    # verify JWT
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401

    query = client.query(kind=USERS)
    query.add_filter(filter=PropertyFilter('sub', '=', payload['sub']))
    requestor = list(query.fetch())

    if len(requestor) != 1:
        return ("DB Error")
    
    # check for admin
    if requestor[0]['role'] == 'admin':
        query = client.query(kind=USERS)
        results = list(query.fetch())

        users_list = []
        for user in results:
            user['id'] = user.key.id
            users_list.append(user)
        
        for user in users_list:
            if 'avatar_url' in user:
                user.pop('avatar_url')

        return users_list, 200

    else:
        return ERROR_403, 403    
    
######################################################################
# LOGIN
######################################################################  

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/users/login', methods=['POST'])
def login_user():
    """
   Generates a JWT for a registered user of the app by 
   sending a request to Auth0 domain created for the
   REST API to get a token
    """

    content = request.get_json()
    if 'username' and 'password' not in content:
        return ERROR_400, 400
    
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    r_json  = r.json()
    if 'error' in r_json:
        return ERROR_401, 401
    token = {"token": r_json['id_token']}
    return token, 200

######################################################################
# COURSES
######################################################################

@app.route('/courses', methods=['POST'])
def post_course():
    """
    Creates a course.
    Auth0: Admin role
    """

    if request.method == 'POST':
        content = request.get_json()

        # invalid or missing JWT
        try:
            payload = verify_jwt(request)
        except AuthError:
            return ERROR_401, 401

        # query for admin role
        query = client.query(kind=USERS)
        query.add_filter(filter=PropertyFilter('sub', '=', payload['sub']))
        requestor = list(query.fetch())

        # return err if not admin
        if requestor[0]['role'] != 'admin':
            return ERROR_403, 403

        # only 1 admin in db
        if len(requestor) != 1: 
            return ("DB Error")

        # missing any content 
        if len(content) < 5: 
            return ERROR_400, 400
        
        # checking that instructor exists

        query_1 = client.query(kind=USERS)
        key = client.key(USERS, content['instructor_id'])
        query_1.key_filter(key, "=")
        query_1.add_filter(filter=PropertyFilter('role', '=', 'instructor'))
        instructor = list(query_1.fetch())

        if len(instructor) < 1 or instructor[0]['role'] != 'instructor':
            return ERROR_400, 400

        # all checks passed, create course
        new_course = datastore.entity.Entity(key=client.key(COURSES))
        new_course.update({"subject": content["subject"], "number": int(content["number"]),
        "title": content["title"], "term": content['term'], "instructor_id": int(content['instructor_id'])})
        client.put(new_course)
        new_course['id'] = new_course.key.id

        if new_course['id'] == None:
            new_course['self'] = request.url + "/null"
        else:
            new_course['self'] = request.url + "/" + str(new_course['id'])

        return jsonify(new_course), 201
        
@app.route('/' + COURSES, methods=['GET'])
def get_all_courses():
    """
    Gets a paginated list of all courses.
    Auth0: Unprotected
    """

    # set base for pagination
    query = request.args.to_dict()
    if query == {}:
        offset = 0
    else:
        offset = int(query['offset'])

    # query for courses and sort
    query_1 = client.query(kind=COURSES)
    query_1.order = ['subject']
    classes = list(query_1.fetch(limit=3, offset=offset)) # already a list

    course_catalog = {}
    courses = []  

    for c in classes:
        c['id'] = c.key.id
        c['self'] = request.host_url + "courses" + "/" + str(c['id'])
        courses.append(c)

    course_catalog['courses'] = courses

    # set next link
    limit = 3
    offset += 3
    previous = request.url_root + COURSES
    next = previous + "?offset=" + str(offset) + "&limit=" + str(limit)
    course_catalog['next'] = next

    return course_catalog, 200

@app.route('/' + COURSES + "/<int:course_id>", methods=['GET'])
def get_course(course_id):
    """
    Gets an existing course. 
    Auth0: Unprotected
    """

    if request.method == 'GET':

        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)

        # course doesn't exist
        if course == None:
            return ERROR_404, 404
        
        course['id'] = course_id
        course['self'] = request.url

        return jsonify(course), 200

@app.route('/' + COURSES + "/<int:course_id>", methods=['PATCH'])
def update_course(course_id):
    """
    Perfoms a partial update on the course.
    Auth0: Admin role 
    """

    if request.method == 'PATCH':
        content = request.get_json()

        # invalid or missing JWT
        try:
            payload = verify_jwt(request)
        except AuthError:
            return ERROR_401, 401

        # query for admin role
        query = client.query(kind=USERS)
        query.add_filter(filter=PropertyFilter('sub', '=', payload['sub']))
        requestor = list(query.fetch())

        # check for course exists
        query_1 = client.query(kind=COURSES)
        key = client.key(COURSES, course_id)
        query_1.key_filter(key, "=")
        course = list(query_1.fetch())

        # if no course or user not admin - reject
        if requestor[0]['role'] != 'admin' or len(course) < 1:
            return ERROR_403, 403
        
        # check if instructor can update
        if 'instructor_id' in content:
            query_2 = client.query(kind=USERS)
            key = client.key(USERS, content['instructor_id'])
            query_2.key_filter(key, "=")
            query_2.add_filter(filter=PropertyFilter('role', '=', 'instructor'))
            instructor = list(query_2.fetch())

            if len(instructor) < 1 or instructor[0]['role'] != 'instructor':
                return ERROR_400, 400
        
        course[0].update(content)
        client.put(course[0])
        return course[0], 200        

@app.route('/' + COURSES + "/<int:course_id>", methods=['DELETE'])
def delete_course(course_id):
    """
    Delete a course 
    - deletes enrollment of students enrolled
    - assigned instructor is no longer associated with course
    Auth0: Admin role 
    """

    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)

    # verify
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401
    
    query = client.query(kind=USERS)
    query.add_filter(filter=PropertyFilter('sub', '=', payload['sub']))
    requestor = list(query.fetch())

    if len(requestor) != 1:
        return ("DB Error")

    # only admin can delete courses
    if requestor[0]['role'] == 'admin':  
        client.delete(course_key)
        return ("", 204)
    
    if course is None or requestor[0]['role'] != 'admin':
        return ERROR_403, 403
    

######################################################################
# ENROLLMENT
######################################################################

@app.route('/' + COURSES + "/<int:course_id>" + "/students", methods=['PATCH'])
def update_enrollement(course_id):
    """
    Enroll and/or disenroll students from a course.
    Auth0: Admin role or course Instructor
    """

    content = request.get_json()

    # verify
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401
    
    # check if course exists
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)

    if course is None:
        return ERROR_403, 403

    # check if JWT belongs to admin or course instructor
    role_query = client.query(kind=USERS)
    role_query.add_filter(filter=PropertyFilter('sub', '=', payload['sub']))
    requestor = list(role_query.fetch())

    if requestor[0]['role'] != 'admin' and course['instructor_id'] != requestor[0].key.id:
        return ERROR_403, 403
    
    # check if data in add/remove arrays is valid
    # student IDs exist in db

    # no duplicate IDs in the arrays
    for student in content['add']:
        for ids in content['remove']:
            if student == ids:
                return ERROR_409, 409
            
    # all students in add array have student role
    for student in content['add'] + content['remove']:
        student_query = client.query(kind=USERS)
        key = client.key(USERS, student)
        student_query.key_filter(key, "=")
        student_query.add_filter(filter=PropertyFilter('role', '=', 'student'))
        possible_student = list(student_query.fetch())
        
        if len(possible_student) != 1:
            return ERROR_409, 409

    # add enrollment
    for student in content['add']:
        add_query = client.query(kind=ENROLLMENT)
        add_query.add_filter(filter=PropertyFilter('course_id', '=', course_id))
        add_query.add_filter(filter=PropertyFilter('student_id', '=', student))
        add_student = list(add_query.fetch())

        if len(add_student) >= 1:
            continue

        new_enrollment = datastore.entity.Entity(key=client.key(ENROLLMENT))
        new_enrollment.update({'course_id': course_id, 'student_id': student})
        client.put(new_enrollment)
        new_enrollment['id'] = new_enrollment.key.id

    # remove enrollment
    for student in content['remove']:
        remove_query = client.query(kind=ENROLLMENT)
        remove_query.add_filter(filter=PropertyFilter('course_id', '=', course_id))
        remove_query.add_filter(filter=PropertyFilter('student_id', '=', student))
        remove_student = list(remove_query.fetch())

        if len(remove_student) < 1:
            continue

        client.delete(remove_student[0].key)

    return (""), 200

@app.route('/' + COURSES + "/<int:course_id>" + "/students", methods=['GET'])
def get_enrollement(course_id):
    """
    Get the list of students enrolled in a course.
    Auth0: Admin role or course Instructior
    """

    # verify
    try:
        payload = verify_jwt(request)
    except AuthError:
        return ERROR_401, 401
    
    # check if course exists
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)

    if course is None:
        return ERROR_403, 403
    
    # check for admin role or instructor
    query = client.query(kind=USERS)
    query.add_filter(filter=PropertyFilter('sub', '=', payload['sub']))
    requestor = list(query.fetch())

    if requestor[0]['role'] != 'admin' and requestor[0].key.id != course['instructor_id']:
        return ERROR_403, 403

    enrollment_query = client.query(kind=ENROLLMENT)
    enrollment_query.add_filter(filter=PropertyFilter('course_id', '=', course_id))
    course_enrollment = list(enrollment_query.fetch())

    # still return if enrollment is none
    enrollment = []
    for i in course_enrollment:
        enrollment.append(i['student_id'])

    return enrollment, 200
        
# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    """
    Decodes the JWT
    """

    payload = verify_jwt(request)
    return payload      


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
