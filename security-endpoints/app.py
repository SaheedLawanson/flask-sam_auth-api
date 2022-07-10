import json, os, boto3
from flask_lambda import FlaskLambda
from flask import request

dynamodb_client = boto3.client('dynamodb')
cognito_client = boto3.client('cognito-idp')

table_name = os.environ['TABLE_NAME']
cognito_client_id = os.environ['CLIENT_ID']

app = FlaskLambda(__name__)

# MODULES
def response_object(message, status, data=None, content={"Content-Type": "application/json"}):
    return (
        json.dumps({"message": message, "data": data}),
        status,
        content
    )

def dynamodb_deformatter(db_json, prefix):
    # Convert dynamodb col names to human readable names
    # args: key = "UFirstName", prefix = 'U' => "firstName"
    def prefix_remover(key, prefix):
        lp = len(prefix)
        if key[:lp] == prefix:
            keyName = key[lp:]
            return keyName[0].lower() + keyName[1:]

        else:
            return key

    typeCode = { 'S': str, 'L': list, 'N': int, 'M': dict, 'SS': list}

    dtype, data = list(db_json.items())[0]

    if dtype not in ('M', 'L'): return typeCode[dtype](data)

    if dtype == 'M':
        return {prefix_remover(k, prefix) : dynamodb_deformatter(v, prefix) for k, v in data.items()}

    else:
        return [dynamodb_deformatter(item, prefix) for item in data]

def authorizer(request):
    def wrapper1(func):
        def wrapper2(*args, **kwargs):

            try:
                bearer_token = request.headers['Authorization']
                access_token = bearer_token.split(' ')[1]

                response = cognito_client.get_user(
                    AccessToken = access_token
                )
            except:
                return response_object("Authentication error, access denied", 401)

            user_attributes = response['UserAttributes']
            user = {attribute['Name']: attribute['Value'] for attribute in user_attributes}

            request.auth_user_id = user['email']
            return func(*args, **kwargs)
        return wrapper2
    return wrapper1


# ENDPOINTS
@app.route('/sign_up', methods=['POST'])
def sign_up():
    try:
        body = json.loads(request.data)

        password = body.pop('password')
        attributes = [
            "email", "first_name", "last_name",
            "fullname", "phone_number", "address",
            "dob", "gender", "username"
        ]
        custom_attributes = [
            "image_id", "date_created", "is_recurring",
            "profile_type", "balance", "tenant_id",
            "promo_code", "formatted_date", "account_number",
            "father_name", "status", "city", "rating",
            "state", "country", "delete_flag", "last_logged_in",
            "last_modified", "bvn", "pin", "question_1",
            "question_2", "question_3", "answer_1", "answer_2",
            "answer_3", "docType", "date_joined", "is_superuser",
            "is_staff", "is_active", "countryCode",
            "receive_notification"
        ]

        response = cognito_client.sign_up(
            ClientId = cognito_client_id,
            Username = body["email"],
            Password = password,
            UserAttributes = [
                {
                    'Name': 'email', 'Value': body["email"]
                },
                {
                    'Name': 'given_name', 'Value': body['first_name']
                },
                {
                    'Name': 'family_name', 'Value': body['last_name']
                },
                {
                    'Name': 'name', 'Value': body['fullname']
                },
                {
                    'Name': 'phone_number', 'Value': body['phone_number']
                },
                {
                    'Name': 'address', 'Value': body['address']
                },
                {
                    'Name': 'birthdate', 'Value': body['dob']
                },
                {
                    'Name': 'gender', 'Value': body['gender']
                },
                {
                    'Name': 'preferred_username', 'Value': body['username']
                }
            ] + [
                {
                    'Name': f'custom:{attr}', 'Value': body[attr]
                } for attr in custom_attributes
            ],
            ValidationData = [
                {
                    'Name': 'email', 'Value': body['email']
                }
            ]
        )

        dynamodb_client.put_item(
            TableName = table_name,
            Item = {
                attribute: {'S': body[attribute]} for attribute in attributes
            } | {
                attribute: {'S': body[attribute]} for attribute in custom_attributes
            },
            ConditionExpression = "attribute_not_exists(#email)",
            ExpressionAttributeNames = {
                "#email": "email"
            }
        )

        return response_object(
            f"Successfully signed in, a confirmation code has been sent to {response['CodeDeliveryDetails']['Destination']}",
            200,
            None
        ) 

    except Exception:
        return response_object("An error occurred", 400, None) 

@app.route('/confirm_sign_up', methods=['POST'])
def confirm_sign_up():
    try:
        body = json.loads(request.data)

        user_email = body['user_email']
        code = body['confirmation_code']

        response = cognito_client.confirm_sign_up(
            ClientId = cognito_client_id,
            Username = user_email,
            ConfirmationCode = code
        )
        # response.pop('ResponseMetadata')

        return response_object("Successfully confirmed signup", 200, data=response)
    
    except cognito_client.exceptions.CodeMismatchException:
        return response_object("Supplied code is invalid", 402)

    except SystemError:
        return response_object("An error occurred", 400) 

@app.route('/login', methods=['POST'])
def log_in():
    try:
        body = json.loads(request.data)

        user_email = body['user_email']
        password = body.pop('password')

        response = cognito_client.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters = {
                'USERNAME': user_email,
                'PASSWORD': password
            },
            ClientId = cognito_client_id
        )

        return response_object("Successfully logged in", 200, data = response['AuthenticationResult'])

    except cognito_client.exceptions.UserNotConfirmedException:
        return response_object('This account has not been activated', 402)

    except cognito_client.exceptions.NotAuthorizedException:
        return response_object('Incorrect username or password', 403)
 
    except Exception:
        return response_object('An error occurred', 405) 

@app.route('/get_data')
@authorizer(request)
def get_data():
    try:
        email = request.auth_user_id

        response = dynamodb_client.get_item(
            TableName = table_name,
            Key = {
                "email": {"S": email}
            }
        )

        return response_object(
            "Successfully fetched data",
            200,
            dynamodb_deformatter({"M": response["Item"]}, 'Z')
        )

    except SystemError:
        return response_object("An error occurred", 400) 


if __name__ == "__main__":
    app.run(debug = True)