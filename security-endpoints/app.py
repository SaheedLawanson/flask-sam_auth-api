import json, os, boto3
from flask_lambda import FlaskLambda
from flask import request
from models import UserModel


aws_environment = os.environ["AWS_ENVIRONMENT"]

# Setup variables for local environment
if aws_environment == "local":  
    # Configuring aws api clients
    cognito_client = boto3.client('cognito-idp', endpoint_url="http://localhost:9229")
    
    # Create Cognito userpool and client
    userpool = cognito_client.create_user_pool(
        PoolName = "users_pool",
        Policies={
            'PasswordPolicy': {
                'MinimumLength': 123,
                'RequireUppercase': True,
                'RequireLowercase': True,
                'RequireNumbers': True,
                'TemporaryPasswordValidityDays': 123
            }
        },
        AutoVerifiedAttributes=[
            'email',
        ],
        UsernameAttributes=[
            'email',
        ],
        Schema = [
            {
                "Name": "email",
                "AttributeDataType": "String",
                "Mutable": False,
                "Required": True
            },
            {
                "Name": "phone_number",
                "AttributeDataType": "String",
                "Mutable": False,
                "Required": True
            },
            {
                "Name": "preferred_username",
                "AttributeDataType": "String",
                "Mutable": False,
                "Required": True
            },
            {
            "Name": "name",
            "AttributeDataType": "String",
            "Mutable": False,
            "Required": True
            },
            {
            "Name": "given_name",
            "AttributeDataType": "String",
            "Mutable": False,
            "Required": True
            },
            {
            "Name": "family_name",
            "AttributeDataType": "String",
            "Mutable": False,
            "Required": True
            },
            {
            "Name": "address",
            "AttributeDataType": "String",
            "Mutable": False,
            "Required": True
            },
            {
            "Name": "gender",
            "AttributeDataType": "String",
            "Mutable": False,
            "Required": True
            },
            {
            "Name": "birthdate",
            "AttributeDataType": "String",
            "Mutable": False,
            "Required": True
            },
            {
            "Name": "date_created",
            "AttributeDataType": "String"
            },
            {
            "Name": "is_recurring",
            "AttributeDataType": "Boolean"
            },
            {
            "Name": "account_number",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "10"
            }
            },
            {
            "Name": "delete_flag",
            "AttributeDataType": "Boolean"
            },
            {
            "Name": "last_logged_in",
            "AttributeDataType": "String"
            },
            {
            "Name": "last_modified",
            "AttributeDataType": "String"
            },
            {
            "Name": "bvn",
            "AttributeDataType": "String",
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "14"
            }
            },
            {
            "Name": "pin",
            "AttributeDataType": "String",
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "14"
            }
            },
            {
            "Name": "date_joined",
            "AttributeDataType": "String",
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "is_superuser",
            "AttributeDataType": "Boolean"
            },
            {
            "Name": "is_staff",
            "AttributeDataType": "Boolean"
            },
            {
            "Name": "is_active",
            "AttributeDataType": "Boolean"
            },
            {
            "Name": "receive_notification",
            "AttributeDataType": "Boolean"
            },
            {
            "Name": "image_id",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "profile_type",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "balance",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "tenant_id",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "promo_code",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "formatted_date",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "father_name",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "status",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "city",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "rating",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "state",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "country",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "question_1",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "question_2",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "question_3",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "answer_1",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "answer_2",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "answer_3",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "docType",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            },
            {
            "Name": "countryCode",
            "AttributeDataType": "String",
            "Mutable": False,
            "StringAttributeConstraints": {
                "MinLength": "0",
                "MaxLength": "200"
            }
            }
        ],
        AccountRecoverySetting={
            'RecoveryMechanisms': [
                {
                    'Priority': 123,
                    'Name': 'verified_email'
                },
            ]
        }
    )
    userpool_client = cognito_client.create_user_pool_client(
        UserPoolId=userpool["UserPool"]["Id"],
        ClientName='myUserPoolClient',
        AccessTokenValidity=5,
        TokenValidityUnits={
            'AccessToken': 'minutes'
        },
        ExplicitAuthFlows=[
            'USER_PASSWORD_AUTH',
        ]
    )
    cognito_client_id = userpool_client["UserPoolClient"]["ClientId"]

    # Create dynamodb table on local instance
    UserModel.create_table(billing_mode="PAY_PER_REQUEST")

# Setup variables for cloud environment
else:
    # Configuring aws api clients
    cognito_client = boto3.client('cognito-idp')

    table_name = os.environ["TABLE_NAME"]
    cognito_client_id = os.environ['CLIENT_ID']


app = FlaskLambda(__name__)

# MODULES
def response_object(message, status, data=None, content={"Content-Type": "application/json"}):
    return (
        json.dumps({"message": message, "data": data}),
        status,
        content
    )

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
        # Extract request parameters
        body = json.loads(request.data)

        email = body.get("email")

        # Remove password from parameters
        password = body.pop('password')

        # Create a list of user attributes for future iterations
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

        # Sign user with attributes
        response = cognito_client.sign_up(
            ClientId = cognito_client_id,
            Username = email,
            Password = password,
            UserAttributes = [
                {
                    'Name': 'email', 'Value': body.get("email")
                },
                {
                    'Name': 'given_name', 'Value': body.get('first_name')
                },
                {
                    'Name': 'family_name', 'Value': body.get('last_name')
                },
                {
                    'Name': 'name', 'Value': body.get('fullname')
                },
                {
                    'Name': 'phone_number', 'Value': body.get('phone_number')
                },
                {
                    'Name': 'address', 'Value': body.get('address')
                },
                {
                    'Name': 'birthdate', 'Value': body.get('dob')
                },
                {
                    'Name': 'gender', 'Value': body.get('gender')
                },
                {
                    'Name': 'preferred_username', 'Value': body.get('username')
                }
            ] + [
                {
                    'Name': f'custom:{attr}', 'Value': body.get(attr)
                } for attr in custom_attributes
            ],
            ValidationData = [
                {
                    'Name': 'email', 'Value': email
                }
            ]
        )

        # Create user in database
        otherAttributes = {
                attribute: body.get(attribute) for attribute in attributes
            } | {
                attribute: body.get(attribute) for attribute in custom_attributes
            }
            
        user = UserModel(
            email, 
            **otherAttributes
        )
        user.save()

        # Generate response
        return response_object(
            f"Successfully signed in, a confirmation code has been sent to {response['CodeDeliveryDetails']['Destination']}",
            200,
            None
        ) 

    except Exception as e:
        return response_object(e, 400, None) 

@app.route('/confirm_sign_up', methods=['POST'])
def confirm_sign_up():
    try:
        # Extract parameters from request
        body = json.loads(request.data)

        user_email = body.get('user_email')
        code = body.get('confirmation_code')

        # Confirm user sign up
        response = cognito_client.confirm_sign_up(
            ClientId = cognito_client_id,
            Username = user_email,
            ConfirmationCode = code
        )

        # Generate response
        return response_object("Successfully confirmed signup", 200, data=response)
    
    except cognito_client.exceptions.CodeMismatchException:
        return response_object("Supplied code is invalid", 402)

    except SystemError:
        return response_object("An error occurred", 400) 

@app.route('/login', methods=['POST'])
def log_in():
    try:
        # Extract parameters from request
        body = json.loads(request.data)

        user_email = body.get('user_email')
        password = body.pop('password')

        # Log in the user
        response = cognito_client.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters = {
                'USERNAME': user_email,
                'PASSWORD': password
            },
            ClientId = cognito_client_id
        )

        # Generate response
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
        response = UserModel.get(request.auth_user_id).to_json()

        return response_object(
            "Successfully fetched data",
            200,
            json.loads(response)
        )

    except SystemError:
        return response_object("An error occurred", 400) 


if __name__ == "__main__":
    app.run(debug = False)