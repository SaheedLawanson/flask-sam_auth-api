# FLASK SAM AUTH API
This repo contains an API with authentication and authorization: sign_up, sign_in, forgot password, change password and so on, built using Flask framework and AWS Cognito API which is to be deployed to AWS Lambda using AWS SAM.

## Technologies Used
- Flask Lambda
- AWS SAM & Cognito
- Docker

## Usage
-  To install dependencies, run: ```pip install -r requirements.txt``` in your terminal
-  To run locally:
    - set the environmental variable AWS_ENVIRONMENT: ```export AWS_ENVIRONMENT=local``` for linux and ```set AWS_ENVIRONMENT=local``` for windows.
    -  run ```docker-compose up``` to start up a cognito and dynamodb locally.
    -  then run ```python ./security-endpoints/app.py``` to start the server.
    
-  To run on AWS cloud:
    -  run the following commands in the terminal
        -  ```sam build```
        - ```sam deploy```
- Test end points with postman: import the api documentation using the json link [here](https://www.getpostman.com/collections/8f0643c4dab2cf1b6e4d)


## Note
Currently, the flask lambda framework has a bug, view the git hub issue [here](https://github.com/sivel/flask-lambda/pull/14/commits/5c54ab08f29132acd65e97c9ac971bd023e5366f) , so before you run ```sam deploy``` replace:

```
from werkzeug.wrappers import BaseRequest
```
with
```
try: # werkzeug <= 2.0.3
    from werkzeug.wrappers import BaseRequest
except: # werkzeug > 2.1
    from werkzeug.wrappers import Request as BaseRequest
```
in the flask_lambda.py file of your local python modules and also in the ".aws-sam/deps" folder
