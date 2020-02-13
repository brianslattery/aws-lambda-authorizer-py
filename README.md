# Authorizer Lambda for AWS API Gateway

The intent of this is to outline a pattern for creating a Python Lambda in AWS to serve a *basic* Authorization function that will evaluate a JSON Web Token (JWT).

The goal is to gain a basic understanding of one possible pattern, and to understand how to work through some common errors that may be received while attempting to do so.

## Assumptions
* You have an AWS account
* You know how to deploy an EC2 Image
* You have an SSH client

## External libraries
* [PyJWT](https://pyjwt.readthedocs.io/en/latest)
* [Cryptography](https://cryptography.io)
  * [CFFI](http://cffi.readthedocs.org/)
  * [pycparser](https://github.com/eliben/pycparser)

## Step 1: Preparing the dependencies (imports)

1. Deploy an **Amazon Linux 2 AMI** EC2 instance. A **t2-micro** will work just fine.
2. Connect to the EC2 instance: `ssh ec2-user@52.12.110.70`
3. `sudo yum install python3`
4. `mkdir py && cd py`
5. `pip3 install pyjwt -t .`
6. `pip3 install cryptography -t .`
7. `cd .. && zip -r imports.zip py/`
8. `exit` - back on local system now
9. `scp ec2-user@52.12.110.70:~/imports.zip .`

At this point, we have the required dependencies in a zip file, and have brought them back to our local system.

## Step 2: Complete the Lambda function
In this step, we'll put together the user-defined code. If you've created a Lambda function before, the general concepts AWS_REGION _mostly_ the same. The main difference is that there is a contract that must be followed - the returned object must meet certain criteria. While the Lambda itself may complete just fine, when integrated as an Authorizer, that process will fail if it returns an unexpected object.

1. We'll need to import the PyJWT library, so lets start there. We also import environ to read from the Lambda environment.
  ~~~~
  import jwt
  from os import environ
  ~~~~
The other libraries will be imported within the PyJWT package; our entry point is PyJWT so we'll only need that.

2. Now we define some constants.
We'll set the public key that we'll accept, a key for a claim that we're going to use, and the resource pattern.
  ~~~~
  # Public key from JWT.io (RS256)
  PUB_KEY = '-----BEGIN PUBLIC KEY-----\n\
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\n\
  vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\n\
  aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\n\
  tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\n\
  e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\n\
  V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\n\
  MwIDAQAB\n\
  -----END PUBLIC KEY-----'

  USER_ID_CLAIM = 'user_id'

  region = environ['AWS_REGION']
  resource_pattern = 'arn:aws:execute-api:{}:**'.format(region)
  ~~~~

3. A Lambda starts with a method which will serve as an entry point, so we add that:
  ~~~~
  def lambda_handler(event, context):
  ~~~~
The event object will "look" like this:
  ~~~~
  {
    "type": "TOKEN",
    "authorizationToken": "Bearer {jwt}",
    "methodArn": "arn:aws:execute-api:{REGION}:{ACCOUNT_ID}:path"
  }
  ~~~~
> The `Bearer` prefix is a standard pattern, so we'll expect that to be part of the request header. This is not something that is AWS specific. Technically, you could leave this out, but it would not be following standards.


4. We'll need to extract the token from our event, so we can use this code:
  ~~~~
  tkn = evt['authorizationToken']
  # Remove the `Bearer ` prefix
  tkn = jwt[7:len(jwt)]
  tkn = jwt.encode('utf-8')
  ~~~~

5. Decode the token and validate it. PyJWT will perform most of the validations. We add an assertion that the `user_id` is present, as we'll use that later on.
  ~~~~
  claims = jwt.decode(tkn, PUB_KEY)
  assert USER_ID_CLAIM in claims, 'Claims must include \'user_id\''
  ~~~~

6. Define a Policy object
This is only an example; you can and should be far more restrictive. Each scenario should be evaluated, and the most restrictive security that can be used should be used. The *Resource* value is set the resource we defined earlier on. The *principalId* is taken from the dict object that was returned via successful decoding of the JWT.
  ~~~~
  policy = {
      'principalId': claims[USER_ID_CLAIM],
      'policyDocument': {
          'Version': '2012-10-17',
          'Statement': [{
              'Effect': 'Allow',
              'Action': 'execute-api:Invoke',
              'Resource': resource_pattern
            }
           ]
      }
  }
  ~~~~

7. Add additional data to the context
This implementation iterates over the claims, and adds them to teh context if able. You may want to be more explicit here, but this will cover basic use cases. If the claims set contains non-primitive types, some additional transformations will need to occur. The returned object will be rejected when used by an Authorizer if context values are anything but String, Number, or Boolean. All values are treated as text.
  ~~~~
  ctx = {}
  for k,v in claims.items():
      if is_valid_context_type(v):
          ctx[k] = v

  policy['context'] = ctx
  ~~~~
Outside of the `lambda_handler` method, we'll create a utility method:
  ~~~~
  def is_valid_context_type(claim_value):
      return isinstance(claim_value, str) or \
              isinstance(claim_value, int) or \
              isinstance(claim_value, unicode)
  ~~~~
> Some may wonder why not use *basestring* in lieu of *str* and *unicode* -> It is no longer valid Python 3.

## Step 3: Bundle the user-defined code and libraries.
1. Unzip the imports.zip file we retrieved in *Step 1*.
2. Add the user-defined code, `lambda_function.py`.
3. Zip everything back up.

## Step 4: Deploy the Lambda


### AWS Console Version
1. Navigate to the Lambda service in the AWS Console.
2. In the upper right corner of the page, click **Create Function**.
3. Enter a function name such as `my-authorizer-lambda`.
4. For the runtime, choose **Python 3.7**.
> This should align with the Python version that you use on the EC2 instance. In
testing, my experience was that 3.7 is the latest version on EC2. Using 3.8
resulted in the following error: `No module named '_cffi_backend'`
5. _(Optional)_ Expand **Choose or create an execution role** and either configure or use an existing role. The default option will suffice for this.
6. Click **Create Function** in the bottom right. (This takes a few seconds).
7. Navigate to the second section titled **Function code**. Locate the **Code entry type** drop down, and select **Upload a .zip file**.
8. Select the **Upload** button, navigate to the zip from Step 3, and choose **Open**.
9. Click **Save** in the upper right side of the page.

### AWS CLI Version (to-do)

## Step 4: Testing

A sample JWT can be obtained from [JWT.io]. A sample is also included below. If you choose to generate your own, do ensure that the Public Key is the same. This example is based on `RS256`.

### Basic
1. Click **Test** in the upper right side of the page. (This will invoke a modal to create a new test event as we've not previously created one.)
2. In the drop-down of the *Configure test event* modal, select **Amazon API Gateway Authorizer**.
3. Set an event name. This is something only you will see (or anyone else that uses the same account (yikes!)). Perhaps call it `TestValidToken`.
4. Enter `Bearer ` plus the JWT token (there is one in *Sample Data* below)
5. Click the **Create** button. The modal will close.
6. Notice that the dropdown to the left of the *Create* button now shows your new event. (If it does not, expand and select the event you just created). Click **Test**. You should see *Execution result: succeeded*.
7. Poke around, explore, learn!

### From API Gateway
TODO

## Sample Data

### Valid JWT

~~~~
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZmlyc3RfbmFtZSI6ImJyaWFuIiwibGFzdF9uYW1lIjoic2xhdHRlcnkiLCJ1c2VyX2lkIjoibmNjMTcwMWEifQ.E4S6uqW2S_v5Bax1aWdU219s82FjgQgQONt0u44hU4n52-g4SvDloP_yyDBWgeYP6JSgGhQpdMy4LXFZIiLTMCpumyBEfmsowJBlm2rrR8MQnKmLVxpYRrzvBfRci-JwIo8I-kHL3-xJkZec66vB4ueo057-mdkOMkXfdEDOBLmgleO5I8s5p9yfGY5bPkMjC3bN_2Hu8h0TGGJYXR6nQgyRc8NVauavB4Hj4SIwqR_O_Yvht5S90t_onADtdW3I_AtJ8iM3-95Po-zng2XrGumQL-y64WqUNRcqqkIstcoTkpwYyL4UfgdcbgpGlt84NbcSGNMhIxQtKQg1OJu0fw
~~~~

### Invalid JWT (Signature)
~~~~
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxGW9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cmGvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA
~~~~

### Public Key
~~~~
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----
~~~~

## License
[MIT License](https://brn.mit-license.org)

[JWT.io]: https://jwt.io
