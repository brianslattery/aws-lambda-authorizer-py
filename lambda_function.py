# Copyright 2020 Brian J Slattery <oss@brnsl.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Example Python script for a basic AWS Lambda Authorizer.
"""
import jwt
from os import environ

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

def lambda_handler(evt, ctx):

    '''
    Extract the token. Remove the `Bearer ` prefix. Set encoding.
    '''
    tkn = evt['authorizationToken']
    tkn = tkn[7:len(tkn)]
    tkn = tkn.encode('utf8')

    '''
    We're not using this here, but also available is the method ARN which can
    be used alongside additional logic if desired.
    '''
    method_arn = evt['methodArn']

    claims = jwt.decode(tkn, PUB_KEY)

    assert USER_ID_CLAIM in claims, 'Claims must include \'user_id\''

    '''
    NOTE: This is an overly relaxed policy. Consider changing it to be more
    restrictive based on requirements. Principle of Least Privilege. You can
    also create multiple statements within the document as necessary.
    '''
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

    '''
    Iterate over the claims from the token. Add them to the context if they are
    valid types for the returned context (String, Number, Boolean).
    '''
    ctx = {}
    for k,v in claims.items():
        if is_valid_context_type(v):
            ctx[k] = v
        else:
            thetp = type(v)
            print('Token claim {} for {} is neither. = {}'.format(v, k, thetp))

    policy['context'] = ctx

    return policy

def is_valid_context_type(claim_value):
    """
    Returns true if the value type
    https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-
    lambda-authorizer-output.html
    """
    return isinstance(claim_value, str) or \
            isinstance(claim_value, int) or \
            isinstance(claim_value, unicode)
