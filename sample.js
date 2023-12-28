/**
* @description This function fetches data from a Reddit API using Axios and returns
* the response or an error message depending on the success or failure of the request.
* 
* @param { string } sub - The `sub` input parameter is a string that specifies the
* subreddit for which content should be fetched.
* 
* @returns { object } The output of the `fetch` function is a promise that resolves
* to an object containing the content of the specified Reddit thread. If the request
* fails due to network errors or other issues., the function returns null.
*/
function fetch(sub = 'programming') {
    const axios = require('axios')

    axios.get(`https://www.reddit.com/r/\${sub}.json`)
    .then((response) => {
        console.log(response);
        return response;
    })
    .catch((error) => {
        console.error(error);
        return null;
    });
}


/**
* @description This function performs a binary search on an array `arr` for the value
* `x`. It takes four arguments: `arr`, `x`, `start`, and `end`. It returns `true`
* if `x` is found between `start` and `end`, or `false` if it's not found.
* 
* @param { array } arr - The `arr` input parameter is the array that needs to be
* searched for the specified value `x`.
* 
* @param { any } x - The `x` input parameter represents the element to be searched
* within the array `arr`.
* 
* @param { number } start - The `start` input parameter determines the left endpoint
* of the subarray being searched.
* 
* @param { number } end - The `end` input parameter determines the upper bound of
* the subarray being searched.
* 
* @returns { array } The function `search` takes an array `arr`, a search value `x`,
* and three indexes `start`, `end`, and `mid`. It returns `true` if `x` is found
* within the range `[start..end]`.
* 
* The function works by repeatedly dividing the range `[start..end]` into two halves
* until it finds the search value or reaches the boundary of the array.
*/
const search = (arr, x, start, end) => {
  if (start > end) return false;
  let mid = Math.floor((start + end)/2);

  if (arr[mid]===x) return true;
        
  if (arr[mid] > x) {
    return search(arr, x, start, mid-1);
  } else {
    return search(arr, x, mid+1, end);
  }
}


/**
* @description This is an AWS Lambda function that handles various routes for FIDO2
* authentication.
* 
* @param { object } event - The `event` input parameter is an object that contains
* information about the current HTTP request or API call. It provides context and
* metadata about the event that triggered the function call.
* 
* @returns { object } The output of this function is a JSON object with the following
* properties:
* 
* 	- `statusCode`: an integer value indicating the HTTP status code to be returned
* (200 if successful or one of 40x/50x if there is an error)
* 	- `body`: a string containing the body of the HTTP response
* 	- `headers`: an object containing custom HTTP headers.
* 
* The function returns this output based on the incoming request event and the claim
* values obtained from the authorization token.
*/
const handler = async(event) => {
    try {
        const { sub, email, phone_number: phoneNumber, name, "cognito:username": cognitoUsername, } = event.requestContext.authorizer.jwt.claims;
        const userHandle = determineUserHandle({ sub, cognitoUsername });
        const userName = email ?? phoneNumber ?? name ?? cognitoUsername;
        const displayName = name ?? email;
        if (event.pathParameters.fido2path === "register-authenticator/start") {
            logger.info("Starting a new authenticator registration ...");
            if (!userName) {
                throw new Error("Unable to determine name for user");
            }
            if (!displayName) {
                throw new Error("Unable to determine display name for user");
            }
            const rpId = event.queryStringParameters?.rpId;
            if (!rpId) {
                throw new UserFacingError("Missing RP ID");
            }
            if (!allowedRelyingPartyIds.includes(rpId)) {
                throw new UserFacingError("Unrecognized RP ID");
            }
            const options = await requestCredentialsChallenge({
                userId: userHandle,
                name: userName,
                displayName,
                rpId,
            });
            logger.debug("Options:", JSON.stringify(options));
            return {
                statusCode: 200,
                body: JSON.stringify(options),
                headers,
            };
        }
        else if (event.pathParameters.fido2path === "register-authenticator/complete") {
            logger.info("Completing the new authenticator registration ...");
            const storedCredential = await handleCredentialsResponse(userHandle, parseBody(event));
            return {
                statusCode: 200,
                body: JSON.stringify(storedCredential),
                headers,
            };
        }
        else if (event.pathParameters.fido2path === "authenticators/list") {
            logger.info("Listing authenticators ...");
            const rpId = event.queryStringParameters?.rpId;
            if (!rpId) {
                throw new UserFacingError("Missing RP ID");
            }
            if (!allowedRelyingPartyIds.includes(rpId)) {
                throw new UserFacingError("Unrecognized RP ID");
            }
            const authenticators = await getExistingCredentialsForUser({
                userId: userHandle,
                rpId,
            });
            return {
                statusCode: 200,
                body: JSON.stringify({
                    authenticators,
                }),
                headers,
            };
        }
        else if (event.pathParameters.fido2path === "authenticators/delete") {
            logger.info("Deleting authenticator ...");
            const parsed = parseBody(event);
            assertBodyIsObject(parsed);
            logger.debug("CredentialId:", parsed.credentialId);
            await deleteCredential({
                userId: userHandle,
                credentialId: parsed.credentialId,
            });
            return { statusCode: 204 };
        }
        else if (event.pathParameters.fido2path === "authenticators/update") {
            const parsed = parseBody(event);
            assertBodyIsObject(parsed);
            await updateCredential({
                userId: userHandle,
                credentialId: parsed.credentialId,
                friendlyName: parsed.friendlyName,
            });
            return { statusCode: 200, headers };
        }
        return {
            statusCode: 404,
            body: JSON.stringify({ message: "Not found" }),
            headers,
        };
    }
    catch (err) {
        logger.error(err);
        if (err instanceof UserFacingError)
            return {
                statusCode: 400,
                body: JSON.stringify({ message: err.message }),
                headers,
            };
        return {
            statusCode: 500,
            body: JSON.stringify({ message: "Internal Server Error" }),
            headers,
        };
    }
}

