/**
* @description This function fetches data from a Reddit API using the `axios` library.
* 
* @param { string } sub - In the given function `fetch`, the `sub` input parameter
* is a string that specifies the subreddit to retrieve data from.
* 
* @returns { object } The output returned by this function is a promise that resolves
* to the response data from the Reddit API for the specified subreddit (determined
* by the `sub` parameter).
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
* @description This function performs a binary search on an array of items to find
* a specific item (x).
* 
* @param { array } arr - The `arr` input parameter is the array to be searched.
* 
* @param { any } x - In the provided function `search`, the input parameter `x` is
* the element to be searched within the array `arr`.
* 
* @param { number } start - The `start` parameter defines the beginning index of the
* range of elements to be searched.
* 
* @param { number } end - The `end` parameter specifies the last index of the array
* to be searched.
* 
* @returns { boolean } The function `search` takes an array `arr`, a target value
* `x`, and three indexes `start`, `end`, and returns `true` or `false` indicating
* whether `x` exists between `start` and `end` inclusive.
* 
* The function works by repeatedly dividing the search interval into two halves using
* the midpoint formula `mid = (start + end) / 2`. If the target value matches the
* value at index `mid`, the function returns `true`. If the value at `mid` is greater
* than `x`, the function recursively calls itself with `start` updated to `mid-1`,
* otherwise it recalls itself with `end` updated to `mid+1`.
* 
* In essence:
* 
* 	- The function first checks if the target is equal to the middle element of the
* search interval. If so - true is returned.
* 	- Otherwise it divides the interval into two parts and repeats the same check on
* one of them.
* 	- This process continues until either x is found or the interval is reduced to a
* single element.
* 
* Therefore: the function returns `true` if `x` exists anywhere within the interval
* specified by `start` and `end`.
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

