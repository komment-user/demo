/**
* @description This function fetches data from a Reddit API using Axios. It takes
* an optional parameter `sub` which specifies the subreddit to fetch posts from.
* 
* @param { string } sub - The `sub` input parameter specifies the subreddit for which
* the posts should be fetched.
* 
* @returns { object } The output of the function `fetch` is an object representing
* the JSON data retrieved from the specified Reddit subreddit. If no subreddit is
* specified (e.g., when calling the function with `sub = ''`), the function returns
* a default object containing the top-level comments for the specified subreddit.
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
* @description This function performs a binary search on an array `arr` for an element
* `x`.
* 
* @param { array } arr - The `arr` input parameter is the array to be searched.
* 
* @param { any } x - The `x` input parameter is the element to be searched for within
* the array `arr`.
* 
* @param { number } start - The `start` parameter defines the beginning index of the
* search range within the array.
* 
* @param { number } end - The `end` input parameter specifies the end index of the
* range to be searched for the element `x`.
* 
* @returns { boolean } This function takes an array `arr`, a value `x`, and three
* indexes `start`, `end`, and `mid` as input. It searches for the value `x` within
* the array `arr` starting from index `start` until index `end`.
* 
* The output returned by this function is either `true` if `x` is found within the
* array at index `mid`, or `false` if it is not found.
* 
* Here's a concise description of the function:
* 
* Searches for the value 'x' within the array 'arr' starting from index 'start' until
* index 'end'.
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
* @description This function is an AWS Lambda function that handles four different
* endpoints for a FIDO2 authenticator server:
* 
* 1/ `register-authenticator/start`: Start the registration of a new authenticator
* for a user.
* 2/ `register-authenticator/complete`: Complete the registration of a new authenticator
* for a user.
* 3/ `authenticators/list`: List all existing authenticators for a user.
* 4/ `authenticators/delete` and `authenticators/update`: Delete or update an existing
* authenticator for a user.
* 
* The function takes an event object as input and uses the `requestContext.authorizer.jwt.claims`
* to retrieve the user handle and other information from the request.
* 
* @param { any } event - The `event` input parameter is an AWS API Gateway event
* object that contains information about the incoming request.
* 
* @returns { object } The output of the function is a HTTP response object that
* contains the following information:
* 
* 	- `statusCode`: an integer indicating the HTTP status code (either 200 OK for a
* successful request or 404 Not Found if the requested path parameter is not found)
* 	- `body`: a string containing the JSON payload of the response (which can be empty
* if `statusCode` is 404)
* 	- `headers`: an object containing the headers of the HTTP response.
* 
* The function handles several possible paths and determines which path is requested
* based on the value of `event.pathParameters.fido2path`. It then returns a appropriate
* response based on the path.
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




