
/**
* @description This function fetches data from a Reddit API endpoint using Axios and
* logs the response to the console.
* 
* @param { string } sub - The `sub` input parameter is a subreddit name or topic
* that the function fetches data for.
* 
* @returns { object } The output returned by this function is a promise that resolves
* to the response object from the Reddit API for the specified subreddit.
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
* @description This function implements a recursive algorithm to find an element 'x'
* within a sorted array 'arr'. It works by finding the middle index of the array
* 'mid', and then checking if 'x' is equal to 'arr[mid]'.
* 
* @param { array } arr - The `arr` input parameter is the array to be searched.
* 
* @param { any } x - The `x` input parameter is the element to be searched within
* the array.
* 
* @param { number } start - The `start` input parameter determines the beginning of
* the subarray to be searched.
* 
* @param { number } end - The `end` input parameter specifies the endpoint of the
* range to search within the array. It determines the index beyond which the function
* should not continue searching for the element.
* 
* @returns { boolean } This function is a binary search algorithm that takes an array
* and three parameters: x (the value to search for), start (the beginning index of
* the range to search), and end (the ending index of the range to search).
* 
* The function works by first checking if the start and end indices are out of order
* (i.e., if end is less than start). If so (i.e., if end < start), it immediately
* returns false.
* 
* Next (if start > end does not hold true), the function calculates the midpoint of
* the range by rounding down to the nearest integer withMath.floor() and then checks
* if the value at that index matches the search value x. If they do match (i.e.,
* arr[mid]===x), the function returns true immediately.
* 
* If they don't match (i.e., arr[mid] > x), the function recursively calls itself
* with the same arguments except with start and end reversed (start becomes mid-1
* and end becomes mid+1). This effectively divides the search space into two smaller
* subspaces around the midpoint.
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

