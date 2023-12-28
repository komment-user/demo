
/**
* @description This function fetches data from a Reddit API based on a specified
* subreddit and logs the response to the console.
* 
* @param { string } sub - The `sub` input parameter is a subreddit name or label
* that filters the content of the API request to the specified subreddit.
* 
* @returns { object } This function fetches data from a Reddit API endpoint using
* Axios. It takes an optional subreddit parameter defaulting to 'programming'.
* The output of the function depends on whether there's a response from the API or
* not:
* If no errors occur and an API response is received: The console logs the API response.
* If there's an error :The console logs the error .
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
* @description This function implements a binary search algorithm to find an element
* `x` within an array `arr`. It takes four parameters: `arr`, `x`, `start`, and
* `end`. The function first checks if the start and end indices are out of order
* (i.e., `start>end`), and returns false if so. Otherwise it calculates the midpoint
* `mid` of the range `[start..end]` and checks if `arr[mid]` is equal to `x`. If it
* is equal , the function returns true.
* 
* If `arr[mid]` is greater than `x`, the function recursively calls itself with the
* search bounds adjusted to `start...mid-1` or `mid+1...end` depending on whether
* `arr[mid]` is greater or less than `x`. This process continues until the element
* is found or it is determined that `x` is not present within the range.
* 
* @param { array } arr - The `arr` input parameter is the array that should contain
* the sought value.
* 
* @param { any } x - In the `search` function provided by the question giver - an
* array of unknown size 'arr' containing an element or values and two integer arguments
* for both extreme index within which 'element x'.
* 
* @param { number } start - The `start` input parameter represents the beginning
* index of the array where the search will start looking for the target element `x`.
* 
* @param { number } end - The `end` parameter determines the upper bound of the
* subarray that is being searched.
* 
* @returns { boolean } The output of this function is `true` or `false`. The function
* takes an array and a target value as input and repeatedly divides the search space
* into two parts (using the midpoint) until it finds the target value or determines
* that it is not present. If the target value is found (i.e., `arr[mid]` matches the
* input `x`), the function returns `true`.
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

