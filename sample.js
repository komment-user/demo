/**
* @description This function fetches the JSON data from a Reddit thread with the
* specified `sub` parameter (defaults to "programming") using Axios.
* 
* @param { string } sub - The `sub` input parameter specifies the subreddit name to
* fetch content for.
* 
* @returns { object } The function `fetch` takes a subreddit name as an optional
* parameter (`sub` = 'programming' here) and makes an axios GET request to `https://www.reddit.com/r/$sub.json`.
* 
* The output returned by the function is:
* 
* 1/ The response data from Reddit's API (logged to the console).
* 2/ Null if there was an error accessing the API.
* 
* In other words - a promise of the response or null.
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
* @description This function implements a binary search algorithm that searches for
* an element `x` within an array `arr`.
* 
* @param { array } arr - The `arr` input parameter is the array that contains the
* element to be searched for.
* 
* @param { any } x - The `x` input parameter represents the value to be searched
* within the array passed as the first argument to the function.
* 
* @param { number } start - The `start` parameter specifies the left boundary of the
* subarray to be searched.
* 
* @param { number } end - The `end` input parameter determines the end of the range
* for which the `search` function should look for the given `x`.
* 
* @returns { boolean } The function `search` takes an array `arr`, a target value
* `x`, and three indices `start`, `end`, and `mid` as parameters. It checks if `x`
* exists anywhere within `arr` using binary search.
* 
* The output returned by the function is `true` or `false`, depending on whether `x`
* was found within the array or not.
* 
* Here's a step-by-step description of the function:
* 
* 1/ Check if `start` is greater than `end`. If so. the search ends immediately with
* a return value of `false`.
* 2/ Calculate the midpoint of the range (`mid = (start + end)/2`).
* 3/ If the element at the midpoint equals `x`, the function returns `true`.
* 4/ If the element at the midpoint is greater than `x`, then the target value must
* be within the lower half of the range. In this case:
*    a. Check if the starting index of the lower half is less than or equal to the
* current midpoint (`mid-1`). If not. the search ends with a return value of `false`.
*    b. Recursively call the function with `arr`, `x`, `start`, and `mid-1`.
* 5/ Otherwise (the element at the midpoint is less than or equal to `x`), the target
* value must be within the upper half of the range. In this case:
*    a. Check if the ending index of the upper half is greater than the current
* midpoint (`mid+1`). If not. the search ends with a return value of `false`.
*    b. Recursively call the function with `arr`, `x`, `mid+1`, and `end`.
* 6/ If no valid index is found during either of these two recursive calls (stepped
* 4b or 5b), the search ends with a return value of `false`.
* 
* So to summarize: the function searches for `x` within the range `[start..end]` by
* repeatedly dividing the range into smaller segments using the midpoint and recurrency
* until either `x` is found or it can be established that `x` does not exist within
* the range.
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

