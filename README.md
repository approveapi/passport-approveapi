# passport-approveapi
ApproveAPI passwordless authentication strategy for PassportJS

## Installation

  `npm install passport-approveapi`
  
## Usage

### Configure Strategy

  The ApproveAPIStrategy constructor receives three parameters:

  * `options`: A javascript object containing some configuration:
    * `apiKey` An ApproveAPI api key.
    * `callbackUrl`: A URL which users will be redirected to once they approve the login prompt. Must be set as an endpoint for acceptToken.
    * `contactField`: The name of the field which contains the email or other contact handle of the user to send the prompt to.
    * `promptMessage`: The message included with the login prompt.
    * `ttl`: Optional integer, defaults to 10 minutes (in seconds). It's used to set the token and prompt expiration.
    * `secret`: An encryption secret used to sign the login tokens.
  * `verifyUser`: A function that receives the request and returns a promise containing the user object. It may be used to insert and/or find the user in the database.
  
### Authenticate Requests
  
  Use `passport.authenticate()`, specifying the `'approveapi'` strategy for two actions:
  
#### requestToken
  In this situation the passport authenticate middleware will send a token produced by the user information, which is returned by the `verifyUser` function.
  
  ```javascript
  app.post('/auth/approveapi',
      passport.authenticate('approveapi', { action : 'requestToken' }),
      (req, res) => res.redirect('/check-your-inbox')
  )
  ```
  
#### acceptToken
  In this situation the passport authenticate middleware will check for a valid token.
  
  ```javascript
  app.get('/auth/approveapi/callback',
    passport.authenticate('approveapi', { action : 'acceptToken' }),
    (req, res) => res.redirect('/profile')
  )
  ```
