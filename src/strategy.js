const ApproveAPI = require('approveapi');
const jwt = require('jsonwebtoken');
const PassportStrategy = require('passport-strategy');
const {promisify} = require('util')
const lookup = require('./lookup')

class ApproveAPIStrategy extends PassportStrategy {
  /**
   * @param {string} apiKey - A key for ApproveAPI
   * @param {string} callbackUrl - The URL that the magic link will be set to. This URL should utilize the acceptToken action as a middleware.
   * @param {string} contactField - The email/contact-info field from the request
   * @param {string} promptMessage - The message included with the passwordless login prompt
   * @param {string} secret - The secret to sign the token with
   * @param {Number} ttl - Time to live
   * @param {Function} verifyUser - A function to verify the user
   */
  constructor (
    {
      apiKey,
      callbackUrl,
      contactField,
      promptMessage,
      ttl = 60 * 10, // default: 10 minutes
    },
    verifyUser
  ) {
    if (!apiKey) throw new Error('ApproveAPI magic link authentication strategy requires an ApproveAPI key');
    if (!callbackUrl) throw new Error('ApproveAPI magic link authentication strategy requires a callback URL');
    if (!contactField) throw new Error('ApproveAPI magic link authentication strategy requires a contact field');
    if (!promptMessage) throw new Error('ApproveAPI magic link authentication strategy requires a login prompt message');
    if (!verifyUser) throw new Error('ApproveAPI magic link authentication strategy requires a verifyUser function');
    super()

    this.name = 'approveapi'
    this.callbackUrl = callbackUrl
    this.contactField = contactField
    this.promptMessage = promptMessage
    this.secret = apiKey
    this.ttl = ttl
    this.verifyUser = verifyUser

    this.tokenField = 'token'

    this.approveAPIClient = ApproveAPI.createClient(apiKey);
    this.sendToken = async function(user, token) {
      const contactInfo = lookup(user, this.contactField)
      if (!contactInfo) {
        throw new Error('Unable to parse the contact field from of the given user')
      }

      let redirect_url
      if (this.callbackUrl.includes('?')) {
        redirect_url = this.callbackUrl + '&' + this.tokenField + '=' + token
      }
      else {
        redirect_url = this.callbackUrl + '?' + this.tokenField + '=' + token
      }

      const params = {
        'approve_redirect_url': redirect_url,
        'approve_text': 'Log In',
        'body': this.promptMessage,
        'expires_in': this.ttl,
        'user': contactInfo
      };
      return this.approveAPIClient.createPrompt(params);
    }
  }

  async authenticate(req, options = {}) {
      const _options = {
          action: 'acceptToken',
          ...options
      };

      if (_options.action === 'requestToken') {
          return this.requestToken(req, _options)
      }
      else if (_options.action === 'acceptToken') {
          return this.acceptToken(req, _options)
      }
      else {
          return this.error(new Error('Unknown action'))
      }
  }    
  
  async acceptToken (req, options) {
    const token = lookup(req.body, this.tokenField) || lookup(req.query, this.tokenField)

    if (!token) {
      return this.fail({message: 'Token missing'})
    }

    let user
    // Verify JWT
    try {
      const verifyToken = promisify(jwt.verify)
      let {user: tokenUser} = await verifyToken(
        token,
        this.secret
      )
      user = tokenUser
    } catch (err) {
      return this.fail({message: err.message})
    }

    // Pass setting a passport user
    // Next middleware can check req.user object
    return this.success(user)
  }

  async requestToken (req, options) {
    let userFields = {}
    let user

    //Lookup ApproveAPI contact information
    const contact = lookup(req.body, this.contactField) || lookup(req.query, this.contactField);
    if (!contact) {
        return this.fail(new Error('Contact information missing'));
    }
    userFields[this.contactField] = contact;

    // Verify user
    try {
      user = await this.verifyUser(userFields)
    } catch (err) {
      return this.error(err)
    }

    if (!user) {
      return this.fail(
        {message: options.authMessage || `No user found`},
        400
      )
    }

    // Generate JWT
    const createToken = promisify(jwt.sign)
    let token
    try {
      token = await createToken(
        {user: user, iat: Math.floor(Date.now() / 1000)},
        this.secret,
        {expiresIn: this.ttl}
      )
    } catch (err) {
      return this.error(err)
    }

    // Deliver JWT
    try {
      await this.sendToken(user, token)
    } catch (err) {
      return this.error(err)
    }

    return this.pass({message: 'Token succesfully delivered'})
  }
}

module.exports = ApproveAPIStrategy