/**
 * Copyright 2013 Nomura Research Institute, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The following software is included for convenience: JSJWS, JSRSASIGN, CryptoJS;
 * Use of any of these software may be governed by their respective licenses.
 */

/**
  * The 'jsjws'(JSON Web Signature JavaScript Library) License
  *
  * Copyright (c) 2012 Kenji Urushima
  *
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
  * in the Software without restriction, including without limitation the rights
  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  * copies of the Software, and to permit persons to whom the Software is
  * furnished to do so, subject to the following conditions:
  *
  * The above copyright notice and this permission notice shall be included in
  * all copies or substantial portions of the Software.
  *
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  * THE SOFTWARE.
 */

/**
 * The 'jsrsasign'(RSA-Sign JavaScript Library) License
 *
 * Copyright (c) 2010-2013 Kenji Urushima
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

/**
 * The Crypto-JS  license
 *
 * (c) 2009-2013 by Jeff Mott. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this list
 * of conditions, and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions, and the following disclaimer in the documentation or other
 * materials provided with the distribution.
 *
 * Neither the name CryptoJS nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS," AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */



/**
 * OIDC namespace
 * @namespace OIDC
 */
var OIDC = namespace('OIDC');

/**
 * @property {array} OIDC.supportedProviderOptions                                 - List of the Identity Provider's configuration parameters
 * @property {string} OIDC.supportedProviderOptions.issuer                         - Issuer ID
 * @property {string} OIDC.supportedProviderOptions.authorization_endpoint         - Authorization Endpoint URL
 * @property {string} OIDC.supportedProviderOptions.jwks_uri                       - JWKS URL
 * @property {boolean} OIDC.supportedProviderOptions.claims_parameter_supported    - Claims parameter support
 * @property {boolean} OIDC.supportedProviderOptions.request_parameter_supported   - Request parameter support
 * @property {object} OIDC.supportedProviderOptions.jwks                           - Identity Provider's JWK Set
 * @readonly
 * @memberof OIDC
 */
OIDC.supportedProviderOptions = [
    'issuer',
    'authorization_endpoint',
    'jwks_uri',
    'claims_parameter_supported',
    'request_parameter_supported',
    'jwks'

    /*
    / Reserve for future use
    'token_endpoint',
    'userinfo_endpoint',
    'check_session_iframe',
    'end_session_endpoint',
    'registration_endpoint',
    'scopes_supported',
    'response_types_supported',
    'grant_types_supported',
    'acr_values_supported',
    'subject_types_supported',
    'userinfo_signing_alg_values_supported',
    'userinfo_encryption_alg_values_supported',
    'id_token_signing_alg_values_supported',
    'id_token_encryption_alg_values_supported',
    'id_token_encryption_enc_values_supported',
    'request_object_signing_alg_values_supported',
    'request_object_encryption_alg_values_supported',
    'request_object_encryption_enc_values_supported',
    'token_endpoint_auth_methods_supported',
    'token_endpoint_auth_signing_alg_values_supported',
    'display_values_supported',
    'claim_types_supported',
    'claims_supported',
    'service_documentation',
    'ui_locales_supported',
    'require_request_uri_registration',
    'op_policy_uri',
    'op_tos_uri',
    'claims_locales_supported',
    'request_uri_parameter_supported',
    */
];

/**
 * @property {array} OIDC.supportedRequestOptions                  - Supported Login Request parameters
 * @property {string} OIDC.supportedRequestOptions.scope           - space separated scope values
 * @property {string} OIDC.supportedRequestOptions.response_type   - space separated response_type values
 * @property {string} OIDC.supportedRequestOptions.display         - display
 * @property {string} OIDC.supportedRequestOptions.max_age         - max_age
 * @property {string} [OIDC.supportedRequestOptions.state]         - state
 * @property {string} [OIDC.supportedRequestOptions.nonce]         - nonce
 * @property {object} OIDC.supportedRequestOptions.claims          - claims object containing what information to return in the UserInfo endpoint and ID Token
 * @property {array} OIDC.supportedRequestOptions.claims.id_token  - list of claims to return in the ID Token
 * @property {array} OIDC.supportedRequestOptions.claims.userinfo  - list of claims to return in the UserInfo endpoint
 * @property {boolean} OIDC.supportedRequestOptions.request        - signed request object JWS. Not supported yet.
 * @readonly
 * @memberof OIDC
 *
 */
OIDC.supportedRequestOptions = [
    'scope',
    'response_type',
    'display',
    'max_age',
    'claims',
    'request'
];

/**
 * @property {array} OIDC.supportedClientOptions                  - List of supported Client configuration parameters
 * @property {string} OIDC.supportedClientOptions.client_id       - The client's client_id
 * @property {string} OIDC.supportedClientOptions.redirect_uri    - The client's redirect_uri
 * @readonly
 * @memberof OIDC
 *
 */
OIDC.supportedClientOptions = [
    'client_id',
    'redirect_uri'
//    'client_secret',
];

/**
 * Callback to perform custom state validation.
 * @callback validator
 * @param {string} urlState     - state parameter retrieved from the page URL
 * @param {string} storedState  - state parameter retrieved from session storage
 * @return {boolean}            - returns true if there is no state mistmatch
 */

/**
 * @property {array} [OIDC.supportedValidationOptions]                - Supported Validation parameters
 * @property {validator} [OIDC.supportedValidationOptions.validator]  - callback to perform custom state validation
 * @readonly
 * @memberof OIDC
 *
 */
OIDC.supportedValidationOptions = [
    'validator'
];


/**
 * Sets the Identity Provider's configuration parameters
 * @function setProviderInfo
 * @memberof OIDC
 * @param {object} p      - The Identity Provider's configuration options described in {@link OIDC.supportedProviderOptions}
 * @returns {boolean}     - Indicates status of
 * @example
 * // set Identity Provider configuration
 * OIDC.setProviderInfo( {
 *                          issuer: 'https:/op.example.com',
 *                          authorization_endpoint: 'http://op.example.com/auth.html',
 *                          jwks_uri: 'https://op.example.com/jwks'
 *                       }
 *                     );
 *
 * // set Identity Provider configuration using discovery information
 * var discovery = OIDC.discover('https://op.example.com');
 * if(var)
 *     OIDC.setProviderInfo(discovery);
 */
OIDC.setProviderInfo = function (p)
{
    var params = this.supportedProviderOptions;

    try{
        if (p !== 'undefined') {
            for (var i = 0; i < params.length; i++) {
                if (p[params[i]] !== 'undefined') {
                    this[params[i]] = p[params[i]];
                }
            }
        }
        return true;
    }

    catch(e){
        throw new OidcException("Unable to set the Identity Provider's configuration parameters: " + e.toString());
        return false;
    }

};


/**
 * Sets the Client's configuration parameters
 * @function setClientInfo
 * @memberof OIDC
 * @param {object} p      - The Client's configuration options described in {@link OIDC.supportedClientOptions}
 * @returns {boolean}       Indicates status of call
 * @example
 * // set client_id and redirect_uri
 * OIDC.setClientInfo( {
 *                          client_id: 'myclientID',
 *                          redirect_uri: 'https://rp.example.com/callback.html'
 *                     }
 *                   );
 */
OIDC.setClientInfo = function(p)
{
    var params = this.supportedClientOptions;
    try{
        if(typeof p !== 'undefined') {
            if (typeof p['client_id'] == 'undefined'){
              clientInfoFromServer = OIDC.registerClient(p['redirect_uri'])
              p['client_id'] = clientInfoFromServer['client_id'];
            }
            for(var i = 0; i < params.length; i++) {
                if(typeof p[params[i]] !== 'undefined') {
                    this[params[i]] = p[params[i]];
                }
            }
        }
        return true;
    }

    catch(e){
        throw new OidcException("Unable to set the Client's configuration parameters: " + e.toString());
        return false;
    }

};

/**
 * Print provider information, client information and
 *results of id_token verification on console. (OIDC.debug)
 * @function debug
 * @memberof OIDC
 * @param {boolean} toggle    - Boolean value that enables or disables debugging output
 * @param {string} id_token   - The ID Token string
 * @throws {OidcException}
 */
OIDC.debug = function (toggle, id_token)
{
  if (toggle == true){
    var providerInfo = sessionStorage['providerInfo'];
    var clientInfo = sessionStorage['clientInfo'];
    var sigVerified = this.verifyIdTokenSig(id_token);
    var valid = this.isValidIdToken(id_token);
    console.log({provider: providerInfo, client: clientInfo});
    if(!valid) console.log("Id_token is not valid!");
    if(!sigVerified) console.log("The signature of the id_token is not verified!");
    if(sigVerified && valid) console.log("Id_token is valid and its signature is verified!");
  }
}

/**
 * Stores the Identity Provider and Client configuration options in the browser session storage for reuse later
 * @function storeInfo
 * @memberof OIDC
 * @param {object} providerInfo    - The Identity Provider's configuration options described in {@link OIDC.supportedProviderOptions}
 * @param {object} clientInfo      - The Client's configuration options described in {@link OIDC.supportedClientOptions}
 */
OIDC.storeInfo = function (providerInfo, clientInfo)
{
    var pOptions = this.supportedProviderOptions;
    var cOptions = this.supportedClientOptions;
    var pInfo = {};
    var cInfo = {};

    try{
        if(providerInfo) {
            for(var i = 0; i < pOptions.length; i++) {
                if(typeof providerInfo[pOptions[i]] != 'undefined')
                    pInfo[pOptions[i]] = providerInfo[pOptions[i]];
            }
            sessionStorage['providerInfo'] = JSON.stringify(pInfo);
        } else {
            if(sessionStorage['providerInfo'])
                sessionStorage.removeItem('providerInfo');
        }

        if(clientInfo) {
            for(i = 0; i < cOptions.length; i++) {
                if(typeof clientInfo[cOptions[i]] != 'undefined')
                    cInfo[cOptions[i]] = clientInfo[cOptions[i]];
            }
            sessionStorage['clientInfo'] = JSON.stringify(cInfo);
        } else {
            if(sessionStorage['clientInfo'])
                sessionStorage.removeItem('clientInfo');
        }
    }

    catch(e){
        throw new OidcException('Unable to store the Identity Provider and Client configuration options: ' + e.toString());
    }

};


/**
 * Load and restore the Identity Provider and Client configuration options from the browser session storage
 * @function restoreInfo
 * @memberof OIDC
 */
OIDC.restoreInfo = function()
{
    var providerInfo = sessionStorage['providerInfo'];
    var clientInfo = sessionStorage['clientInfo'];
    try{
        if(providerInfo) {
            this.setProviderInfo(JSON.parse(providerInfo));
        }
        if(clientInfo) {
            this.setClientInfo(JSON.parse(clientInfo));
        }
    }

    catch(e){
        throw new OidcException('Unable to restore the Identity Provider and Client configuration options: ' + e.toString());
    }

};

/**
 * Check whether the required configuration parameters are set
 * @function checkRequiredInfo
 * @param {array} params    - List of Identity Provider and client configuration parameters
 * @memberof OIDC
 * @private
 * @return {boolean}        - Indicates whether the options have been set
 *
 */
OIDC.checkRequiredInfo = function(params)
{
    try{
        if(params) {
            for(var i = 0; i < params.length; i++) {
                if(!this[params[i]]) {
                    throw new OidcException('Required parameter not set - ' + params[i]);
                }
            }
        }
        return true;
    }

    catch(e){
        throw new OidcException('Unable to check whether the required configuration parameters are set: ' + e.toString());
        return false;
    }

};

/**
 * Clears the Identity Provider configuration parameters
 * @function clearProviderInfo
 * @memberof OIDC
 * @private
 */
OIDC.clearProviderInfo = function()
{
    try{
        for(var i = 0; i < this.supportedProviderOptions.length; i++) {
          this[this.supportedProviderOptions[i]] = null;
        }
    }

    catch(e){
        throw new OidcException('Unable to clear the Identity Provider configuration parameters: ' + e.toString());
    }
};


/**
* Generate Login Request for debugging purpose.
* @param {object} reqOptions    - Optional authentication request options. See {@link OIDC.supportedRequestOptions}
* @throws {OidcException}
* @memberof OIDC
* @return {JSON}        - All data need to login including the URL for authentication.
*/
OIDC.generateLoginRequest = function(reqOptions) {
    try {
        // verify required parameters
        this.checkRequiredInfo(new Array('client_id', 'redirect_uri', 'authorization_endpoint'));

        var state = null;
        var nonce = null;

        // Replace state and nonce with secure ones if
        var crypto = window.crypto || window.msCrypto;
        if(crypto && crypto.getRandomValues) {
          var D = new Uint32Array(2);
          crypto.getRandomValues(D);
          state = D[0].toString(36);
          nonce = D[1].toString(36);
        } else {
          var byteArrayToLong = function(/*byte[]*/byteArray) {
            var value = 0;
            for ( var i = byteArray.length - 1; i >= 0; i--) {
              value = (value * 256) + byteArray[i];
            }
            return value;
          };

          rng_seed_time();
          var sRandom = new SecureRandom();
          var randState= new Array(4);
          sRandom.nextBytes(randState);
          state = byteArrayToLong(randState).toString(36);

          rng_seed_time();
          var randNonce= new Array(4);
          sRandom.nextBytes(randNonce);
          nonce = byteArrayToLong(randNonce).toString(36);
        }


        // Store the them in session storage
        sessionStorage['state'] = state;
        sessionStorage['nonce'] = nonce;

        var response_type = 'id_token';
        var scope = 'openid';
        var display = null;
        var max_age = null;
        var claims = null;
        var idTokenClaims = {};
        var userInfoClaims = {};

        if(reqOptions) {
          if(reqOptions['response_type']) {
            var parts = reqOptions['response_type'].split(' ');
            var temp = [];
            if(parts) {
              for(var i = 0; i < parts.length; i++) {
                if(parts[i] == 'code' || parts[i] == 'token' || parts[i] == 'id_token')
                temp.push(parts[i]);
              }
            }
            if(temp)
            response_type = temp.join(' ');
          }

          if(reqOptions['scope'])
          scope = reqOptions['scope'];
          if(reqOptions['display'])
          display = reqOptions['display'];
          if(reqOptions['max_age'])
          max_age = reqOptions['max_age'];


          if(reqOptions['claims']) {

            if(this['claims_parameter_supported']) {

              if(reqOptions['claims']['id_token']) {
                for(var j = 0; j < reqOptions['claims']['id_token'].length; j++) {
                  idTokenClaims[reqOptions['claims']['id_token'][j]] = null
                }
                if(!claims)
                claims = {};
                claims['id_token'] = idTokenClaims;
              }
              if(reqOptions['claims']['userinfo']) {
                for(var k = 0; k < reqOptions['claims']['userinfo'].length; k++) {
                  userInfoClaims[reqOptions['claims']['userinfo'][k]] = null;
                }
                if(!claims)
                claims = {};
                claims['userinfo'] = userInfoClaims;
              }

            } else
            throw new OidcException('Provider does not support claims request parameter')

          }
        }

        // Construct the redirect URL
        // For getting an id token, response_type of
        // "token id_token" (note the space), scope of
        // "openid", and some value for nonce is required.
        // client_id must be the consumer key of the connected app.
        // redirect_uri must match the callback URL configured for
        // the connected app.

        var optParams = '';
        if(display)
        optParams += '&display='  + display;
        if(max_age)
        optParams += '&max_age=' + max_age;
        if(claims)
        optParams += '&claims=' + JSON.stringify(claims);

        var url =
        this['authorization_endpoint']
        + '?response_type=' + response_type
        + '&scope=' + scope
        + '&nonce=' + nonce
        + '&client_id=' + this['client_id']
        + '&redirect_uri=' + this['redirect_uri']
        + '&state=' + state
        + optParams;

        var loginRequest = {
          'authorization_endpoint': this['authorization_endpoint'],
          'response_type': response_type,
          'scope': scope,
          'nonce': nonce,
          'client_id': this['client_id'],
          'redirect_uri': this['redirect_uri'],
          'state': state,
          'optional_parameters': optParams,
          'url': url
        }
        return loginRequest;
    } catch (e) {
        throw new OidcException('Unable to generate login request: ' + e.toString());
    }
};

/**
* Redirect to the Identity Provider for authenticaton
* @param {object} reqOptions    - Optional authentication request options. See {@link OIDC.supportedRequestOptions}
* @throws {OidcException}
* @example
*
* // login with options
* OIDC.login( {
*               scope : 'openid profile',
*               response_type : 'token id_token',
*               max_age : 60,
*               claims : {
*                          id_token : ['email', 'phone_number'],
*                          userinfo : ['given_name', 'family_name']
*                        }
*              }
*            );
*
* // login with default scope=openid, response_type=id_token
* OIDC.login();
*/
OIDC.login = function(reqOptions) {
  try {
    // verify required parameters
    this.checkRequiredInfo(new Array('client_id', 'redirect_uri', 'authorization_endpoint'));

    var reqOptionsExist = !!reqOptions;
    var state = null;
    var nonce = null;

    if(reqOptionsExist && (reqOptions['nonce'] && reqOptions['state'])) {
      state = reqOptions['state']
      nonce = reqOptions['nonce']
    }

    // Replace state and nonce with secure ones if
    var crypto = window.crypto || window.msCrypto;
    if(crypto && crypto.getRandomValues) {
      var D = new Uint32Array(2);
      crypto.getRandomValues(D);
      state = reqOptionsExist && reqOptions['state'] ? reqOptions['state'] : D[0].toString(36);
      nonce = reqOptionsExist && reqOptions['nonce'] ? reqOptions['nonce'] : D[1].toString(36);
    } else {
      var byteArrayToLong = function(/*byte[]*/byteArray) {
        var value = 0;
        for ( var i = byteArray.length - 1; i >= 0; i--) {
          value = (value * 256) + byteArray[i];
        }
        return value;
      };

      rng_seed_time();
      var sRandom = new SecureRandom();
      var randState= new Array(4);
      sRandom.nextBytes(randState);
      state = byteArrayToLong(randState).toString(36);

      rng_seed_time();
      var randNonce= new Array(4);
      sRandom.nextBytes(randNonce);
      nonce = byteArrayToLong(randNonce).toString(36);
    }


    // Store the them in session storage
    sessionStorage['state'] = state;
    sessionStorage['nonce'] = nonce;

    var response_type = 'id_token';
    var scope = 'openid';
    var display = null;
    var max_age = null;
    var claims = null;
    var idTokenClaims = {};
    var userInfoClaims = {};

    if(reqOptionsExist) {
      if(reqOptions['response_type']) {
        var parts = reqOptions['response_type'].split(' ');
        var temp = [];
        if(parts) {
          for(var i = 0; i < parts.length; i++) {
            if(parts[i] == 'code' || parts[i] == 'token' || parts[i] == 'id_token')
            temp.push(parts[i]);
          }
        }
        if(temp)
        response_type = temp.join(' ');
      }

      if(reqOptions['scope'])
      scope = reqOptions['scope'];
      if(reqOptions['display'])
      display = reqOptions['display'];
      if(reqOptions['max_age'])
      max_age = reqOptions['max_age'];


      if(reqOptions['claims']) {

        if(this['claims_parameter_supported']) {

          if(reqOptions['claims']['id_token']) {
            for(var j = 0; j < reqOptions['claims']['id_token'].length; j++) {
              idTokenClaims[reqOptions['claims']['id_token'][j]] = null
            }
            if(!claims)
            claims = {};
            claims['id_token'] = idTokenClaims;
          }
          if(reqOptions['claims']['userinfo']) {
            for(var k = 0; k < reqOptions['claims']['userinfo'].length; k++) {
              userInfoClaims[reqOptions['claims']['userinfo'][k]] = null;
            }
            if(!claims)
            claims = {};
            claims['userinfo'] = userInfoClaims;
          }

        } else
        throw new OidcException('Provider does not support claims request parameter')

      }
    }

    // Construct the redirect URL
    // For getting an id token, response_type of
    // "token id_token" (note the space), scope of
    // "openid", and some value for nonce is required.
    // client_id must be the consumer key of the connected app.
    // redirect_uri must match the callback URL configured for
    // the connected app.

    var optParams = '';
    if(display)
    optParams += '&display='  + display;
    if(max_age)
    optParams += '&max_age=' + max_age;
    if(claims)
    optParams += '&claims=' + JSON.stringify(claims);

    var url =
    this['authorization_endpoint']
    + '?response_type=' + response_type
    + '&scope=' + scope
    + '&nonce=' + nonce
    + '&client_id=' + this['client_id']
    + '&redirect_uri=' + this['redirect_uri']
    + '&state=' + state
    + optParams;

    if (reqOptions['window'])
      return window.open(url, '_blank', reqOptions['window']);
    window.location.replace(url);
  } catch (e) {
      throw new OidcException('Unable to redirect to the Identity Provider for authenticaton: ' + e.toString());
  }
};

/**
 * Verifies the ID Token signature using the JWK Keyset from jwks or jwks_uri of the
 * Identity Provider Configuration options set via {@link OIDC.setProviderInfo}.
 * Supports only RSA signatures
 * @param {string }id_token      - The ID Token string
 * @returns {boolean}           Indicates whether the signature is valid or not
 * @see OIDC.setProviderInfo
 * @throws {OidcException}
 */
OIDC.verifyIdTokenSig = function (id_token)
{
    try {
        var verified = false;
        var requiredParam = this['jwks_uri'] || this['jwks'];
        if(!requiredParam) {
          throw new OidcException('jwks_uri or jwks parameter not set');
        } else  if(id_token) {
          var idtParts = this.getIdTokenParts(id_token);
          var header = this.getJsonObject(idtParts[0])
          var jwks = this['jwks'] || this.fetchJSON(this['jwks_uri']);
          if(!jwks)
          throw new OidcException('No JWK keyset');
          else {
            if(header['alg'] && header['alg'].substr(0, 2) == 'RS') {
              var jwk = this.jwk_get_key(jwks, 'RSA', 'sig', header['kid']);
              if(!jwk)
              new OidcException('No matching JWK found');
              else {
                verified = this.rsaVerifyJWS(id_token, jwk[0]);
              }
            } else
            throw new OidcException('Unsupported JWS signature algorithm ' + header['alg']);
          }
        }
        return verified;
    } catch (e) {
        throw new OidcException('Unable to verify the ID Token signature: ' + e.toString());
    }
}


/**
 * Validates the information in the ID Token against configuration data in the Identity Provider
 * and Client configuration set via {@link OIDC.setProviderInfo} and set via {@link OIDC.setClientInfo}
 * @param {string} id_token      - The ID Token string
 * @returns {boolean}           Validity of the ID Token
 * @throws {OidcException}
 */
OIDC.isValidIdToken = function(id_token)
{
    try {
        var idt = null;
        var valid = false;
        this.checkRequiredInfo(['issuer', 'client_id']);

        if(id_token) {
          var idtParts = this.getIdTokenParts(id_token);
          var payload = this.getJsonObject(idtParts[1])
          if(payload) {
            var now =  new Date() / 1000;
            if( payload['iat'] >  now + (5 * 60))
            throw new OidcException('ID Token issued time is later than current time');
            if(payload['exp'] < now - (5*60))
            throw new OidcException('ID Token expired');
            var audience = null;
            if(payload['aud']) {
              if(payload['aud'] instanceof Array) {
                audience = payload['aud'][0];
              } else
              audience = payload['aud'];
            }
            if(audience != this['client_id'])
            throw new OidcException('invalid audience');
            if(payload['iss'] != this['issuer'])
            throw new OidcException('invalid issuer ' + payload['iss'] + ' != ' + this['issuer']);
            if(payload['nonce'] != sessionStorage['nonce'])
            throw new OidcException('invalid nonce');
            valid = true;
          } else
          throw new OidcException('Unable to parse JWS payload');
        }
        return valid;
    } catch (e) {
        throw new OidcException('Unable to validate information in the ID Token: ' + e.toString());
    }
}

/**
 * Verifies the JWS string using the JWK
 * @param {string} jws      - The JWS string
 * @param {object} jwk      - The JWK Key that will be used to verify the signature
 * @returns {boolean}       Validity of the JWS signature
 * @throws {OidcException}
 */
OIDC.rsaVerifyJWS = function (jws, jwk)
{
    try {
        if(jws && typeof jwk === 'object') {
          if(jwk['kty'] == 'RSA') {
            var verifier = KJUR.jws.JWS;
            if(jwk['n'] && jwk['e']) {
              var pubkey = KEYUTIL.getKey({ kty: 'RSA', n: jwk['n'], e: jwk['e'] })
              return verifier.verify(jws, pubkey, ['RS256']);
            } else if (jwk['x5c']) {
              return verifier.verifyJWSByPemX509Cert(jws, "-----BEGIN CERTIFICATE-----\n" + jwk['x5c'][0] + "\n-----END CERTIFICATE-----\n");
            }
          } else {
            throw new OidcException('No RSA kty in JWK');
          }
        }
    } catch (e) {
        throw new OidcException('Unable to verify the JWS string: ' + e.toString());
        return false;
    }
}

/**
 * Get the ID Token from the current page URL whose signature is verified and contents validated
 * against the configuration data set via {@link OIDC.setProviderInfo} and {@link OIDC.setClientInfo}
 * @param {object} [validationOptions]  - Optional validation options. See {@link OIDC.supportedValidationOptions}
 * @returns {string|null}
 * @throws {OidcException}
 */
OIDC.getValidIdToken = function(validationOptions)
{
    try {
        var url = window.location.href;

        // Check if there was an error parameter
        var error = url.match('[?&]error=([^&]*)');
        if (error) {
          // If so, extract the error description and display it
          var description = url.match('[?&]error_description=([^&]*)');
          throw new OidcException(error[1] + ' Description: ' + description[1]);
        }

        // Extract state from the state parameter
        var customValidatorExists = validationOptions && validationOptions['validator'] && typeof validationOptions['validator'] === 'function';
        var urlState = OIDC.getState();
        var storedState = sessionStorage['state'];
        var goodState = customValidatorExists ? validationOptions.validator(urlState, storedState) : urlState === storedState;

        // Extract id token from the id_token parameter
        var match = url.match('[?#&]id_token=([^&]*)');
        if (!goodState) {
          throw new OidcException('State mismatch');
        } else if (match) {
          var id_token = match[1]; // String captured by ([^&]*)

          if (id_token) {
            var sigVerified = this.verifyIdTokenSig(id_token);
            var valid = this.isValidIdToken(id_token);
            if (sigVerified && valid) {
              return id_token;
            }
          } else {
            throw new OidcException('Could not retrieve ID Token from the URL');
          }
        } else {
          throw new OidcException('No ID Token returned');
        }
    } catch (e) {
        throw new OidcException('Unable to get the ID Token from the current page URL: ' + e.toString());
        return null;
    }
};

/**
 * Get State from the current page URL
 * @returns {string|null} State
 */
OIDC.getState = function()
{
  try {
    var url = window.location.href;
    var smatch = url.match('[?#&]state=([^&]*)');
    if (smatch && smatch[1]) {
      return decodeURIComponent(smatch[1]);
    } else {
      console.error(new Error('No State parameter found on current page URL!'));
      return null;
    }
  } catch (e) {
    throw new OidcException('Unable to get the State from the current page URL: ' + e.toString());
    return null;
  }
}

/**
 * Get Access Token from the current page URL
 *
 * @returns {string|null}  Access Token
 */
OIDC.getAccessToken = function()
{
    try {
      var url = window.location.href;
      // Check for token
      var token = url.match('[?#&]access_token=([^&]*)');
      if (token)
        return token[1];
      else
        console.error(new Error("No access_token found on current page URL!"));
        return null;
    } catch (e) {
        throw new OidcException('Unable to get the Access Token from the current page URL: ' + e.toString());
        return null;
    }
}


/**
 * Get Authorization Code from the current page URL
 *
 * @returns {string|null}  Authorization Code
 */
OIDC.getCode = function()
{
    try {
        var url = window.location.href;

        // Check for code
        var code = url.match('[?&]code=([^(&)]*)');
        if (code) {
          return code[1];
        }
    } catch (e) {
        throw new OidcException('Unable to get the Authorization Code from the current page URL: ' + e.toString());
        return null;
    }
}


/**
 * Splits the ID Token string into the individual JWS parts
 * @param  {string} id_token    - ID Token
 * @returns {Array} An array of the JWS compact serialization components (header, payload, signature)
 */
OIDC.getIdTokenParts = function (id_token)
{
    try {
        var jws = new KJUR.jws.JWS();
        jws.parseJWS(id_token);
        return new Array(jws.parsedJWS.headS, jws.parsedJWS.payloadS, jws.parsedJWS.si);
    } catch (e) {
        throw new OidcException('Unable to split the ID Token string: ' + e.toString());
    }
};

/**
 * Get the contents of the ID Token payload as an JSON object
 * @param {string} id_token     - ID Token
 * @returns {object}            - The ID Token payload JSON object
 */
OIDC.getIdTokenPayload = function (id_token)
{
    try {
      var parts = this.getIdTokenParts(id_token);
      if(parts) return this.getJsonObject(parts[1]);
    } catch (e) {
      throw new OidcException('Unable to get the contents of the ID Token payload: ' + e.toString());
    }
}

/**
 * Get the JSON object from the JSON string
 * @param {string} jsonS    - JSON string
 * @returns {object|null}   JSON object or null
 */
OIDC.getJsonObject = function (jsonS)
{
    try {
      var jws = KJUR.jws.JWS;
      if(jws.isSafeJSONString(jsonS)) {
        return jws.readSafeJSONString(jsonS);
      }
    } catch (e) {
      throw new OidcException('Unable to get the JSON object from JSON string: ' + e.toString());
      return null;
    }
};


/**
 * Retrieves the JSON file at the specified URL. The URL must have CORS enabled for this function to work.
 * @param {string} url      - URL to fetch the JSON file
 * @returns {string|null}    contents of the URL or null
 * @throws {OidcException}
 */
OIDC.fetchJSON = function(url) {
    try {
        var request = new XMLHttpRequest();
        request.open('GET', url, false);
        request.send(null);

        if (request.status === 200) {
            return request.responseText;
        } else
            throw new OidcException("fetchJSON - " + request.status + ' ' + request.statusText);

    }
    catch(e) {
        throw new OidcException('Unable to retrieve JSON file at ' + url + ' : ' + e.toString());
    }
    return null;
};

/**
 * Retrieve the JWK key that matches the input criteria
 * @param {string|object} jwkIn     - JWK Keyset string or object
 * @param {string} kty              - The 'kty' to match (RSA|EC). Only RSA is supported.
 * @param {string}use               - The 'use' to match (sig|enc).
 * @param {string}kid               - The 'kid' to match
 * @returns {array}                 Array of JWK keys that match the specified criteria                                                                     itera
 */
OIDC.jwk_get_key = function(jwkIn, kty, use, kid )
{
    try {
      var jwk = null;
      var foundKeys = [];

      if(jwkIn) {
        if(typeof jwkIn === 'string')
        jwk = this.getJsonObject(jwkIn);
        else if(typeof jwkIn === 'object')
        jwk = jwkIn;

        if(jwk != null) {
          if(typeof jwk['keys'] === 'object') {
            if(jwk.keys.length == 0)
            return null;

            for(var i = 0; i < jwk.keys.length; i++) {
              if(jwk['keys'][i]['kty'] == kty)
              foundKeys.push(jwk.keys[i]);
            }

            if(foundKeys.length == 0)
            return null;

            if(use) {
              var temp = [];
              for(var j = 0; j < foundKeys.length; j++) {
                if(!foundKeys[j]['use'])
                temp.push(foundKeys[j]);
                else if(foundKeys[j]['use'] == use)
                temp.push(foundKeys[j]);
              }
              foundKeys = temp;
            }
            if(foundKeys.length == 0)
            return null;

            if(kid) {
              temp = [];
              for(var k = 0; k < foundKeys.length; k++) {
                if(foundKeys[k]['kid'] == kid)
                temp.push(foundKeys[k]);
              }
              foundKeys = temp;
            }
            if(foundKeys.length == 0)
            return null;
            else
            return foundKeys;
          }
        }

      }
    } catch (e) {
        throw new OidcException('Unable to retrieve the JWK key: ' + e.toString());
    }

};

/**
 * Performs discovery on the IdP issuer_id (OIDC.discover)
 * @function discover
 * @memberof OIDC
 * @param {string} issuer     - The Identity Provider's issuer_id
 * @returns {object|null}     - The JSON object of the discovery document or null
 * @throws {OidcException}
 */
OIDC.discover = function(issuer)
{
    try {
        var discovery = null;
        if(issuer) {
          var openidConfig = issuer + '/.well-known/openid-configuration';
          var discoveryDoc = this.fetchJSON(openidConfig);
          if(discoveryDoc)
          discovery = this.getJsonObject(discoveryDoc)
        }
        return discovery;
    } catch (e) {
        throw new OidcException('Unable to perform discovery: ' + e.toString());
    }
};


/**
 * Request and return the user information from the Identity Provider. (OIDC.getUserInfo)
 * @function getUserInfo
 * @memberof OIDC
 * @param {string} access_token     - Access Token string
 * @returns {object|null}     - The JSON object of the user claims or null
 * @throws {OidcException}
 */
OIDC.getUserInfo = function(access_token)
{
  try {
      var providerURL = JSON.parse(sessionStorage['providerInfo'])['issuer']
      var providerInfo = OIDC.discover(providerURL);
      var request = new XMLHttpRequest();

      /*
       * Note: A Cross-Origin Request with HTTP POST method should indicate the Content-type
       * header: application/x-www-form-urlencoded, application/form-data or text/plain for
       * Simple Requests or a different value for Preflighted Requests
       */
      request.open('POST', providerInfo['userinfo_endpoint'], false);
      request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

      request.setRequestHeader("authorization", "Bearer " + access_token);
      request.send(null);

      if (request.status === 200) {
          return request.responseText;
      } else
          throw new OidcException("getUserInfo - " + request.status + ' ' + request.statusText);

  }
  catch(e) {
      throw new OidcException('Unable to get user info:' + e.toString());
  }
}

/**
 * Dynamically register a new client with the given redirect URI. (OIDC.registerClient)
 * The following list describe the default configuration for a client dynamically registered:
 * Application Type: Web
 * Client Name: Dynamically Registered Client
 * Subject Type: Public
 * Grant Type: implicit
 * Response Type: token, id_token
 * Scopes: email, openid, profile
 * @function registerClient
 * @memberof OIDC
 * @param {string} redirect_uri     - The redirect URI string
 * @returns {object|null}     - The JSON object of the Client information
 * @throws {OidcException}
 */
OIDC.registerClient = function(redirect_uri){
  try {
      var clientMetadata = {
          "redirect_uris" : [redirect_uri],
          "application_type": "Web",
          "client_name": "Dynamically Registered Client",
          "subject_type": "public",
          "grant_types": ["implicit"],
          "response_types": ["token", "id_token"],
          "scopes": ["email", "openid", "profile"]
      };
      var request = new XMLHttpRequest();
      request.open("POST", providerInfo['registration_endpoint'], false);
      request.setRequestHeader("Content-Type", "application/json");
      request.setRequestHeader("Accept", "application/json");
      request.send(JSON.stringify(clientMetadata));
      if (request.status === 200) {
          return JSON.parse(request.responseText);
      } else
          throw new OidcException("getUserInfo - " + request.status + ' ' + request.statusText);
  } catch (e) {
      throw new OidcException('Unable to register new client:' + e.toString());
  }
}

function JSONObjToHTMLTable(JSONObj)
{
    try {
      var HTMLString = '\n<table class="table table-striped">';
      for (var claim in JSONObj){
         HTMLString = HTMLString + '\n<TR><TD>' + claim + '</TD><TD>' + JSONObj[claim] + '</TD></TR>';
      }
      HTMLString = HTMLString + '\n</table>';
      return HTMLString;
    } catch (e) {
      throw new OidcException('Unable to get JSON Obj to HTML table:' + e.toString());
      return null;
    }

}

/**
 * OidcException
 * @param {string } message  - The exception error message
 * @constructor
 */
function OidcException(message) {
    this.name = 'OidcException';
    this.message = message;
}
OidcException.prototype = new Error();
OidcException.prototype.constructor = OidcException;



function namespace(namespaceString) {
    var parts = namespaceString.split('.'),
        parent = window,
        currentPart = '';

    for(var i = 0, length = parts.length; i < length; i++) {
        currentPart = parts[i];
        parent[currentPart] = parent[currentPart] || {};
        parent = parent[currentPart];
    }
    return parent;
}

/*  core.js  */
/*
CryptoJS v3.1.9
https://github.com/brix/crypto-js
(c) 2009-2013 by Jeff Mott. (c) 2013-2016 Evan Vosberg. All rights reserved.
https://github.com/brix/crypto-js
*/
var CryptoJS=CryptoJS||function(a,b){var c=Object.create||function(){function a(){}return function(b){var c;return a.prototype=b,c=new a,a.prototype=null,c}}(),d={},e=d.lib={},f=e.Base=function(){return{extend:function(a){var b=c(this);return a&&b.mixIn(a),b.hasOwnProperty("init")&&this.init!==b.init||(b.init=function(){b.$super.init.apply(this,arguments)}),b.init.prototype=b,b.$super=this,b},create:function(){var a=this.extend();return a.init.apply(a,arguments),a},init:function(){},mixIn:function(a){for(var b in a)a.hasOwnProperty(b)&&(this[b]=a[b]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}}}(),g=e.WordArray=f.extend({init:function(a,c){a=this.words=a||[],c!=b?this.sigBytes=c:this.sigBytes=4*a.length},toString:function(a){return(a||i).stringify(this)},concat:function(a){var b=this.words,c=a.words,d=this.sigBytes,e=a.sigBytes;if(this.clamp(),d%4)for(var f=0;f<e;f++){var g=c[f>>>2]>>>24-f%4*8&255;b[d+f>>>2]|=g<<24-(d+f)%4*8}else for(var f=0;f<e;f+=4)b[d+f>>>2]=c[f>>>2];return this.sigBytes+=e,this},clamp:function(){var b=this.words,c=this.sigBytes;b[c>>>2]&=4294967295<<32-c%4*8,b.length=a.ceil(c/4)},clone:function(){var a=f.clone.call(this);return a.words=this.words.slice(0),a},random:function(b){for(var f,c=[],d=function(b){var b=b,c=987654321,d=4294967295;return function(){c=36969*(65535&c)+(c>>16)&d,b=18e3*(65535&b)+(b>>16)&d;var e=(c<<16)+b&d;return e/=4294967296,e+=.5,e*(a.random()>.5?1:-1)}},e=0;e<b;e+=4){var h=d(4294967296*(f||a.random()));f=987654071*h(),c.push(4294967296*h()|0)}return new g.init(c,b)}}),h=d.enc={},i=h.Hex={stringify:function(a){for(var b=a.words,c=a.sigBytes,d=[],e=0;e<c;e++){var f=b[e>>>2]>>>24-e%4*8&255;d.push((f>>>4).toString(16)),d.push((15&f).toString(16))}return d.join("")},parse:function(a){for(var b=a.length,c=[],d=0;d<b;d+=2)c[d>>>3]|=parseInt(a.substr(d,2),16)<<24-d%8*4;return new g.init(c,b/2)}},j=h.Latin1={stringify:function(a){for(var b=a.words,c=a.sigBytes,d=[],e=0;e<c;e++){var f=b[e>>>2]>>>24-e%4*8&255;d.push(String.fromCharCode(f))}return d.join("")},parse:function(a){for(var b=a.length,c=[],d=0;d<b;d++)c[d>>>2]|=(255&a.charCodeAt(d))<<24-d%4*8;return new g.init(c,b)}},k=h.Utf8={stringify:function(a){try{return decodeURIComponent(escape(j.stringify(a)))}catch(a){throw new Error("Malformed UTF-8 data")}},parse:function(a){return j.parse(unescape(encodeURIComponent(a)))}},l=e.BufferedBlockAlgorithm=f.extend({reset:function(){this._data=new g.init,this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=k.parse(a)),this._data.concat(a),this._nDataBytes+=a.sigBytes},_process:function(b){var c=this._data,d=c.words,e=c.sigBytes,f=this.blockSize,h=4*f,i=e/h;i=b?a.ceil(i):a.max((0|i)-this._minBufferSize,0);var j=i*f,k=a.min(4*j,e);if(j){for(var l=0;l<j;l+=f)this._doProcessBlock(d,l);var m=d.splice(0,j);c.sigBytes-=k}return new g.init(m,k)},clone:function(){var a=f.clone.call(this);return a._data=this._data.clone(),a},_minBufferSize:0}),n=(e.Hasher=l.extend({cfg:f.extend(),init:function(a){this.cfg=this.cfg.extend(a),this.reset()},reset:function(){l.reset.call(this),this._doReset()},update:function(a){return this._append(a),this._process(),this},finalize:function(a){a&&this._append(a);var b=this._doFinalize();return b},blockSize:16,_createHelper:function(a){return function(b,c){return new a.init(c).finalize(b)}},_createHmacHelper:function(a){return function(b,c){return new n.HMAC.init(a,c).finalize(b)}}}),d.algo={});return d}(Math);

/*  sha1-min.js  */
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(){var k=CryptoJS,b=k.lib,m=b.WordArray,l=b.Hasher,d=[],b=k.algo.SHA1=l.extend({_doReset:function(){this._hash=new m.init([1732584193,4023233417,2562383102,271733878,3285377520])},_doProcessBlock:function(n,p){for(var a=this._hash.words,e=a[0],f=a[1],h=a[2],j=a[3],b=a[4],c=0;80>c;c++){if(16>c)d[c]=n[p+c]|0;else{var g=d[c-3]^d[c-8]^d[c-14]^d[c-16];d[c]=g<<1|g>>>31}g=(e<<5|e>>>27)+b+d[c];g=20>c?g+((f&h|~f&j)+1518500249):40>c?g+((f^h^j)+1859775393):60>c?g+((f&h|f&j|h&j)-1894007588):g+((f^h^
j)-899497514);b=j;j=h;h=f<<30|f>>>2;f=e;e=g}a[0]=a[0]+e|0;a[1]=a[1]+f|0;a[2]=a[2]+h|0;a[3]=a[3]+j|0;a[4]=a[4]+b|0},_doFinalize:function(){var b=this._data,d=b.words,a=8*this._nDataBytes,e=8*b.sigBytes;d[e>>>5]|=128<<24-e%32;d[(e+64>>>9<<4)+14]=Math.floor(a/4294967296);d[(e+64>>>9<<4)+15]=a;b.sigBytes=4*d.length;this._process();return this._hash},clone:function(){var b=l.clone.call(this);b._hash=this._hash.clone();return b}});k.SHA1=l._createHelper(b);k.HmacSHA1=l._createHmacHelper(b)})();

/*  sha256-min.js  */
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(k){for(var g=CryptoJS,h=g.lib,v=h.WordArray,j=h.Hasher,h=g.algo,s=[],t=[],u=function(q){return 4294967296*(q-(q|0))|0},l=2,b=0;64>b;){var d;a:{d=l;for(var w=k.sqrt(d),r=2;r<=w;r++)if(!(d%r)){d=!1;break a}d=!0}d&&(8>b&&(s[b]=u(k.pow(l,0.5))),t[b]=u(k.pow(l,1/3)),b++);l++}var n=[],h=h.SHA256=j.extend({_doReset:function(){this._hash=new v.init(s.slice(0))},_doProcessBlock:function(q,h){for(var a=this._hash.words,c=a[0],d=a[1],b=a[2],k=a[3],f=a[4],g=a[5],j=a[6],l=a[7],e=0;64>e;e++){if(16>e)n[e]=
q[h+e]|0;else{var m=n[e-15],p=n[e-2];n[e]=((m<<25|m>>>7)^(m<<14|m>>>18)^m>>>3)+n[e-7]+((p<<15|p>>>17)^(p<<13|p>>>19)^p>>>10)+n[e-16]}m=l+((f<<26|f>>>6)^(f<<21|f>>>11)^(f<<7|f>>>25))+(f&g^~f&j)+t[e]+n[e];p=((c<<30|c>>>2)^(c<<19|c>>>13)^(c<<10|c>>>22))+(c&d^c&b^d&b);l=j;j=g;g=f;f=k+m|0;k=b;b=d;d=c;c=m+p|0}a[0]=a[0]+c|0;a[1]=a[1]+d|0;a[2]=a[2]+b|0;a[3]=a[3]+k|0;a[4]=a[4]+f|0;a[5]=a[5]+g|0;a[6]=a[6]+j|0;a[7]=a[7]+l|0},_doFinalize:function(){var d=this._data,b=d.words,a=8*this._nDataBytes,c=8*d.sigBytes;
b[c>>>5]|=128<<24-c%32;b[(c+64>>>9<<4)+14]=k.floor(a/4294967296);b[(c+64>>>9<<4)+15]=a;d.sigBytes=4*b.length;this._process();return this._hash},clone:function(){var b=j.clone.call(this);b._hash=this._hash.clone();return b}});g.SHA256=j._createHelper(h);g.HmacSHA256=j._createHmacHelper(h)})(Math);

/*  x64-core-min.js  */
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(g){var a=CryptoJS,f=a.lib,e=f.Base,h=f.WordArray,a=a.x64={};a.Word=e.extend({init:function(b,c){this.high=b;this.low=c}});a.WordArray=e.extend({init:function(b,c){b=this.words=b||[];this.sigBytes=c!=g?c:8*b.length},toX32:function(){for(var b=this.words,c=b.length,a=[],d=0;d<c;d++){var e=b[d];a.push(e.high);a.push(e.low)}return h.create(a,this.sigBytes)},clone:function(){for(var b=e.clone.call(this),c=b.words=this.words.slice(0),a=c.length,d=0;d<a;d++)c[d]=c[d].clone();return b}})})();

/*  sha512-min.js  */
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(){function a(){return d.create.apply(d,arguments)}for(var n=CryptoJS,r=n.lib.Hasher,e=n.x64,d=e.Word,T=e.WordArray,e=n.algo,ea=[a(1116352408,3609767458),a(1899447441,602891725),a(3049323471,3964484399),a(3921009573,2173295548),a(961987163,4081628472),a(1508970993,3053834265),a(2453635748,2937671579),a(2870763221,3664609560),a(3624381080,2734883394),a(310598401,1164996542),a(607225278,1323610764),a(1426881987,3590304994),a(1925078388,4068182383),a(2162078206,991336113),a(2614888103,633803317),
a(3248222580,3479774868),a(3835390401,2666613458),a(4022224774,944711139),a(264347078,2341262773),a(604807628,2007800933),a(770255983,1495990901),a(1249150122,1856431235),a(1555081692,3175218132),a(1996064986,2198950837),a(2554220882,3999719339),a(2821834349,766784016),a(2952996808,2566594879),a(3210313671,3203337956),a(3336571891,1034457026),a(3584528711,2466948901),a(113926993,3758326383),a(338241895,168717936),a(666307205,1188179964),a(773529912,1546045734),a(1294757372,1522805485),a(1396182291,
2643833823),a(1695183700,2343527390),a(1986661051,1014477480),a(2177026350,1206759142),a(2456956037,344077627),a(2730485921,1290863460),a(2820302411,3158454273),a(3259730800,3505952657),a(3345764771,106217008),a(3516065817,3606008344),a(3600352804,1432725776),a(4094571909,1467031594),a(275423344,851169720),a(430227734,3100823752),a(506948616,1363258195),a(659060556,3750685593),a(883997877,3785050280),a(958139571,3318307427),a(1322822218,3812723403),a(1537002063,2003034995),a(1747873779,3602036899),
a(1955562222,1575990012),a(2024104815,1125592928),a(2227730452,2716904306),a(2361852424,442776044),a(2428436474,593698344),a(2756734187,3733110249),a(3204031479,2999351573),a(3329325298,3815920427),a(3391569614,3928383900),a(3515267271,566280711),a(3940187606,3454069534),a(4118630271,4000239992),a(116418474,1914138554),a(174292421,2731055270),a(289380356,3203993006),a(460393269,320620315),a(685471733,587496836),a(852142971,1086792851),a(1017036298,365543100),a(1126000580,2618297676),a(1288033470,
3409855158),a(1501505948,4234509866),a(1607167915,987167468),a(1816402316,1246189591)],v=[],w=0;80>w;w++)v[w]=a();e=e.SHA512=r.extend({_doReset:function(){this._hash=new T.init([new d.init(1779033703,4089235720),new d.init(3144134277,2227873595),new d.init(1013904242,4271175723),new d.init(2773480762,1595750129),new d.init(1359893119,2917565137),new d.init(2600822924,725511199),new d.init(528734635,4215389547),new d.init(1541459225,327033209)])},_doProcessBlock:function(a,d){for(var f=this._hash.words,
F=f[0],e=f[1],n=f[2],r=f[3],G=f[4],H=f[5],I=f[6],f=f[7],w=F.high,J=F.low,X=e.high,K=e.low,Y=n.high,L=n.low,Z=r.high,M=r.low,$=G.high,N=G.low,aa=H.high,O=H.low,ba=I.high,P=I.low,ca=f.high,Q=f.low,k=w,g=J,z=X,x=K,A=Y,y=L,U=Z,B=M,l=$,h=N,R=aa,C=O,S=ba,D=P,V=ca,E=Q,m=0;80>m;m++){var s=v[m];if(16>m)var j=s.high=a[d+2*m]|0,b=s.low=a[d+2*m+1]|0;else{var j=v[m-15],b=j.high,p=j.low,j=(b>>>1|p<<31)^(b>>>8|p<<24)^b>>>7,p=(p>>>1|b<<31)^(p>>>8|b<<24)^(p>>>7|b<<25),u=v[m-2],b=u.high,c=u.low,u=(b>>>19|c<<13)^(b<<
3|c>>>29)^b>>>6,c=(c>>>19|b<<13)^(c<<3|b>>>29)^(c>>>6|b<<26),b=v[m-7],W=b.high,t=v[m-16],q=t.high,t=t.low,b=p+b.low,j=j+W+(b>>>0<p>>>0?1:0),b=b+c,j=j+u+(b>>>0<c>>>0?1:0),b=b+t,j=j+q+(b>>>0<t>>>0?1:0);s.high=j;s.low=b}var W=l&R^~l&S,t=h&C^~h&D,s=k&z^k&A^z&A,T=g&x^g&y^x&y,p=(k>>>28|g<<4)^(k<<30|g>>>2)^(k<<25|g>>>7),u=(g>>>28|k<<4)^(g<<30|k>>>2)^(g<<25|k>>>7),c=ea[m],fa=c.high,da=c.low,c=E+((h>>>14|l<<18)^(h>>>18|l<<14)^(h<<23|l>>>9)),q=V+((l>>>14|h<<18)^(l>>>18|h<<14)^(l<<23|h>>>9))+(c>>>0<E>>>0?1:
0),c=c+t,q=q+W+(c>>>0<t>>>0?1:0),c=c+da,q=q+fa+(c>>>0<da>>>0?1:0),c=c+b,q=q+j+(c>>>0<b>>>0?1:0),b=u+T,s=p+s+(b>>>0<u>>>0?1:0),V=S,E=D,S=R,D=C,R=l,C=h,h=B+c|0,l=U+q+(h>>>0<B>>>0?1:0)|0,U=A,B=y,A=z,y=x,z=k,x=g,g=c+b|0,k=q+s+(g>>>0<c>>>0?1:0)|0}J=F.low=J+g;F.high=w+k+(J>>>0<g>>>0?1:0);K=e.low=K+x;e.high=X+z+(K>>>0<x>>>0?1:0);L=n.low=L+y;n.high=Y+A+(L>>>0<y>>>0?1:0);M=r.low=M+B;r.high=Z+U+(M>>>0<B>>>0?1:0);N=G.low=N+h;G.high=$+l+(N>>>0<h>>>0?1:0);O=H.low=O+C;H.high=aa+R+(O>>>0<C>>>0?1:0);P=I.low=P+D;
I.high=ba+S+(P>>>0<D>>>0?1:0);Q=f.low=Q+E;f.high=ca+V+(Q>>>0<E>>>0?1:0)},_doFinalize:function(){var a=this._data,d=a.words,f=8*this._nDataBytes,e=8*a.sigBytes;d[e>>>5]|=128<<24-e%32;d[(e+128>>>10<<5)+30]=Math.floor(f/4294967296);d[(e+128>>>10<<5)+31]=f;a.sigBytes=4*d.length;this._process();return this._hash.toX32()},clone:function(){var a=r.clone.call(this);a._hash=this._hash.clone();return a},blockSize:32});n.SHA512=r._createHelper(e);n.HmacSHA512=r._createHmacHelper(e)})();

/*  sha384-min.js  */
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(){var c=CryptoJS,a=c.x64,b=a.Word,e=a.WordArray,a=c.algo,d=a.SHA512,a=a.SHA384=d.extend({_doReset:function(){this._hash=new e.init([new b.init(3418070365,3238371032),new b.init(1654270250,914150663),new b.init(2438529370,812702999),new b.init(355462360,4144912697),new b.init(1731405415,4290775857),new b.init(2394180231,1750603025),new b.init(3675008525,1694076839),new b.init(1203062813,3204075428)])},_doFinalize:function(){var a=d._doFinalize.call(this);a.sigBytes-=16;return a}});c.SHA384=
d._createHelper(a);c.HmacSHA384=d._createHmacHelper(a)})();

/*  base64-min.js  */
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
var b64map="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";var b64pad="=";function hex2b64(d){var b;var e;var a="";for(b=0;b+3<=d.length;b+=3){e=parseInt(d.substring(b,b+3),16);a+=b64map.charAt(e>>6)+b64map.charAt(e&63)}if(b+1==d.length){e=parseInt(d.substring(b,b+1),16);a+=b64map.charAt(e<<2)}else{if(b+2==d.length){e=parseInt(d.substring(b,b+2),16);a+=b64map.charAt(e>>2)+b64map.charAt((e&3)<<4)}}if(b64pad){while((a.length&3)>0){a+=b64pad}}return a}function b64tohex(f){var d="";var e;var b=0;var c;var a;for(e=0;e<f.length;++e){if(f.charAt(e)==b64pad){break}a=b64map.indexOf(f.charAt(e));if(a<0){continue}if(b==0){d+=int2char(a>>2);c=a&3;b=1}else{if(b==1){d+=int2char((c<<2)|(a>>4));c=a&15;b=2}else{if(b==2){d+=int2char(c);d+=int2char(a>>2);c=a&3;b=3}else{d+=int2char((c<<2)|(a>>4));d+=int2char(a&15);b=0}}}}if(b==1){d+=int2char(c<<2)}return d}function b64toBA(e){var d=b64tohex(e);var c;var b=new Array();for(c=0;2*c<d.length;++c){b[c]=parseInt(d.substring(2*c,2*c+2),16)}return b};
/*  jsbn-min.js  */
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
var dbits;var canary=244837814094590;var j_lm=((canary&16777215)==15715070);function BigInteger(e,d,f){if(e!=null){if("number"==typeof e){this.fromNumber(e,d,f)}else{if(d==null&&"string"!=typeof e){this.fromString(e,256)}else{this.fromString(e,d)}}}}function nbi(){return new BigInteger(null)}function am1(f,a,b,e,h,g){while(--g>=0){var d=a*this[f++]+b[e]+h;h=Math.floor(d/67108864);b[e++]=d&67108863}return h}function am2(f,q,r,e,o,a){var k=q&32767,p=q>>15;while(--a>=0){var d=this[f]&32767;var g=this[f++]>>15;var b=p*d+g*k;d=k*d+((b&32767)<<15)+r[e]+(o&1073741823);o=(d>>>30)+(b>>>15)+p*g+(o>>>30);r[e++]=d&1073741823}return o}function am3(f,q,r,e,o,a){var k=q&16383,p=q>>14;while(--a>=0){var d=this[f]&16383;var g=this[f++]>>14;var b=p*d+g*k;d=k*d+((b&16383)<<14)+r[e]+o;o=(d>>28)+(b>>14)+p*g;r[e++]=d&268435455}return o}if(j_lm&&(navigator.appName=="Microsoft Internet Explorer")){BigInteger.prototype.am=am2;dbits=30}else{if(j_lm&&(navigator.appName!="Netscape")){BigInteger.prototype.am=am1;dbits=26}else{BigInteger.prototype.am=am3;dbits=28}}BigInteger.prototype.DB=dbits;BigInteger.prototype.DM=((1<<dbits)-1);BigInteger.prototype.DV=(1<<dbits);var BI_FP=52;BigInteger.prototype.FV=Math.pow(2,BI_FP);BigInteger.prototype.F1=BI_FP-dbits;BigInteger.prototype.F2=2*dbits-BI_FP;var BI_RM="0123456789abcdefghijklmnopqrstuvwxyz";var BI_RC=new Array();var rr,vv;rr="0".charCodeAt(0);for(vv=0;vv<=9;++vv){BI_RC[rr++]=vv}rr="a".charCodeAt(0);for(vv=10;vv<36;++vv){BI_RC[rr++]=vv}rr="A".charCodeAt(0);for(vv=10;vv<36;++vv){BI_RC[rr++]=vv}function int2char(a){return BI_RM.charAt(a)}function intAt(b,a){var d=BI_RC[b.charCodeAt(a)];return(d==null)?-1:d}function bnpCopyTo(b){for(var a=this.t-1;a>=0;--a){b[a]=this[a]}b.t=this.t;b.s=this.s}function bnpFromInt(a){this.t=1;this.s=(a<0)?-1:0;if(a>0){this[0]=a}else{if(a<-1){this[0]=a+this.DV}else{this.t=0}}}function nbv(a){var b=nbi();b.fromInt(a);return b}function bnpFromString(h,c){var e;if(c==16){e=4}else{if(c==8){e=3}else{if(c==256){e=8}else{if(c==2){e=1}else{if(c==32){e=5}else{if(c==4){e=2}else{this.fromRadix(h,c);return}}}}}}this.t=0;this.s=0;var g=h.length,d=false,f=0;while(--g>=0){var a=(e==8)?h[g]&255:intAt(h,g);if(a<0){if(h.charAt(g)=="-"){d=true}continue}d=false;if(f==0){this[this.t++]=a}else{if(f+e>this.DB){this[this.t-1]|=(a&((1<<(this.DB-f))-1))<<f;this[this.t++]=(a>>(this.DB-f))}else{this[this.t-1]|=a<<f}}f+=e;if(f>=this.DB){f-=this.DB}}if(e==8&&(h[0]&128)!=0){this.s=-1;if(f>0){this[this.t-1]|=((1<<(this.DB-f))-1)<<f}}this.clamp();if(d){BigInteger.ZERO.subTo(this,this)}}function bnpClamp(){var a=this.s&this.DM;while(this.t>0&&this[this.t-1]==a){--this.t}}function bnToString(c){if(this.s<0){return"-"+this.negate().toString(c)}var e;if(c==16){e=4}else{if(c==8){e=3}else{if(c==2){e=1}else{if(c==32){e=5}else{if(c==4){e=2}else{return this.toRadix(c)}}}}}var g=(1<<e)-1,l,a=false,h="",f=this.t;var j=this.DB-(f*this.DB)%e;if(f-->0){if(j<this.DB&&(l=this[f]>>j)>0){a=true;h=int2char(l)}while(f>=0){if(j<e){l=(this[f]&((1<<j)-1))<<(e-j);l|=this[--f]>>(j+=this.DB-e)}else{l=(this[f]>>(j-=e))&g;if(j<=0){j+=this.DB;--f}}if(l>0){a=true}if(a){h+=int2char(l)}}}return a?h:"0"}function bnNegate(){var a=nbi();BigInteger.ZERO.subTo(this,a);return a}function bnAbs(){return(this.s<0)?this.negate():this}function bnCompareTo(b){var d=this.s-b.s;if(d!=0){return d}var c=this.t;d=c-b.t;if(d!=0){return(this.s<0)?-d:d}while(--c>=0){if((d=this[c]-b[c])!=0){return d}}return 0}function nbits(a){var c=1,b;if((b=a>>>16)!=0){a=b;c+=16}if((b=a>>8)!=0){a=b;c+=8}if((b=a>>4)!=0){a=b;c+=4}if((b=a>>2)!=0){a=b;c+=2}if((b=a>>1)!=0){a=b;c+=1}return c}function bnBitLength(){if(this.t<=0){return 0}return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM))}function bnpDLShiftTo(c,b){var a;for(a=this.t-1;a>=0;--a){b[a+c]=this[a]}for(a=c-1;a>=0;--a){b[a]=0}b.t=this.t+c;b.s=this.s}function bnpDRShiftTo(c,b){for(var a=c;a<this.t;++a){b[a-c]=this[a]}b.t=Math.max(this.t-c,0);b.s=this.s}function bnpLShiftTo(j,e){var b=j%this.DB;var a=this.DB-b;var g=(1<<a)-1;var f=Math.floor(j/this.DB),h=(this.s<<b)&this.DM,d;for(d=this.t-1;d>=0;--d){e[d+f+1]=(this[d]>>a)|h;h=(this[d]&g)<<b}for(d=f-1;d>=0;--d){e[d]=0}e[f]=h;e.t=this.t+f+1;e.s=this.s;e.clamp()}function bnpRShiftTo(g,d){d.s=this.s;var e=Math.floor(g/this.DB);if(e>=this.t){d.t=0;return}var b=g%this.DB;var a=this.DB-b;var f=(1<<b)-1;d[0]=this[e]>>b;for(var c=e+1;c<this.t;++c){d[c-e-1]|=(this[c]&f)<<a;d[c-e]=this[c]>>b}if(b>0){d[this.t-e-1]|=(this.s&f)<<a}d.t=this.t-e;d.clamp()}function bnpSubTo(d,f){var e=0,g=0,b=Math.min(d.t,this.t);while(e<b){g+=this[e]-d[e];f[e++]=g&this.DM;g>>=this.DB}if(d.t<this.t){g-=d.s;while(e<this.t){g+=this[e];f[e++]=g&this.DM;g>>=this.DB}g+=this.s}else{g+=this.s;while(e<d.t){g-=d[e];f[e++]=g&this.DM;g>>=this.DB}g-=d.s}f.s=(g<0)?-1:0;if(g<-1){f[e++]=this.DV+g}else{if(g>0){f[e++]=g}}f.t=e;f.clamp()}function bnpMultiplyTo(c,e){var b=this.abs(),f=c.abs();var d=b.t;e.t=d+f.t;while(--d>=0){e[d]=0}for(d=0;d<f.t;++d){e[d+b.t]=b.am(0,f[d],e,d,0,b.t)}e.s=0;e.clamp();if(this.s!=c.s){BigInteger.ZERO.subTo(e,e)}}function bnpSquareTo(d){var a=this.abs();var b=d.t=2*a.t;while(--b>=0){d[b]=0}for(b=0;b<a.t-1;++b){var e=a.am(b,a[b],d,2*b,0,1);if((d[b+a.t]+=a.am(b+1,2*a[b],d,2*b+1,e,a.t-b-1))>=a.DV){d[b+a.t]-=a.DV;d[b+a.t+1]=1}}if(d.t>0){d[d.t-1]+=a.am(b,a[b],d,2*b,0,1)}d.s=0;d.clamp()}function bnpDivRemTo(n,h,g){var w=n.abs();if(w.t<=0){return}var k=this.abs();if(k.t<w.t){if(h!=null){h.fromInt(0)}if(g!=null){this.copyTo(g)}return}if(g==null){g=nbi()}var d=nbi(),a=this.s,l=n.s;var v=this.DB-nbits(w[w.t-1]);if(v>0){w.lShiftTo(v,d);k.lShiftTo(v,g)}else{w.copyTo(d);k.copyTo(g)}var p=d.t;var b=d[p-1];if(b==0){return}var o=b*(1<<this.F1)+((p>1)?d[p-2]>>this.F2:0);var A=this.FV/o,z=(1<<this.F1)/o,x=1<<this.F2;var u=g.t,s=u-p,f=(h==null)?nbi():h;d.dlShiftTo(s,f);if(g.compareTo(f)>=0){g[g.t++]=1;g.subTo(f,g)}BigInteger.ONE.dlShiftTo(p,f);f.subTo(d,d);while(d.t<p){d[d.t++]=0}while(--s>=0){var c=(g[--u]==b)?this.DM:Math.floor(g[u]*A+(g[u-1]+x)*z);if((g[u]+=d.am(0,c,g,s,0,p))<c){d.dlShiftTo(s,f);g.subTo(f,g);while(g[u]<--c){g.subTo(f,g)}}}if(h!=null){g.drShiftTo(p,h);if(a!=l){BigInteger.ZERO.subTo(h,h)}}g.t=p;g.clamp();if(v>0){g.rShiftTo(v,g)}if(a<0){BigInteger.ZERO.subTo(g,g)}}function bnMod(b){var c=nbi();this.abs().divRemTo(b,null,c);if(this.s<0&&c.compareTo(BigInteger.ZERO)>0){b.subTo(c,c)}return c}function Classic(a){this.m=a}function cConvert(a){if(a.s<0||a.compareTo(this.m)>=0){return a.mod(this.m)}else{return a}}function cRevert(a){return a}function cReduce(a){a.divRemTo(this.m,null,a)}function cMulTo(a,c,b){a.multiplyTo(c,b);this.reduce(b)}function cSqrTo(a,b){a.squareTo(b);this.reduce(b)}Classic.prototype.convert=cConvert;Classic.prototype.revert=cRevert;Classic.prototype.reduce=cReduce;Classic.prototype.mulTo=cMulTo;Classic.prototype.sqrTo=cSqrTo;function bnpInvDigit(){if(this.t<1){return 0}var a=this[0];if((a&1)==0){return 0}var b=a&3;b=(b*(2-(a&15)*b))&15;b=(b*(2-(a&255)*b))&255;b=(b*(2-(((a&65535)*b)&65535)))&65535;b=(b*(2-a*b%this.DV))%this.DV;return(b>0)?this.DV-b:-b}function Montgomery(a){this.m=a;this.mp=a.invDigit();this.mpl=this.mp&32767;this.mph=this.mp>>15;this.um=(1<<(a.DB-15))-1;this.mt2=2*a.t}function montConvert(a){var b=nbi();a.abs().dlShiftTo(this.m.t,b);b.divRemTo(this.m,null,b);if(a.s<0&&b.compareTo(BigInteger.ZERO)>0){this.m.subTo(b,b)}return b}function montRevert(a){var b=nbi();a.copyTo(b);this.reduce(b);return b}function montReduce(a){while(a.t<=this.mt2){a[a.t++]=0}for(var c=0;c<this.m.t;++c){var b=a[c]&32767;var d=(b*this.mpl+(((b*this.mph+(a[c]>>15)*this.mpl)&this.um)<<15))&a.DM;b=c+this.m.t;a[b]+=this.m.am(0,d,a,c,0,this.m.t);while(a[b]>=a.DV){a[b]-=a.DV;a[++b]++}}a.clamp();a.drShiftTo(this.m.t,a);if(a.compareTo(this.m)>=0){a.subTo(this.m,a)}}function montSqrTo(a,b){a.squareTo(b);this.reduce(b)}function montMulTo(a,c,b){a.multiplyTo(c,b);this.reduce(b)}Montgomery.prototype.convert=montConvert;Montgomery.prototype.revert=montRevert;Montgomery.prototype.reduce=montReduce;Montgomery.prototype.mulTo=montMulTo;Montgomery.prototype.sqrTo=montSqrTo;function bnpIsEven(){return((this.t>0)?(this[0]&1):this.s)==0}function bnpExp(h,j){if(h>4294967295||h<1){return BigInteger.ONE}var f=nbi(),a=nbi(),d=j.convert(this),c=nbits(h)-1;d.copyTo(f);while(--c>=0){j.sqrTo(f,a);if((h&(1<<c))>0){j.mulTo(a,d,f)}else{var b=f;f=a;a=b}}return j.revert(f)}function bnModPowInt(b,a){var c;if(b<256||a.isEven()){c=new Classic(a)}else{c=new Montgomery(a)}return this.exp(b,c)}BigInteger.prototype.copyTo=bnpCopyTo;BigInteger.prototype.fromInt=bnpFromInt;BigInteger.prototype.fromString=bnpFromString;BigInteger.prototype.clamp=bnpClamp;BigInteger.prototype.dlShiftTo=bnpDLShiftTo;BigInteger.prototype.drShiftTo=bnpDRShiftTo;BigInteger.prototype.lShiftTo=bnpLShiftTo;BigInteger.prototype.rShiftTo=bnpRShiftTo;BigInteger.prototype.subTo=bnpSubTo;BigInteger.prototype.multiplyTo=bnpMultiplyTo;BigInteger.prototype.squareTo=bnpSquareTo;BigInteger.prototype.divRemTo=bnpDivRemTo;BigInteger.prototype.invDigit=bnpInvDigit;BigInteger.prototype.isEven=bnpIsEven;BigInteger.prototype.exp=bnpExp;BigInteger.prototype.toString=bnToString;BigInteger.prototype.negate=bnNegate;BigInteger.prototype.abs=bnAbs;BigInteger.prototype.compareTo=bnCompareTo;BigInteger.prototype.bitLength=bnBitLength;BigInteger.prototype.mod=bnMod;BigInteger.prototype.modPowInt=bnModPowInt;BigInteger.ZERO=nbv(0);BigInteger.ONE=nbv(1);
/*  jsbn2-min.js  */
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function bnClone(){var a=nbi();this.copyTo(a);return a}function bnIntValue(){if(this.s<0){if(this.t==1){return this[0]-this.DV}else{if(this.t==0){return -1}}}else{if(this.t==1){return this[0]}else{if(this.t==0){return 0}}}return((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0]}function bnByteValue(){return(this.t==0)?this.s:(this[0]<<24)>>24}function bnShortValue(){return(this.t==0)?this.s:(this[0]<<16)>>16}function bnpChunkSize(a){return Math.floor(Math.LN2*this.DB/Math.log(a))}function bnSigNum(){if(this.s<0){return -1}else{if(this.t<=0||(this.t==1&&this[0]<=0)){return 0}else{return 1}}}function bnpToRadix(c){if(c==null){c=10}if(this.signum()==0||c<2||c>36){return"0"}var f=this.chunkSize(c);var e=Math.pow(c,f);var i=nbv(e),j=nbi(),h=nbi(),g="";this.divRemTo(i,j,h);while(j.signum()>0){g=(e+h.intValue()).toString(c).substr(1)+g;j.divRemTo(i,j,h)}return h.intValue().toString(c)+g}function bnpFromRadix(m,h){this.fromInt(0);if(h==null){h=10}var f=this.chunkSize(h);var g=Math.pow(h,f),e=false,a=0,l=0;for(var c=0;c<m.length;++c){var k=intAt(m,c);if(k<0){if(m.charAt(c)=="-"&&this.signum()==0){e=true}continue}l=h*l+k;if(++a>=f){this.dMultiply(g);this.dAddOffset(l,0);a=0;l=0}}if(a>0){this.dMultiply(Math.pow(h,a));this.dAddOffset(l,0)}if(e){BigInteger.ZERO.subTo(this,this)}}function bnpFromNumber(f,e,h){if("number"==typeof e){if(f<2){this.fromInt(1)}else{this.fromNumber(f,h);if(!this.testBit(f-1)){this.bitwiseTo(BigInteger.ONE.shiftLeft(f-1),op_or,this)}if(this.isEven()){this.dAddOffset(1,0)}while(!this.isProbablePrime(e)){this.dAddOffset(2,0);if(this.bitLength()>f){this.subTo(BigInteger.ONE.shiftLeft(f-1),this)}}}}else{var d=new Array(),g=f&7;d.length=(f>>3)+1;e.nextBytes(d);if(g>0){d[0]&=((1<<g)-1)}else{d[0]=0}this.fromString(d,256)}}function bnToByteArray(){var b=this.t,c=new Array();c[0]=this.s;var e=this.DB-(b*this.DB)%8,f,a=0;if(b-->0){if(e<this.DB&&(f=this[b]>>e)!=(this.s&this.DM)>>e){c[a++]=f|(this.s<<(this.DB-e))}while(b>=0){if(e<8){f=(this[b]&((1<<e)-1))<<(8-e);f|=this[--b]>>(e+=this.DB-8)}else{f=(this[b]>>(e-=8))&255;if(e<=0){e+=this.DB;--b}}if((f&128)!=0){f|=-256}if(a==0&&(this.s&128)!=(f&128)){++a}if(a>0||f!=this.s){c[a++]=f}}}return c}function bnEquals(b){return(this.compareTo(b)==0)}function bnMin(b){return(this.compareTo(b)<0)?this:b}function bnMax(b){return(this.compareTo(b)>0)?this:b}function bnpBitwiseTo(c,h,e){var d,g,b=Math.min(c.t,this.t);for(d=0;d<b;++d){e[d]=h(this[d],c[d])}if(c.t<this.t){g=c.s&this.DM;for(d=b;d<this.t;++d){e[d]=h(this[d],g)}e.t=this.t}else{g=this.s&this.DM;for(d=b;d<c.t;++d){e[d]=h(g,c[d])}e.t=c.t}e.s=h(this.s,c.s);e.clamp()}function op_and(a,b){return a&b}function bnAnd(b){var c=nbi();this.bitwiseTo(b,op_and,c);return c}function op_or(a,b){return a|b}function bnOr(b){var c=nbi();this.bitwiseTo(b,op_or,c);return c}function op_xor(a,b){return a^b}function bnXor(b){var c=nbi();this.bitwiseTo(b,op_xor,c);return c}function op_andnot(a,b){return a&~b}function bnAndNot(b){var c=nbi();this.bitwiseTo(b,op_andnot,c);return c}function bnNot(){var b=nbi();for(var a=0;a<this.t;++a){b[a]=this.DM&~this[a]}b.t=this.t;b.s=~this.s;return b}function bnShiftLeft(b){var a=nbi();if(b<0){this.rShiftTo(-b,a)}else{this.lShiftTo(b,a)}return a}function bnShiftRight(b){var a=nbi();if(b<0){this.lShiftTo(-b,a)}else{this.rShiftTo(b,a)}return a}function lbit(a){if(a==0){return -1}var b=0;if((a&65535)==0){a>>=16;b+=16}if((a&255)==0){a>>=8;b+=8}if((a&15)==0){a>>=4;b+=4}if((a&3)==0){a>>=2;b+=2}if((a&1)==0){++b}return b}function bnGetLowestSetBit(){for(var a=0;a<this.t;++a){if(this[a]!=0){return a*this.DB+lbit(this[a])}}if(this.s<0){return this.t*this.DB}return -1}function cbit(a){var b=0;while(a!=0){a&=a-1;++b}return b}function bnBitCount(){var c=0,a=this.s&this.DM;for(var b=0;b<this.t;++b){c+=cbit(this[b]^a)}return c}function bnTestBit(b){var a=Math.floor(b/this.DB);if(a>=this.t){return(this.s!=0)}return((this[a]&(1<<(b%this.DB)))!=0)}function bnpChangeBit(c,b){var a=BigInteger.ONE.shiftLeft(c);this.bitwiseTo(a,b,a);return a}function bnSetBit(a){return this.changeBit(a,op_or)}function bnClearBit(a){return this.changeBit(a,op_andnot)}function bnFlipBit(a){return this.changeBit(a,op_xor)}function bnpAddTo(d,f){var e=0,g=0,b=Math.min(d.t,this.t);while(e<b){g+=this[e]+d[e];f[e++]=g&this.DM;g>>=this.DB}if(d.t<this.t){g+=d.s;while(e<this.t){g+=this[e];f[e++]=g&this.DM;g>>=this.DB}g+=this.s}else{g+=this.s;while(e<d.t){g+=d[e];f[e++]=g&this.DM;g>>=this.DB}g+=d.s}f.s=(g<0)?-1:0;if(g>0){f[e++]=g}else{if(g<-1){f[e++]=this.DV+g}}f.t=e;f.clamp()}function bnAdd(b){var c=nbi();this.addTo(b,c);return c}function bnSubtract(b){var c=nbi();this.subTo(b,c);return c}function bnMultiply(b){var c=nbi();this.multiplyTo(b,c);return c}function bnSquare(){var a=nbi();this.squareTo(a);return a}function bnDivide(b){var c=nbi();this.divRemTo(b,c,null);return c}function bnRemainder(b){var c=nbi();this.divRemTo(b,null,c);return c}function bnDivideAndRemainder(b){var d=nbi(),c=nbi();this.divRemTo(b,d,c);return new Array(d,c)}function bnpDMultiply(a){this[this.t]=this.am(0,a-1,this,0,0,this.t);++this.t;this.clamp()}function bnpDAddOffset(b,a){if(b==0){return}while(this.t<=a){this[this.t++]=0}this[a]+=b;while(this[a]>=this.DV){this[a]-=this.DV;if(++a>=this.t){this[this.t++]=0}++this[a]}}function NullExp(){}function nNop(a){return a}function nMulTo(a,c,b){a.multiplyTo(c,b)}function nSqrTo(a,b){a.squareTo(b)}NullExp.prototype.convert=nNop;NullExp.prototype.revert=nNop;NullExp.prototype.mulTo=nMulTo;NullExp.prototype.sqrTo=nSqrTo;function bnPow(a){return this.exp(a,new NullExp())}function bnpMultiplyLowerTo(b,f,e){var d=Math.min(this.t+b.t,f);e.s=0;e.t=d;while(d>0){e[--d]=0}var c;for(c=e.t-this.t;d<c;++d){e[d+this.t]=this.am(0,b[d],e,d,0,this.t)}for(c=Math.min(b.t,f);d<c;++d){this.am(0,b[d],e,d,0,f-d)}e.clamp()}function bnpMultiplyUpperTo(b,e,d){--e;var c=d.t=this.t+b.t-e;d.s=0;while(--c>=0){d[c]=0}for(c=Math.max(e-this.t,0);c<b.t;++c){d[this.t+c-e]=this.am(e-c,b[c],d,0,0,this.t+c-e)}d.clamp();d.drShiftTo(1,d)}function Barrett(a){this.r2=nbi();this.q3=nbi();BigInteger.ONE.dlShiftTo(2*a.t,this.r2);this.mu=this.r2.divide(a);this.m=a}function barrettConvert(a){if(a.s<0||a.t>2*this.m.t){return a.mod(this.m)}else{if(a.compareTo(this.m)<0){return a}else{var b=nbi();a.copyTo(b);this.reduce(b);return b}}}function barrettRevert(a){return a}function barrettReduce(a){a.drShiftTo(this.m.t-1,this.r2);if(a.t>this.m.t+1){a.t=this.m.t+1;a.clamp()}this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);while(a.compareTo(this.r2)<0){a.dAddOffset(1,this.m.t+1)}a.subTo(this.r2,a);while(a.compareTo(this.m)>=0){a.subTo(this.m,a)}}function barrettSqrTo(a,b){a.squareTo(b);this.reduce(b)}function barrettMulTo(a,c,b){a.multiplyTo(c,b);this.reduce(b)}Barrett.prototype.convert=barrettConvert;Barrett.prototype.revert=barrettRevert;Barrett.prototype.reduce=barrettReduce;Barrett.prototype.mulTo=barrettMulTo;Barrett.prototype.sqrTo=barrettSqrTo;function bnModPow(q,f){var o=q.bitLength(),h,b=nbv(1),v;if(o<=0){return b}else{if(o<18){h=1}else{if(o<48){h=3}else{if(o<144){h=4}else{if(o<768){h=5}else{h=6}}}}}if(o<8){v=new Classic(f)}else{if(f.isEven()){v=new Barrett(f)}else{v=new Montgomery(f)}}var p=new Array(),d=3,s=h-1,a=(1<<h)-1;p[1]=v.convert(this);if(h>1){var A=nbi();v.sqrTo(p[1],A);while(d<=a){p[d]=nbi();v.mulTo(A,p[d-2],p[d]);d+=2}}var l=q.t-1,x,u=true,c=nbi(),y;o=nbits(q[l])-1;while(l>=0){if(o>=s){x=(q[l]>>(o-s))&a}else{x=(q[l]&((1<<(o+1))-1))<<(s-o);if(l>0){x|=q[l-1]>>(this.DB+o-s)}}d=h;while((x&1)==0){x>>=1;--d}if((o-=d)<0){o+=this.DB;--l}if(u){p[x].copyTo(b);u=false}else{while(d>1){v.sqrTo(b,c);v.sqrTo(c,b);d-=2}if(d>0){v.sqrTo(b,c)}else{y=b;b=c;c=y}v.mulTo(c,p[x],b)}while(l>=0&&(q[l]&(1<<o))==0){v.sqrTo(b,c);y=b;b=c;c=y;if(--o<0){o=this.DB-1;--l}}}return v.revert(b)}function bnGCD(c){var b=(this.s<0)?this.negate():this.clone();var h=(c.s<0)?c.negate():c.clone();if(b.compareTo(h)<0){var e=b;b=h;h=e}var d=b.getLowestSetBit(),f=h.getLowestSetBit();if(f<0){return b}if(d<f){f=d}if(f>0){b.rShiftTo(f,b);h.rShiftTo(f,h)}while(b.signum()>0){if((d=b.getLowestSetBit())>0){b.rShiftTo(d,b)}if((d=h.getLowestSetBit())>0){h.rShiftTo(d,h)}if(b.compareTo(h)>=0){b.subTo(h,b);b.rShiftTo(1,b)}else{h.subTo(b,h);h.rShiftTo(1,h)}}if(f>0){h.lShiftTo(f,h)}return h}function bnpModInt(e){if(e<=0){return 0}var c=this.DV%e,b=(this.s<0)?e-1:0;if(this.t>0){if(c==0){b=this[0]%e}else{for(var a=this.t-1;a>=0;--a){b=(c*b+this[a])%e}}}return b}function bnModInverse(f){var j=f.isEven();if((this.isEven()&&j)||f.signum()==0){return BigInteger.ZERO}var i=f.clone(),h=this.clone();var g=nbv(1),e=nbv(0),l=nbv(0),k=nbv(1);while(i.signum()!=0){while(i.isEven()){i.rShiftTo(1,i);if(j){if(!g.isEven()||!e.isEven()){g.addTo(this,g);e.subTo(f,e)}g.rShiftTo(1,g)}else{if(!e.isEven()){e.subTo(f,e)}}e.rShiftTo(1,e)}while(h.isEven()){h.rShiftTo(1,h);if(j){if(!l.isEven()||!k.isEven()){l.addTo(this,l);k.subTo(f,k)}l.rShiftTo(1,l)}else{if(!k.isEven()){k.subTo(f,k)}}k.rShiftTo(1,k)}if(i.compareTo(h)>=0){i.subTo(h,i);if(j){g.subTo(l,g)}e.subTo(k,e)}else{h.subTo(i,h);if(j){l.subTo(g,l)}k.subTo(e,k)}}if(h.compareTo(BigInteger.ONE)!=0){return BigInteger.ZERO}if(k.compareTo(f)>=0){return k.subtract(f)}if(k.signum()<0){k.addTo(f,k)}else{return k}if(k.signum()<0){return k.add(f)}else{return k}}var lowprimes=[2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];var lplim=(1<<26)/lowprimes[lowprimes.length-1];function bnIsProbablePrime(e){var d,b=this.abs();if(b.t==1&&b[0]<=lowprimes[lowprimes.length-1]){for(d=0;d<lowprimes.length;++d){if(b[0]==lowprimes[d]){return true}}return false}if(b.isEven()){return false}d=1;while(d<lowprimes.length){var a=lowprimes[d],c=d+1;while(c<lowprimes.length&&a<lplim){a*=lowprimes[c++]}a=b.modInt(a);while(d<c){if(a%lowprimes[d++]==0){return false}}}return b.millerRabin(e)}function bnpMillerRabin(f){var g=this.subtract(BigInteger.ONE);var c=g.getLowestSetBit();if(c<=0){return false}var h=g.shiftRight(c);f=(f+1)>>1;if(f>lowprimes.length){f=lowprimes.length}var b=nbi();for(var e=0;e<f;++e){b.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);var l=b.modPow(h,this);if(l.compareTo(BigInteger.ONE)!=0&&l.compareTo(g)!=0){var d=1;while(d++<c&&l.compareTo(g)!=0){l=l.modPowInt(2,this);if(l.compareTo(BigInteger.ONE)==0){return false}}if(l.compareTo(g)!=0){return false}}}return true}BigInteger.prototype.chunkSize=bnpChunkSize;BigInteger.prototype.toRadix=bnpToRadix;BigInteger.prototype.fromRadix=bnpFromRadix;BigInteger.prototype.fromNumber=bnpFromNumber;BigInteger.prototype.bitwiseTo=bnpBitwiseTo;BigInteger.prototype.changeBit=bnpChangeBit;BigInteger.prototype.addTo=bnpAddTo;BigInteger.prototype.dMultiply=bnpDMultiply;BigInteger.prototype.dAddOffset=bnpDAddOffset;BigInteger.prototype.multiplyLowerTo=bnpMultiplyLowerTo;BigInteger.prototype.multiplyUpperTo=bnpMultiplyUpperTo;BigInteger.prototype.modInt=bnpModInt;BigInteger.prototype.millerRabin=bnpMillerRabin;BigInteger.prototype.clone=bnClone;BigInteger.prototype.intValue=bnIntValue;BigInteger.prototype.byteValue=bnByteValue;BigInteger.prototype.shortValue=bnShortValue;BigInteger.prototype.signum=bnSigNum;BigInteger.prototype.toByteArray=bnToByteArray;BigInteger.prototype.equals=bnEquals;BigInteger.prototype.min=bnMin;BigInteger.prototype.max=bnMax;BigInteger.prototype.and=bnAnd;BigInteger.prototype.or=bnOr;BigInteger.prototype.xor=bnXor;BigInteger.prototype.andNot=bnAndNot;BigInteger.prototype.not=bnNot;BigInteger.prototype.shiftLeft=bnShiftLeft;BigInteger.prototype.shiftRight=bnShiftRight;BigInteger.prototype.getLowestSetBit=bnGetLowestSetBit;BigInteger.prototype.bitCount=bnBitCount;BigInteger.prototype.testBit=bnTestBit;BigInteger.prototype.setBit=bnSetBit;BigInteger.prototype.clearBit=bnClearBit;BigInteger.prototype.flipBit=bnFlipBit;BigInteger.prototype.add=bnAdd;BigInteger.prototype.subtract=bnSubtract;BigInteger.prototype.multiply=bnMultiply;BigInteger.prototype.divide=bnDivide;BigInteger.prototype.remainder=bnRemainder;BigInteger.prototype.divideAndRemainder=bnDivideAndRemainder;BigInteger.prototype.modPow=bnModPow;BigInteger.prototype.modInverse=bnModInverse;BigInteger.prototype.pow=bnPow;BigInteger.prototype.gcd=bnGCD;BigInteger.prototype.isProbablePrime=bnIsProbablePrime;BigInteger.prototype.square=bnSquare;
/*  rsa-min.js  */
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function parseBigInt(b,a){return new BigInteger(b,a)}function linebrk(c,d){var a="";var b=0;while(b+d<c.length){a+=c.substring(b,b+d)+"\n";b+=d}return a+c.substring(b,c.length)}function byte2Hex(a){if(a<16){return"0"+a.toString(16)}else{return a.toString(16)}}function pkcs1pad2(e,h){if(h<e.length+11){alert("Message too long for RSA");return null}var g=new Array();var d=e.length-1;while(d>=0&&h>0){var f=e.charCodeAt(d--);if(f<128){g[--h]=f}else{if((f>127)&&(f<2048)){g[--h]=(f&63)|128;g[--h]=(f>>6)|192}else{g[--h]=(f&63)|128;g[--h]=((f>>6)&63)|128;g[--h]=(f>>12)|224}}}g[--h]=0;var b=new SecureRandom();var a=new Array();while(h>2){a[0]=0;while(a[0]==0){b.nextBytes(a)}g[--h]=a[0]}g[--h]=2;g[--h]=0;return new BigInteger(g)}function oaep_mgf1_arr(c,a,e){var b="",d=0;while(b.length<a){b+=e(String.fromCharCode.apply(String,c.concat([(d&4278190080)>>24,(d&16711680)>>16,(d&65280)>>8,d&255])));d+=1}return b}var SHA1_SIZE=20;function oaep_pad(l,a,c){if(l.length+2*SHA1_SIZE+2>a){throw"Message too long for RSA"}var h="",d;for(d=0;d<a-l.length-2*SHA1_SIZE-2;d+=1){h+="\x00"}var e=rstr_sha1("")+h+"\x01"+l;var f=new Array(SHA1_SIZE);new SecureRandom().nextBytes(f);var g=oaep_mgf1_arr(f,e.length,c||rstr_sha1);var k=[];for(d=0;d<e.length;d+=1){k[d]=e.charCodeAt(d)^g.charCodeAt(d)}var j=oaep_mgf1_arr(k,f.length,rstr_sha1);var b=[0];for(d=0;d<f.length;d+=1){b[d+1]=f[d]^j.charCodeAt(d)}return new BigInteger(b.concat(k))}function RSAKey(){this.n=null;this.e=0;this.d=null;this.p=null;this.q=null;this.dmp1=null;this.dmq1=null;this.coeff=null}function RSASetPublic(b,a){this.isPublic=true;if(typeof b!=="string"){this.n=b;this.e=a}else{if(b!=null&&a!=null&&b.length>0&&a.length>0){this.n=parseBigInt(b,16);this.e=parseInt(a,16)}else{alert("Invalid RSA public key")}}}function RSADoPublic(a){return a.modPowInt(this.e,this.n)}function RSAEncrypt(d){var a=pkcs1pad2(d,(this.n.bitLength()+7)>>3);if(a==null){return null}var e=this.doPublic(a);if(e==null){return null}var b=e.toString(16);if((b.length&1)==0){return b}else{return"0"+b}}function RSAEncryptOAEP(e,d){var a=oaep_pad(e,(this.n.bitLength()+7)>>3,d);if(a==null){return null}var f=this.doPublic(a);if(f==null){return null}var b=f.toString(16);if((b.length&1)==0){return b}else{return"0"+b}}RSAKey.prototype.doPublic=RSADoPublic;RSAKey.prototype.setPublic=RSASetPublic;RSAKey.prototype.encrypt=RSAEncrypt;RSAKey.prototype.encryptOAEP=RSAEncryptOAEP;RSAKey.prototype.type="RSA";
/*  rsa2-min.js  */
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function pkcs1unpad2(g,j){var a=g.toByteArray();var f=0;while(f<a.length&&a[f]==0){++f}if(a.length-f!=j-1||a[f]!=2){return null}++f;while(a[f]!=0){if(++f>=a.length){return null}}var e="";while(++f<a.length){var h=a[f]&255;if(h<128){e+=String.fromCharCode(h)}else{if((h>191)&&(h<224)){e+=String.fromCharCode(((h&31)<<6)|(a[f+1]&63));++f}else{e+=String.fromCharCode(((h&15)<<12)|((a[f+1]&63)<<6)|(a[f+2]&63));f+=2}}}return e}function oaep_mgf1_str(c,a,e){var b="",d=0;while(b.length<a){b+=e(c+String.fromCharCode.apply(String,[(d&4278190080)>>24,(d&16711680)>>16,(d&65280)>>8,d&255]));d+=1}return b}var SHA1_SIZE=20;function oaep_unpad(l,b,e){l=l.toByteArray();var f;for(f=0;f<l.length;f+=1){l[f]&=255}while(l.length<b){l.unshift(0)}l=String.fromCharCode.apply(String,l);if(l.length<2*SHA1_SIZE+2){throw"Cipher too short"}var c=l.substr(1,SHA1_SIZE);var o=l.substr(SHA1_SIZE+1);var m=oaep_mgf1_str(o,SHA1_SIZE,e||rstr_sha1);var h=[],f;for(f=0;f<c.length;f+=1){h[f]=c.charCodeAt(f)^m.charCodeAt(f)}var j=oaep_mgf1_str(String.fromCharCode.apply(String,h),l.length-SHA1_SIZE,rstr_sha1);var g=[];for(f=0;f<o.length;f+=1){g[f]=o.charCodeAt(f)^j.charCodeAt(f)}g=String.fromCharCode.apply(String,g);if(g.substr(0,SHA1_SIZE)!==rstr_sha1("")){throw"Hash mismatch"}g=g.substr(SHA1_SIZE);var a=g.indexOf("\x01");var k=(a!=-1)?g.substr(0,a).lastIndexOf("\x00"):-1;if(k+1!=a){throw"Malformed data"}return g.substr(a+1)}function RSASetPrivate(c,a,b){this.isPrivate=true;if(typeof c!=="string"){this.n=c;this.e=a;this.d=b}else{if(c!=null&&a!=null&&c.length>0&&a.length>0){this.n=parseBigInt(c,16);this.e=parseInt(a,16);this.d=parseBigInt(b,16)}else{alert("Invalid RSA private key")}}}function RSASetPrivateEx(g,d,e,c,b,a,h,f){this.isPrivate=true;if(g==null){throw"RSASetPrivateEx N == null"}if(d==null){throw"RSASetPrivateEx E == null"}if(g.length==0){throw"RSASetPrivateEx N.length == 0"}if(d.length==0){throw"RSASetPrivateEx E.length == 0"}if(g!=null&&d!=null&&g.length>0&&d.length>0){this.n=parseBigInt(g,16);this.e=parseInt(d,16);this.d=parseBigInt(e,16);this.p=parseBigInt(c,16);this.q=parseBigInt(b,16);this.dmp1=parseBigInt(a,16);this.dmq1=parseBigInt(h,16);this.coeff=parseBigInt(f,16)}else{alert("Invalid RSA private key in RSASetPrivateEx")}}function RSAGenerate(b,i){var a=new SecureRandom();var f=b>>1;this.e=parseInt(i,16);var c=new BigInteger(i,16);for(;;){for(;;){this.p=new BigInteger(b-f,1,a);if(this.p.subtract(BigInteger.ONE).gcd(c).compareTo(BigInteger.ONE)==0&&this.p.isProbablePrime(10)){break}}for(;;){this.q=new BigInteger(f,1,a);if(this.q.subtract(BigInteger.ONE).gcd(c).compareTo(BigInteger.ONE)==0&&this.q.isProbablePrime(10)){break}}if(this.p.compareTo(this.q)<=0){var h=this.p;this.p=this.q;this.q=h}var g=this.p.subtract(BigInteger.ONE);var d=this.q.subtract(BigInteger.ONE);var e=g.multiply(d);if(e.gcd(c).compareTo(BigInteger.ONE)==0){this.n=this.p.multiply(this.q);this.d=c.modInverse(e);this.dmp1=this.d.mod(g);this.dmq1=this.d.mod(d);this.coeff=this.q.modInverse(this.p);break}}}function RSADoPrivate(a){if(this.p==null||this.q==null){return a.modPow(this.d,this.n)}var c=a.mod(this.p).modPow(this.dmp1,this.p);var b=a.mod(this.q).modPow(this.dmq1,this.q);while(c.compareTo(b)<0){c=c.add(this.p)}return c.subtract(b).multiply(this.coeff).mod(this.p).multiply(this.q).add(b)}function RSADecrypt(b){var d=parseBigInt(b,16);var a=this.doPrivate(d);if(a==null){return null}return pkcs1unpad2(a,(this.n.bitLength()+7)>>3)}function RSADecryptOAEP(d,b){var e=parseBigInt(d,16);var a=this.doPrivate(e);if(a==null){return null}return oaep_unpad(a,(this.n.bitLength()+7)>>3,b)}RSAKey.prototype.doPrivate=RSADoPrivate;RSAKey.prototype.setPrivate=RSASetPrivate;RSAKey.prototype.setPrivateEx=RSASetPrivateEx;RSAKey.prototype.generate=RSAGenerate;RSAKey.prototype.decrypt=RSADecrypt;RSAKey.prototype.decryptOAEP=RSADecryptOAEP;
/* rsapem-1.1.min.js  */
/*! rsapem-1.1.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
function _rsapem_pemToBase64(b){var a=b;a=a.replace("-----BEGIN RSA PRIVATE KEY-----","");a=a.replace("-----END RSA PRIVATE KEY-----","");a=a.replace(/[ \n]+/g,"");return a}function _rsapem_getPosArrayOfChildrenFromHex(d){var j=new Array();var k=ASN1HEX.getStartPosOfV_AtObj(d,0);var f=ASN1HEX.getPosOfNextSibling_AtObj(d,k);var h=ASN1HEX.getPosOfNextSibling_AtObj(d,f);var b=ASN1HEX.getPosOfNextSibling_AtObj(d,h);var l=ASN1HEX.getPosOfNextSibling_AtObj(d,b);var e=ASN1HEX.getPosOfNextSibling_AtObj(d,l);var g=ASN1HEX.getPosOfNextSibling_AtObj(d,e);var c=ASN1HEX.getPosOfNextSibling_AtObj(d,g);var i=ASN1HEX.getPosOfNextSibling_AtObj(d,c);j.push(k,f,h,b,l,e,g,c,i);return j}function _rsapem_getHexValueArrayOfChildrenFromHex(i){var o=_rsapem_getPosArrayOfChildrenFromHex(i);var r=ASN1HEX.getHexOfV_AtObj(i,o[0]);var f=ASN1HEX.getHexOfV_AtObj(i,o[1]);var j=ASN1HEX.getHexOfV_AtObj(i,o[2]);var k=ASN1HEX.getHexOfV_AtObj(i,o[3]);var c=ASN1HEX.getHexOfV_AtObj(i,o[4]);var b=ASN1HEX.getHexOfV_AtObj(i,o[5]);var h=ASN1HEX.getHexOfV_AtObj(i,o[6]);var g=ASN1HEX.getHexOfV_AtObj(i,o[7]);var l=ASN1HEX.getHexOfV_AtObj(i,o[8]);var m=new Array();m.push(r,f,j,k,c,b,h,g,l);return m}function _rsapem_readPrivateKeyFromASN1HexString(c){var b=_rsapem_getHexValueArrayOfChildrenFromHex(c);this.setPrivateEx(b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8])}function _rsapem_readPrivateKeyFromPEMString(e){var c=_rsapem_pemToBase64(e);var d=b64tohex(c);var b=_rsapem_getHexValueArrayOfChildrenFromHex(d);this.setPrivateEx(b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8])}RSAKey.prototype.readPrivateKeyFromPEMString=_rsapem_readPrivateKeyFromPEMString;RSAKey.prototype.readPrivateKeyFromASN1HexString=_rsapem_readPrivateKeyFromASN1HexString;
/* rsasign-1.2.min.js  */
/*! rsasign-1.2.7.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
var _RE_HEXDECONLY=new RegExp("");_RE_HEXDECONLY.compile("[^0-9a-f]","gi");function _rsasign_getHexPaddedDigestInfoForString(d,e,a){var b=function(f){return KJUR.crypto.Util.hashString(f,a)};var c=b(d);return KJUR.crypto.Util.getPaddedDigestInfoHex(c,a,e)}function _zeroPaddingOfSignature(e,d){var c="";var a=d/4-e.length;for(var b=0;b<a;b++){c=c+"0"}return c+e}function _rsasign_signString(d,a){var b=function(e){return KJUR.crypto.Util.hashString(e,a)};var c=b(d);return this.signWithMessageHash(c,a)}function _rsasign_signWithMessageHash(e,c){var f=KJUR.crypto.Util.getPaddedDigestInfoHex(e,c,this.n.bitLength());var b=parseBigInt(f,16);var d=this.doPrivate(b);var a=d.toString(16);return _zeroPaddingOfSignature(a,this.n.bitLength())}function _rsasign_signStringWithSHA1(a){return _rsasign_signString.call(this,a,"sha1")}function _rsasign_signStringWithSHA256(a){return _rsasign_signString.call(this,a,"sha256")}function pss_mgf1_str(c,a,e){var b="",d=0;while(b.length<a){b+=hextorstr(e(rstrtohex(c+String.fromCharCode.apply(String,[(d&4278190080)>>24,(d&16711680)>>16,(d&65280)>>8,d&255]))));d+=1}return b}function _rsasign_signStringPSS(e,a,d){var c=function(f){return KJUR.crypto.Util.hashHex(f,a)};var b=c(rstrtohex(e));if(d===undefined){d=-1}return this.signWithMessageHashPSS(b,a,d)}function _rsasign_signWithMessageHashPSS(l,a,k){var b=hextorstr(l);var g=b.length;var m=this.n.bitLength()-1;var c=Math.ceil(m/8);var d;var o=function(i){return KJUR.crypto.Util.hashHex(i,a)};if(k===-1||k===undefined){k=g}else{if(k===-2){k=c-g-2}else{if(k<-2){throw"invalid salt length"}}}if(c<(g+k+2)){throw"data too long"}var f="";if(k>0){f=new Array(k);new SecureRandom().nextBytes(f);f=String.fromCharCode.apply(String,f)}var n=hextorstr(o(rstrtohex("\x00\x00\x00\x00\x00\x00\x00\x00"+b+f)));var j=[];for(d=0;d<c-k-g-2;d+=1){j[d]=0}var e=String.fromCharCode.apply(String,j)+"\x01"+f;var h=pss_mgf1_str(n,e.length,o);var q=[];for(d=0;d<e.length;d+=1){q[d]=e.charCodeAt(d)^h.charCodeAt(d)}var p=(65280>>(8*c-m))&255;q[0]&=~p;for(d=0;d<g;d++){q.push(n.charCodeAt(d))}q.push(188);return _zeroPaddingOfSignature(this.doPrivate(new BigInteger(q)).toString(16),this.n.bitLength())}function _rsasign_getDecryptSignatureBI(a,d,c){var b=new RSAKey();b.setPublic(d,c);var e=b.doPublic(a);return e}function _rsasign_getHexDigestInfoFromSig(a,c,b){var e=_rsasign_getDecryptSignatureBI(a,c,b);var d=e.toString(16).replace(/^1f+00/,"");return d}function _rsasign_getAlgNameAndHashFromHexDisgestInfo(f){for(var e in KJUR.crypto.Util.DIGESTINFOHEAD){var d=KJUR.crypto.Util.DIGESTINFOHEAD[e];var b=d.length;if(f.substring(0,b)==d){var c=[e,f.substring(b)];return c}}return[]}function _rsasign_verifySignatureWithArgs(f,b,g,j){var e=_rsasign_getHexDigestInfoFromSig(b,g,j);var h=_rsasign_getAlgNameAndHashFromHexDisgestInfo(e);if(h.length==0){return false}var d=h[0];var i=h[1];var a=function(k){return KJUR.crypto.Util.hashString(k,d)};var c=a(f);return(i==c)}function _rsasign_verifyHexSignatureForMessage(c,b){var d=parseBigInt(c,16);var a=_rsasign_verifySignatureWithArgs(b,d,this.n.toString(16),this.e.toString(16));return a}function _rsasign_verifyString(f,j){j=j.replace(_RE_HEXDECONLY,"");j=j.replace(/[ \n]+/g,"");var b=parseBigInt(j,16);if(b.bitLength()>this.n.bitLength()){return 0}var i=this.doPublic(b);var e=i.toString(16).replace(/^1f+00/,"");var g=_rsasign_getAlgNameAndHashFromHexDisgestInfo(e);if(g.length==0){return false}var d=g[0];var h=g[1];var a=function(k){return KJUR.crypto.Util.hashString(k,d)};var c=a(f);return(h==c)}function _rsasign_verifyWithMessageHash(e,a){a=a.replace(_RE_HEXDECONLY,"");a=a.replace(/[ \n]+/g,"");var b=parseBigInt(a,16);if(b.bitLength()>this.n.bitLength()){return 0}var h=this.doPublic(b);var g=h.toString(16).replace(/^1f+00/,"");var c=_rsasign_getAlgNameAndHashFromHexDisgestInfo(g);if(c.length==0){return false}var d=c[0];var f=c[1];return(f==e)}function _rsasign_verifyStringPSS(c,b,a,f){var e=function(g){return KJUR.crypto.Util.hashHex(g,a)};var d=e(rstrtohex(c));if(f===undefined){f=-1}return this.verifyWithMessageHashPSS(d,b,a,f)}function _rsasign_verifyWithMessageHashPSS(f,s,l,c){var k=new BigInteger(s,16);if(k.bitLength()>this.n.bitLength()){return false}var r=function(i){return KJUR.crypto.Util.hashHex(i,l)};var j=hextorstr(f);var h=j.length;var g=this.n.bitLength()-1;var m=Math.ceil(g/8);var q;if(c===-1||c===undefined){c=h}else{if(c===-2){c=m-h-2}else{if(c<-2){throw"invalid salt length"}}}if(m<(h+c+2)){throw"data too long"}var a=this.doPublic(k).toByteArray();for(q=0;q<a.length;q+=1){a[q]&=255}while(a.length<m){a.unshift(0)}if(a[m-1]!==188){throw"encoded message does not end in 0xbc"}a=String.fromCharCode.apply(String,a);var d=a.substr(0,m-h-1);var e=a.substr(d.length,h);var p=(65280>>(8*m-g))&255;if((d.charCodeAt(0)&p)!==0){throw"bits beyond keysize not zero"}var n=pss_mgf1_str(e,d.length,r);var o=[];for(q=0;q<d.length;q+=1){o[q]=d.charCodeAt(q)^n.charCodeAt(q)}o[0]&=~p;var b=m-h-c-2;for(q=0;q<b;q+=1){if(o[q]!==0){throw"leftmost octets not zero"}}if(o[b]!==1){throw"0x01 marker not found"}return e===hextorstr(r(rstrtohex("\x00\x00\x00\x00\x00\x00\x00\x00"+j+String.fromCharCode.apply(String,o.slice(-c)))))}RSAKey.prototype.signWithMessageHash=_rsasign_signWithMessageHash;RSAKey.prototype.signString=_rsasign_signString;RSAKey.prototype.signStringWithSHA1=_rsasign_signStringWithSHA1;RSAKey.prototype.signStringWithSHA256=_rsasign_signStringWithSHA256;RSAKey.prototype.sign=_rsasign_signString;RSAKey.prototype.signWithSHA1=_rsasign_signStringWithSHA1;RSAKey.prototype.signWithSHA256=_rsasign_signStringWithSHA256;RSAKey.prototype.signWithMessageHashPSS=_rsasign_signWithMessageHashPSS;RSAKey.prototype.signStringPSS=_rsasign_signStringPSS;RSAKey.prototype.signPSS=_rsasign_signStringPSS;RSAKey.SALT_LEN_HLEN=-1;RSAKey.SALT_LEN_MAX=-2;RSAKey.prototype.verifyWithMessageHash=_rsasign_verifyWithMessageHash;RSAKey.prototype.verifyString=_rsasign_verifyString;RSAKey.prototype.verifyHexSignatureForMessage=_rsasign_verifyHexSignatureForMessage;RSAKey.prototype.verify=_rsasign_verifyString;RSAKey.prototype.verifyHexSignatureForByteArrayMessage=_rsasign_verifyHexSignatureForMessage;RSAKey.prototype.verifyWithMessageHashPSS=_rsasign_verifyWithMessageHashPSS;RSAKey.prototype.verifyStringPSS=_rsasign_verifyStringPSS;RSAKey.prototype.verifyPSS=_rsasign_verifyStringPSS;RSAKey.SALT_LEN_RECOVER=-2;
/* asn1hex-1.1.min.js  */
/*! asn1hex-1.1.8.js (c) 2012-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
var ASN1HEX=new function(){};ASN1HEX.getByteLengthOfL_AtObj=function(a,b){if("8"!=a.substring(b+2,b+3))return 1;var c=parseInt(a.substring(b+3,b+4));return 0==c?-1:0<c&&c<10?c+1:-2},ASN1HEX.getHexOfL_AtObj=function(a,b){var c=ASN1HEX.getByteLengthOfL_AtObj(a,b);return c<1?"":a.substring(b+2,b+2+2*c)},ASN1HEX.getIntOfL_AtObj=function(a,b){var c=ASN1HEX.getHexOfL_AtObj(a,b);if(""==c)return-1;var d;return d=parseInt(c.substring(0,1))<8?new BigInteger(c,16):new BigInteger(c.substring(2),16),d.intValue()},ASN1HEX.getStartPosOfV_AtObj=function(a,b){var c=ASN1HEX.getByteLengthOfL_AtObj(a,b);return c<0?c:b+2*(c+1)},ASN1HEX.getHexOfV_AtObj=function(a,b){var c=ASN1HEX.getStartPosOfV_AtObj(a,b),d=ASN1HEX.getIntOfL_AtObj(a,b);return a.substring(c,c+2*d)},ASN1HEX.getHexOfTLV_AtObj=function(a,b){var c=a.substr(b,2),d=ASN1HEX.getHexOfL_AtObj(a,b),e=ASN1HEX.getHexOfV_AtObj(a,b);return c+d+e},ASN1HEX.getPosOfNextSibling_AtObj=function(a,b){var c=ASN1HEX.getStartPosOfV_AtObj(a,b),d=ASN1HEX.getIntOfL_AtObj(a,b);return c+2*d},ASN1HEX.getPosArrayOfChildren_AtObj=function(a,b){var c=new Array,d=ASN1HEX.getStartPosOfV_AtObj(a,b);"03"==a.substr(b,2)?c.push(d+2):c.push(d);for(var e=ASN1HEX.getIntOfL_AtObj(a,b),f=d,g=0;;){var h=ASN1HEX.getPosOfNextSibling_AtObj(a,f);if(null==h||h-d>=2*e)break;if(g>=200)break;c.push(h),f=h,g++}return c},ASN1HEX.getNthChildIndex_AtObj=function(a,b,c){var d=ASN1HEX.getPosArrayOfChildren_AtObj(a,b);return d[c]},ASN1HEX.getDecendantIndexByNthList=function(a,b,c){if(0==c.length)return b;var d=c.shift(),e=ASN1HEX.getPosArrayOfChildren_AtObj(a,b);return ASN1HEX.getDecendantIndexByNthList(a,e[d],c)},ASN1HEX.getDecendantHexTLVByNthList=function(a,b,c){var d=ASN1HEX.getDecendantIndexByNthList(a,b,c);return ASN1HEX.getHexOfTLV_AtObj(a,d)},ASN1HEX.getDecendantHexVByNthList=function(a,b,c){var d=ASN1HEX.getDecendantIndexByNthList(a,b,c);return ASN1HEX.getHexOfV_AtObj(a,d)},ASN1HEX.getVbyList=function(a,b,c,d){var e=ASN1HEX.getDecendantIndexByNthList(a,b,c);if(void 0===e)throw"can't find nthList object";if(void 0!==d&&a.substr(e,2)!=d)throw"checking tag doesn't match: "+a.substr(e,2)+"!="+d;return ASN1HEX.getHexOfV_AtObj(a,e)},ASN1HEX.hextooidstr=function(a){var b=function(a,b){return a.length>=b?a:new Array(b-a.length+1).join("0")+a},c=[],d=a.substr(0,2),e=parseInt(d,16);c[0]=new String(Math.floor(e/40)),c[1]=new String(e%40);for(var f=a.substr(2),g=[],h=0;h<f.length/2;h++)g.push(parseInt(f.substr(2*h,2),16));for(var i=[],j="",h=0;h<g.length;h++)128&g[h]?j+=b((127&g[h]).toString(2),7):(j+=b((127&g[h]).toString(2),7),i.push(new String(parseInt(j,2))),j="");var k=c.join(".");return i.length>0&&(k=k+"."+i.join(".")),k},ASN1HEX.dump=function(a,b,c,d){var e=a;a instanceof KJUR.asn1.ASN1Object&&(e=a.getEncodedHex());var f=function(a,b){if(a.length<=2*b)return a;var c=a.substr(0,b)+"..(total "+a.length/2+"bytes).."+a.substr(a.length-b,b);return c};void 0===b&&(b={ommit_long_octet:32}),void 0===c&&(c=0),void 0===d&&(d="");var g=b.ommit_long_octet;if("01"==e.substr(c,2)){var h=ASN1HEX.getHexOfV_AtObj(e,c);return"00"==h?d+"BOOLEAN FALSE\n":d+"BOOLEAN TRUE\n"}if("02"==e.substr(c,2)){var h=ASN1HEX.getHexOfV_AtObj(e,c);return d+"INTEGER "+f(h,g)+"\n"}if("03"==e.substr(c,2)){var h=ASN1HEX.getHexOfV_AtObj(e,c);return d+"BITSTRING "+f(h,g)+"\n"}if("04"==e.substr(c,2)){var h=ASN1HEX.getHexOfV_AtObj(e,c);if(ASN1HEX.isASN1HEX(h)){var i=d+"OCTETSTRING, encapsulates\n";return i+=ASN1HEX.dump(h,b,0,d+"  ")}return d+"OCTETSTRING "+f(h,g)+"\n"}if("05"==e.substr(c,2))return d+"NULL\n";if("06"==e.substr(c,2)){var j=ASN1HEX.getHexOfV_AtObj(e,c),k=KJUR.asn1.ASN1Util.oidHexToInt(j),l=KJUR.asn1.x509.OID.oid2name(k),m=k.replace(/\./g," ");return""!=l?d+"ObjectIdentifier "+l+" ("+m+")\n":d+"ObjectIdentifier ("+m+")\n"}if("0c"==e.substr(c,2))return d+"UTF8String '"+hextoutf8(ASN1HEX.getHexOfV_AtObj(e,c))+"'\n";if("13"==e.substr(c,2))return d+"PrintableString '"+hextoutf8(ASN1HEX.getHexOfV_AtObj(e,c))+"'\n";if("14"==e.substr(c,2))return d+"TeletexString '"+hextoutf8(ASN1HEX.getHexOfV_AtObj(e,c))+"'\n";if("16"==e.substr(c,2))return d+"IA5String '"+hextoutf8(ASN1HEX.getHexOfV_AtObj(e,c))+"'\n";if("17"==e.substr(c,2))return d+"UTCTime "+hextoutf8(ASN1HEX.getHexOfV_AtObj(e,c))+"\n";if("18"==e.substr(c,2))return d+"GeneralizedTime "+hextoutf8(ASN1HEX.getHexOfV_AtObj(e,c))+"\n";if("30"==e.substr(c,2)){if("3000"==e.substr(c,4))return d+"SEQUENCE {}\n";var i=d+"SEQUENCE\n",n=ASN1HEX.getPosArrayOfChildren_AtObj(e,c),o=b;if((2==n.length||3==n.length)&&"06"==e.substr(n[0],2)&&"04"==e.substr(n[n.length-1],2)){var p=ASN1HEX.getHexOfV_AtObj(e,n[0]),k=KJUR.asn1.ASN1Util.oidHexToInt(p),l=KJUR.asn1.x509.OID.oid2name(k),q=JSON.parse(JSON.stringify(b));q.x509ExtName=l,o=q}for(var r=0;r<n.length;r++)i+=ASN1HEX.dump(e,o,n[r],d+"  ");return i}if("31"==e.substr(c,2)){for(var i=d+"SET\n",n=ASN1HEX.getPosArrayOfChildren_AtObj(e,c),r=0;r<n.length;r++)i+=ASN1HEX.dump(e,b,n[r],d+"  ");return i}var s=parseInt(e.substr(c,2),16);if(0!=(128&s)){var t=31&s;if(0!=(32&s)){for(var i=d+"["+t+"]\n",n=ASN1HEX.getPosArrayOfChildren_AtObj(e,c),r=0;r<n.length;r++)i+=ASN1HEX.dump(e,b,n[r],d+"  ");return i}var h=ASN1HEX.getHexOfV_AtObj(e,c);"68747470"==h.substr(0,8)&&(h=hextoutf8(h)),"subjectAltName"===b.x509ExtName&&2==t&&(h=hextoutf8(h));var i=d+"["+t+"] "+h+"\n";return i}return d+"UNKNOWN("+e.substr(c,2)+") "+ASN1HEX.getHexOfV_AtObj(e,c)+"\n"},ASN1HEX.isASN1HEX=function(a){if(a.length%2==1)return!1;var b=ASN1HEX.getIntOfL_AtObj(a,0),c=a.substr(0,2),d=ASN1HEX.getHexOfL_AtObj(a,0),e=a.length-c.length-d.length;return e==2*b};
/* x509-1.1.min.js  */
/*! x509-1.1.10.js (c) 2012-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
function X509() { this.subjectPublicKeyRSA = null; this.subjectPublicKeyRSA_hN = null; this.subjectPublicKeyRSA_hE = null; this.hex = null; this.getSerialNumberHex = function() { return ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 1]); }; this.getSignatureAlgorithmField = function() { var sigAlgOidHex = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 2, 0]); var sigAlgOidInt = KJUR.asn1.ASN1Util.oidHexToInt(sigAlgOidHex); var sigAlgName = KJUR.asn1.x509.OID.oid2name(sigAlgOidInt); return sigAlgName; }; this.getIssuerHex = function() { return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]); }; this.getIssuerString = function() { return X509.hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3])); }; this.getSubjectHex = function() { return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]); }; this.getSubjectString = function() { return X509.hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5])); }; this.getNotBefore = function() { var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 0]); s = s.replace(/(..)/g, "%$1"); s = decodeURIComponent(s); return s; }; this.getNotAfter = function() { var s = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 1]); s = s.replace(/(..)/g, "%$1"); s = decodeURIComponent(s); return s; }; this.readCertPEM = function(sCertPEM) { var hCert = X509.pemToHex(sCertPEM); var a = X509.getPublicKeyHexArrayFromCertHex(hCert); var rsa = new RSAKey(); rsa.setPublic(a[0], a[1]); this.subjectPublicKeyRSA = rsa; this.subjectPublicKeyRSA_hN = a[0]; this.subjectPublicKeyRSA_hE = a[1]; this.hex = hCert; }; this.readCertPEMWithoutRSAInit = function(sCertPEM) { var hCert = X509.pemToHex(sCertPEM); var a = X509.getPublicKeyHexArrayFromCertHex(hCert); if (typeof this.subjectPublicKeyRSA.setPublic === "function") { this.subjectPublicKeyRSA.setPublic(a[0], a[1]); } this.subjectPublicKeyRSA_hN = a[0]; this.subjectPublicKeyRSA_hE = a[1]; this.hex = hCert; }; this.getInfo = function() { var s = "Basic Fields\n"; s += " serial number: " + this.getSerialNumberHex() + "\n"; s += " signature algorithm: " + this.getSignatureAlgorithmField() + "\n"; s += " issuer: " + this.getIssuerString() + "\n"; s += " notBefore: " + this.getNotBefore() + "\n"; s += " notAfter: " + this.getNotAfter() + "\n"; s += " subject: " + this.getSubjectString() + "\n"; s += " subject public key info: " + "\n"; var pSPKI = X509.getSubjectPublicKeyInfoPosFromCertHex(this.hex); var hSPKI = ASN1HEX.getHexOfTLV_AtObj(this.hex, pSPKI); var keyObj = KEYUTIL.getKey(hSPKI, null, "pkcs8pub"); if (keyObj instanceof RSAKey) { s += " key algorithm: RSA\n"; s += " n=" + keyObj.n.toString(16).substr(0, 16) + "...\n"; s += " e=" + keyObj.e.toString(16) + "\n"; } s += "X509v3 Extensions:\n"; var aExt = X509.getV3ExtInfoListOfCertHex(this.hex); for (var i = 0; i < aExt.length; i++) { var info = aExt[i]; var extName = KJUR.asn1.x509.OID.oid2name(info["oid"]); if (extName === '') extName = info["oid"]; var critical = ''; if (info["critical"] === true) critical = "CRITICAL"; s += " " + extName + " " + critical + ":\n"; if (extName === "basicConstraints") { var bc = X509.getExtBasicConstraints(this.hex); if (bc.cA === undefined) { s += " {}\n"; } else { s += " cA=true"; if (bc.pathLen !== undefined) s += ", pathLen=" + bc.pathLen; s += "\n"; } } else if (extName === "keyUsage") { s += " " + X509.getExtKeyUsageString(this.hex) + "\n"; } else if (extName === "subjectKeyIdentifier") { s += " " + X509.getExtSubjectKeyIdentifier(this.hex) + "\n"; } else if (extName === "authorityKeyIdentifier") { var akid = X509.getExtAuthorityKeyIdentifier(this.hex); if (akid.kid !== undefined) s += " kid=" + akid.kid + "\n"; } else if (extName === "extKeyUsage") { var eku = X509.getExtExtKeyUsageName(this.hex); s += " " + eku.join(", ") + "\n"; } else if (extName === "subjectAltName") { var san = X509.getExtSubjectAltName(this.hex); s += " " + san.join(", ") + "\n"; } else if (extName === "cRLDistributionPoints") { var cdp = X509.getExtCRLDistributionPointsURI(this.hex); s += " " + cdp + "\n"; } else if (extName === "authorityInfoAccess") { var aia = X509.getExtAIAInfo(this.hex); if (aia.ocsp !== undefined) s += " ocsp: " + aia.ocsp.join(",") + "\n"; if (aia.caissuer !== undefined) s += " caissuer: " + aia.caissuer.join(",") + "\n"; } } s += "signature algorithm: " + X509.getSignatureAlgorithmName(this.hex) + "\n"; s += "signature: " + X509.getSignatureValueHex(this.hex).substr(0, 16) + "...\n"; return s; }; }; X509.pemToBase64 = function(sCertPEM) { var s = sCertPEM; s = s.replace("-----BEGIN CERTIFICATE-----", ""); s = s.replace("-----END CERTIFICATE-----", ""); s = s.replace(/[ \n]+/g, ""); return s; }; X509.pemToHex = function(sCertPEM) { var b64Cert = X509.pemToBase64(sCertPEM); var hCert = b64tohex(b64Cert); return hCert; }; X509.getSubjectPublicKeyPosFromCertHex = function(hCert) { var pInfo = X509.getSubjectPublicKeyInfoPosFromCertHex(hCert); if (pInfo == -1) return -1; var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pInfo); if (a.length != 2) return -1; var pBitString = a[1]; if (hCert.substring(pBitString, pBitString + 2) != '03') return -1; var pBitStringV = ASN1HEX.getStartPosOfV_AtObj(hCert, pBitString); if (hCert.substring(pBitStringV, pBitStringV + 2) != '00') return -1; return pBitStringV + 2; }; X509.getSubjectPublicKeyInfoPosFromCertHex = function(hCert) { var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0); var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pTbsCert); if (a.length < 1) return -1; if (hCert.substring(a[0], a[0] + 10) == "a003020102") { if (a.length < 6) return -1; return a[6]; } else { if (a.length < 5) return -1; return a[5]; } }; X509.getPublicKeyHexArrayFromCertHex = function(hCert) { var p = X509.getSubjectPublicKeyPosFromCertHex(hCert); var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, p); if (a.length != 2) return []; var hN = ASN1HEX.getHexOfV_AtObj(hCert, a[0]); var hE = ASN1HEX.getHexOfV_AtObj(hCert, a[1]); if (hN != null && hE != null) { return [hN, hE]; } else { return []; } }; X509.getHexTbsCertificateFromCert = function(hCert) { var pTbsCert = ASN1HEX.getStartPosOfV_AtObj(hCert, 0); return pTbsCert; }; X509.getPublicKeyHexArrayFromCertPEM = function(sCertPEM) { var hCert = X509.pemToHex(sCertPEM); var a = X509.getPublicKeyHexArrayFromCertHex(hCert); return a; }; X509.hex2dn = function(hex, idx) { if (idx === undefined) idx = 0; if (hex.substr(idx, 2) !== "30") throw "malformed DN"; var a = new Array(); var aIdx = ASN1HEX.getPosArrayOfChildren_AtObj(hex, idx); for (var i = 0; i < aIdx.length; i++) { a.push(X509.hex2rdn(hex, aIdx[i])); } a = a.map(function(s) { return s.replace("/", "\\/"); }); return "/" + a.join("/"); }; X509.hex2rdn = function(hex, idx) { if (idx === undefined) idx = 0; if (hex.substr(idx, 2) !== "31") throw "malformed RDN"; var a = new Array(); var aIdx = ASN1HEX.getPosArrayOfChildren_AtObj(hex, idx); for (var i = 0; i < aIdx.length; i++) { a.push(X509.hex2attrTypeValue(hex, aIdx[i])); } a = a.map(function(s) { return s.replace("+", "\\+"); }); return a.join("+"); }; X509.hex2attrTypeValue = function(hex, idx) { if (idx === undefined) idx = 0; if (hex.substr(idx, 2) !== "30") throw "malformed attribute type and value"; var aIdx = ASN1HEX.getPosArrayOfChildren_AtObj(hex, idx); if (aIdx.length !== 2 || hex.substr(aIdx[0], 2) !== "06") "malformed attribute type and value"; var oidHex = ASN1HEX.getHexOfV_AtObj(hex, aIdx[0]); var oidInt = KJUR.asn1.ASN1Util.oidHexToInt(oidHex); var atype = KJUR.asn1.x509.OID.oid2atype(oidInt); var hV = ASN1HEX.getHexOfV_AtObj(hex, aIdx[1]); var rawV = hextorstr(hV); return atype + "=" + rawV; }; X509.getPublicKeyFromCertPEM = function(sCertPEM) { var info = X509.getPublicKeyInfoPropOfCertPEM(sCertPEM); if (info.algoid == "2a864886f70d010101") { var aRSA = KEYUTIL.parsePublicRawRSAKeyHex(info.keyhex); var key = new RSAKey(); key.setPublic(aRSA.n, aRSA.e); return key; } else if (info.algoid == "2a8648ce3d0201") { var curveName = KJUR.crypto.OID.oidhex2name[info.algparam]; var key = new KJUR.crypto.ECDSA({'curve': curveName, 'info': info.keyhex}); key.setPublicKeyHex(info.keyhex); return key; } else if (info.algoid == "2a8648ce380401") { var p = ASN1HEX.getVbyList(info.algparam, 0, [0], "02"); var q = ASN1HEX.getVbyList(info.algparam, 0, [1], "02"); var g = ASN1HEX.getVbyList(info.algparam, 0, [2], "02"); var y = ASN1HEX.getHexOfV_AtObj(info.keyhex, 0); y = y.substr(2); var key = new KJUR.crypto.DSA(); key.setPublic(new BigInteger(p, 16), new BigInteger(q, 16), new BigInteger(g, 16), new BigInteger(y, 16)); return key; } else { throw "unsupported key"; } }; X509.getPublicKeyInfoPropOfCertPEM = function(sCertPEM) { var result = {}; result.algparam = null; var hCert = X509.pemToHex(sCertPEM); var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, 0); if (a1.length != 3) throw "malformed X.509 certificate PEM (code:001)"; if (hCert.substr(a1[0], 2) != "30") throw "malformed X.509 certificate PEM (code:002)"; var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a1[0]); var idx_spi = 6; if (hCert.substr(a2[0], 2) !== "a0") idx_spi = 5; if (a2.length < idx_spi + 1) throw "malformed X.509 certificate PEM (code:003)"; var a3 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a2[idx_spi]); if (a3.length != 2) throw "malformed X.509 certificate PEM (code:004)"; var a4 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a3[0]); if (a4.length != 2) throw "malformed X.509 certificate PEM (code:005)"; result.algoid = ASN1HEX.getHexOfV_AtObj(hCert, a4[0]); if (hCert.substr(a4[1], 2) == "06") { result.algparam = ASN1HEX.getHexOfV_AtObj(hCert, a4[1]); } else if (hCert.substr(a4[1], 2) == "30") { result.algparam = ASN1HEX.getHexOfTLV_AtObj(hCert, a4[1]); } if (hCert.substr(a3[1], 2) != "03") throw "malformed X.509 certificate PEM (code:006)"; var unusedBitAndKeyHex = ASN1HEX.getHexOfV_AtObj(hCert, a3[1]); result.keyhex = unusedBitAndKeyHex.substr(2); return result; }; X509.getPublicKeyInfoPosOfCertHEX = function(hCert) { var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, 0); if (a1.length != 3) throw "malformed X.509 certificate PEM (code:001)"; if (hCert.substr(a1[0], 2) != "30") throw "malformed X.509 certificate PEM (code:002)"; var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a1[0]); if (a2.length < 7) throw "malformed X.509 certificate PEM (code:003)"; return a2[6]; }; X509.getV3ExtInfoListOfCertHex = function(hCert) { var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, 0); if (a1.length != 3) throw "malformed X.509 certificate PEM (code:001)"; if (hCert.substr(a1[0], 2) != "30") throw "malformed X.509 certificate PEM (code:002)"; var a2 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a1[0]); if (a2.length < 8) throw "malformed X.509 certificate PEM (code:003)"; if (hCert.substr(a2[7], 2) != "a3") throw "malformed X.509 certificate PEM (code:004)"; var a3 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a2[7]); if (a3.length != 1) throw "malformed X.509 certificate PEM (code:005)"; if (hCert.substr(a3[0], 2) != "30") throw "malformed X.509 certificate PEM (code:006)"; var a4 = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, a3[0]); var numExt = a4.length; var aInfo = new Array(numExt); for (var i = 0; i < numExt; i++) { aInfo[i] = X509.getV3ExtItemInfo_AtObj(hCert, a4[i]); } return aInfo; }; X509.getV3ExtItemInfo_AtObj = function(hCert, pos) { var info = {}; info.posTLV = pos; var a = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pos); if (a.length != 2 && a.length != 3) throw "malformed X.509v3 Ext (code:001)"; if (hCert.substr(a[0], 2) != "06") throw "malformed X.509v3 Ext (code:002)"; var valueHex = ASN1HEX.getHexOfV_AtObj(hCert, a[0]); info.oid = ASN1HEX.hextooidstr(valueHex); info.critical = false; if (a.length == 3) info.critical = true; var posExtV = a[a.length - 1]; if (hCert.substr(posExtV, 2) != "04") throw "malformed X.509v3 Ext (code:003)"; info.posV = ASN1HEX.getStartPosOfV_AtObj(hCert, posExtV); return info; }; X509.getHexOfTLV_V3ExtValue = function(hCert, oidOrName) { var pos = X509.getPosOfTLV_V3ExtValue(hCert, oidOrName); if (pos == -1) return null; return ASN1HEX.getHexOfTLV_AtObj(hCert, pos); }; X509.getHexOfV_V3ExtValue = function(hCert, oidOrName) { var pos = X509.getPosOfTLV_V3ExtValue(hCert, oidOrName); if (pos == -1) return null; return ASN1HEX.getHexOfV_AtObj(hCert, pos); }; X509.getPosOfTLV_V3ExtValue = function(hCert, oidOrName) { var oid = oidOrName; if (! oidOrName.match(/^[0-9.]+$/)) oid = KJUR.asn1.x509.OID.name2oid(oidOrName); if (oid == '') return -1; var infoList = X509.getV3ExtInfoListOfCertHex(hCert); for (var i = 0; i < infoList.length; i++) { var info = infoList[i]; if (info.oid == oid) return info.posV; } return -1; }; X509.getExtBasicConstraints = function(hCert) { var hBC = X509.getHexOfV_V3ExtValue(hCert, "basicConstraints"); if (hBC === null) return null; if (hBC === '') return {}; if (hBC === '0101ff') return { "cA": true }; if (hBC.substr(0, 8) === '0101ff02') { var pathLexHex = ASN1HEX.getHexOfV_AtObj(hBC, 6); var pathLen = parseInt(pathLexHex, 16); return { "cA": true, "pathLen": pathLen }; } throw "unknown error"; }; X509.KEYUSAGE_NAME = [ "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly" ]; X509.getExtKeyUsageBin = function(hCert) { var hKeyUsage = X509.getHexOfV_V3ExtValue(hCert, "keyUsage"); if (hKeyUsage == '') return ''; if (hKeyUsage.length % 2 != 0 || hKeyUsage.length <= 2) throw "malformed key usage value"; var unusedBits = parseInt(hKeyUsage.substr(0, 2)); var bKeyUsage = parseInt(hKeyUsage.substr(2), 16).toString(2); return bKeyUsage.substr(0, bKeyUsage.length - unusedBits); }; X509.getExtKeyUsageString = function(hCert) { var bKeyUsage = X509.getExtKeyUsageBin(hCert); var a = new Array(); for (var i = 0; i < bKeyUsage.length; i++) { if (bKeyUsage.substr(i, 1) == "1") a.push(X509.KEYUSAGE_NAME[i]); } return a.join(","); }; X509.getExtSubjectKeyIdentifier = function(hCert) { var hSKID = X509.getHexOfV_V3ExtValue(hCert, "subjectKeyIdentifier"); return hSKID; }; X509.getExtAuthorityKeyIdentifier = function(hCert) { var result = {}; var hAKID = X509.getHexOfTLV_V3ExtValue(hCert, "authorityKeyIdentifier"); if (hAKID === null) return null; var a = ASN1HEX.getPosArrayOfChildren_AtObj(hAKID, 0); for (var i = 0; i < a.length; i++) { if (hAKID.substr(a[i], 2) === "80") result.kid = ASN1HEX.getHexOfV_AtObj(hAKID, a[i]); } return result; }; X509.getExtExtKeyUsageName = function(hCert) { var result = new Array(); var h = X509.getHexOfTLV_V3ExtValue(hCert, "extKeyUsage"); if (h === null) return null; var a = ASN1HEX.getPosArrayOfChildren_AtObj(h, 0); for (var i = 0; i < a.length; i++) { var hex = ASN1HEX.getHexOfV_AtObj(h, a[i]); var oid = KJUR.asn1.ASN1Util.oidHexToInt(hex); var name = KJUR.asn1.x509.OID.oid2name(oid); result.push(name); } return result; }; X509.getExtSubjectAltName = function(hCert) { var result = new Array(); var h = X509.getHexOfTLV_V3ExtValue(hCert, "subjectAltName"); var a = ASN1HEX.getPosArrayOfChildren_AtObj(h, 0); for (var i = 0; i < a.length; i++) { if (h.substr(a[i], 2) === "82") { var fqdn = hextoutf8(ASN1HEX.getHexOfV_AtObj(h, a[i])); result.push(fqdn); } } return result; }; X509.getExtCRLDistributionPointsURI = function(hCert) { var result = new Array(); var h = X509.getHexOfTLV_V3ExtValue(hCert, "cRLDistributionPoints"); var a = ASN1HEX.getPosArrayOfChildren_AtObj(h, 0); for (var i = 0; i < a.length; i++) { var hDP = ASN1HEX.getHexOfTLV_AtObj(h, a[i]); var a1 = ASN1HEX.getPosArrayOfChildren_AtObj(hDP, 0); for (var j = 0; j < a1.length; j++) { if (hDP.substr(a1[j], 2) === "a0") { var hDPN = ASN1HEX.getHexOfV_AtObj(hDP, a1[j]); if (hDPN.substr(0, 2) === "a0") { var hFullName = ASN1HEX.getHexOfV_AtObj(hDPN, 0); if (hFullName.substr(0, 2) === "86") { var hURI = ASN1HEX.getHexOfV_AtObj(hFullName, 0); var uri = hextoutf8(hURI); result.push(uri); } } } } } return result; }; X509.getExtAIAInfo = function(hCert) { var result = {}; result.ocsp = []; result.caissuer = []; var pos1 = X509.getPosOfTLV_V3ExtValue(hCert, "authorityInfoAccess"); if (pos1 == -1) return null; if (hCert.substr(pos1, 2) != "30") throw "malformed AIA Extn Value"; var posAccDescList = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, pos1); for (var i = 0; i < posAccDescList.length; i++) { var p = posAccDescList[i]; var posAccDescChild = ASN1HEX.getPosArrayOfChildren_AtObj(hCert, p); if (posAccDescChild.length != 2) throw "malformed AccessDescription of AIA Extn"; var pOID = posAccDescChild[0]; var pName = posAccDescChild[1]; if (ASN1HEX.getHexOfV_AtObj(hCert, pOID) == "2b06010505073001") { if (hCert.substr(pName, 2) == "86") { result.ocsp.push(hextoutf8(ASN1HEX.getHexOfV_AtObj(hCert, pName))); } } if (ASN1HEX.getHexOfV_AtObj(hCert, pOID) == "2b06010505073002") { if (hCert.substr(pName, 2) == "86") { result.caissuer.push(hextoutf8(ASN1HEX.getHexOfV_AtObj(hCert, pName))); } } } return result; }; X509.getSignatureAlgorithmName = function(hCert) { var sigAlgOidHex = ASN1HEX.getDecendantHexVByNthList(hCert, 0, [1, 0]); var sigAlgOidInt = KJUR.asn1.ASN1Util.oidHexToInt(sigAlgOidHex); var sigAlgName = KJUR.asn1.x509.OID.oid2name(sigAlgOidInt); return sigAlgName; }; X509.getSignatureValueHex = function(hCert) { var h = ASN1HEX.getDecendantHexVByNthList(hCert, 0, [2]); if (h.substr(0, 2) !== "00") throw "can't get signature value"; return h.substr(2); }; X509.getSerialNumberHex = function(hCert) { return ASN1HEX.getDecendantHexVByNthList(hCert, 0, [0, 1]); };
/* crypto-1.1.min.js  */
/*! crypto-1.1.11.js (c) 2013-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
"undefined"!=typeof KJUR&&KJUR||(KJUR={}),"undefined"!=typeof KJUR.crypto&&KJUR.crypto||(KJUR.crypto={}),KJUR.crypto.Util=new function(){this.DIGESTINFOHEAD={sha1:"3021300906052b0e03021a05000414",sha224:"302d300d06096086480165030402040500041c",sha256:"3031300d060960864801650304020105000420",sha384:"3041300d060960864801650304020205000430",sha512:"3051300d060960864801650304020305000440",md2:"3020300c06082a864886f70d020205000410",md5:"3020300c06082a864886f70d020505000410",ripemd160:"3021300906052b2403020105000414"},this.DEFAULTPROVIDER={md5:"cryptojs",sha1:"cryptojs",sha224:"cryptojs",sha256:"cryptojs",sha384:"cryptojs",sha512:"cryptojs",ripemd160:"cryptojs",hmacmd5:"cryptojs",hmacsha1:"cryptojs",hmacsha224:"cryptojs",hmacsha256:"cryptojs",hmacsha384:"cryptojs",hmacsha512:"cryptojs",hmacripemd160:"cryptojs",MD5withRSA:"cryptojs/jsrsa",SHA1withRSA:"cryptojs/jsrsa",SHA224withRSA:"cryptojs/jsrsa",SHA256withRSA:"cryptojs/jsrsa",SHA384withRSA:"cryptojs/jsrsa",SHA512withRSA:"cryptojs/jsrsa",RIPEMD160withRSA:"cryptojs/jsrsa",MD5withECDSA:"cryptojs/jsrsa",SHA1withECDSA:"cryptojs/jsrsa",SHA224withECDSA:"cryptojs/jsrsa",SHA256withECDSA:"cryptojs/jsrsa",SHA384withECDSA:"cryptojs/jsrsa",SHA512withECDSA:"cryptojs/jsrsa",RIPEMD160withECDSA:"cryptojs/jsrsa",SHA1withDSA:"cryptojs/jsrsa",SHA224withDSA:"cryptojs/jsrsa",SHA256withDSA:"cryptojs/jsrsa",MD5withRSAandMGF1:"cryptojs/jsrsa",SHA1withRSAandMGF1:"cryptojs/jsrsa",SHA224withRSAandMGF1:"cryptojs/jsrsa",SHA256withRSAandMGF1:"cryptojs/jsrsa",SHA384withRSAandMGF1:"cryptojs/jsrsa",SHA512withRSAandMGF1:"cryptojs/jsrsa",RIPEMD160withRSAandMGF1:"cryptojs/jsrsa"},this.CRYPTOJSMESSAGEDIGESTNAME={md5:CryptoJS.algo.MD5,sha1:CryptoJS.algo.SHA1,sha224:CryptoJS.algo.SHA224,sha256:CryptoJS.algo.SHA256,sha384:CryptoJS.algo.SHA384,sha512:CryptoJS.algo.SHA512,ripemd160:CryptoJS.algo.RIPEMD160},this.getDigestInfoHex=function(a,b){if("undefined"==typeof this.DIGESTINFOHEAD[b])throw"alg not supported in Util.DIGESTINFOHEAD: "+b;return this.DIGESTINFOHEAD[b]+a},this.getPaddedDigestInfoHex=function(a,b,c){var d=this.getDigestInfoHex(a,b),e=c/4;if(d.length+22>e)throw"key is too short for SigAlg: keylen="+c+","+b;for(var f="0001",g="00"+d,h="",i=e-f.length-g.length,j=0;j<i;j+=2)h+="ff";var k=f+h+g;return k},this.hashString=function(a,b){var c=new KJUR.crypto.MessageDigest({alg:b});return c.digestString(a)},this.hashHex=function(a,b){var c=new KJUR.crypto.MessageDigest({alg:b});return c.digestHex(a)},this.sha1=function(a){var b=new KJUR.crypto.MessageDigest({alg:"sha1",prov:"cryptojs"});return b.digestString(a)},this.sha256=function(a){var b=new KJUR.crypto.MessageDigest({alg:"sha256",prov:"cryptojs"});return b.digestString(a)},this.sha256Hex=function(a){var b=new KJUR.crypto.MessageDigest({alg:"sha256",prov:"cryptojs"});return b.digestHex(a)},this.sha512=function(a){var b=new KJUR.crypto.MessageDigest({alg:"sha512",prov:"cryptojs"});return b.digestString(a)},this.sha512Hex=function(a){var b=new KJUR.crypto.MessageDigest({alg:"sha512",prov:"cryptojs"});return b.digestHex(a)}},KJUR.crypto.Util.md5=function(a){var b=new KJUR.crypto.MessageDigest({alg:"md5",prov:"cryptojs"});return b.digestString(a)},KJUR.crypto.Util.ripemd160=function(a){var b=new KJUR.crypto.MessageDigest({alg:"ripemd160",prov:"cryptojs"});return b.digestString(a)},KJUR.crypto.Util.SECURERANDOMGEN=new SecureRandom,KJUR.crypto.Util.getRandomHexOfNbytes=function(a){var b=new Array(a);return KJUR.crypto.Util.SECURERANDOMGEN.nextBytes(b),BAtohex(b)},KJUR.crypto.Util.getRandomBigIntegerOfNbytes=function(a){return new BigInteger(KJUR.crypto.Util.getRandomHexOfNbytes(a),16)},KJUR.crypto.Util.getRandomHexOfNbits=function(a){var b=a%8,c=(a-b)/8,d=new Array(c+1);return KJUR.crypto.Util.SECURERANDOMGEN.nextBytes(d),d[0]=(255<<b&255^255)&d[0],BAtohex(d)},KJUR.crypto.Util.getRandomBigIntegerOfNbits=function(a){return new BigInteger(KJUR.crypto.Util.getRandomHexOfNbits(a),16)},KJUR.crypto.Util.getRandomBigIntegerZeroToMax=function(a){for(var b=a.bitLength();;){var c=KJUR.crypto.Util.getRandomBigIntegerOfNbits(b);if(a.compareTo(c)!=-1)return c}},KJUR.crypto.Util.getRandomBigIntegerMinToMax=function(a,b){var c=a.compareTo(b);if(1==c)throw"biMin is greater than biMax";if(0==c)return a;var d=b.subtract(a),e=KJUR.crypto.Util.getRandomBigIntegerZeroToMax(d);return e.add(a)},KJUR.crypto.MessageDigest=function(a){this.setAlgAndProvider=function(a,b){if(a=KJUR.crypto.MessageDigest.getCanonicalAlgName(a),null!==a&&void 0===b&&(b=KJUR.crypto.Util.DEFAULTPROVIDER[a]),":md5:sha1:sha224:sha256:sha384:sha512:ripemd160:".indexOf(a)!=-1&&"cryptojs"==b){try{this.md=KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[a].create()}catch(b){throw"setAlgAndProvider hash alg set fail alg="+a+"/"+b}this.updateString=function(a){this.md.update(a)},this.updateHex=function(a){var b=CryptoJS.enc.Hex.parse(a);this.md.update(b)},this.digest=function(){var a=this.md.finalize();return a.toString(CryptoJS.enc.Hex)},this.digestString=function(a){return this.updateString(a),this.digest()},this.digestHex=function(a){return this.updateHex(a),this.digest()}}if(":sha256:".indexOf(a)!=-1&&"sjcl"==b){try{this.md=new sjcl.hash.sha256}catch(b){throw"setAlgAndProvider hash alg set fail alg="+a+"/"+b}this.updateString=function(a){this.md.update(a)},this.updateHex=function(a){var b=sjcl.codec.hex.toBits(a);this.md.update(b)},this.digest=function(){var a=this.md.finalize();return sjcl.codec.hex.fromBits(a)},this.digestString=function(a){return this.updateString(a),this.digest()},this.digestHex=function(a){return this.updateHex(a),this.digest()}}},this.updateString=function(a){throw"updateString(str) not supported for this alg/prov: "+this.algName+"/"+this.provName},this.updateHex=function(a){throw"updateHex(hex) not supported for this alg/prov: "+this.algName+"/"+this.provName},this.digest=function(){throw"digest() not supported for this alg/prov: "+this.algName+"/"+this.provName},this.digestString=function(a){throw"digestString(str) not supported for this alg/prov: "+this.algName+"/"+this.provName},this.digestHex=function(a){throw"digestHex(hex) not supported for this alg/prov: "+this.algName+"/"+this.provName},void 0!==a&&void 0!==a.alg&&(this.algName=a.alg,void 0===a.prov&&(this.provName=KJUR.crypto.Util.DEFAULTPROVIDER[this.algName]),this.setAlgAndProvider(this.algName,this.provName))},KJUR.crypto.MessageDigest.getCanonicalAlgName=function(a){return"string"==typeof a&&(a=a.toLowerCase(),a=a.replace(/-/,"")),a},KJUR.crypto.MessageDigest.getHashLength=function(a){var b=KJUR.crypto.MessageDigest,c=b.getCanonicalAlgName(a);if(void 0===b.HASHLENGTH[c])throw"not supported algorithm: "+a;return b.HASHLENGTH[c]},KJUR.crypto.MessageDigest.HASHLENGTH={md5:16,sha1:20,sha224:28,sha256:32,sha384:48,sha512:64,ripemd160:20},KJUR.crypto.Mac=function(a){this.setAlgAndProvider=function(a,b){if(a=a.toLowerCase(),null==a&&(a="hmacsha1"),a=a.toLowerCase(),"hmac"!=a.substr(0,4))throw"setAlgAndProvider unsupported HMAC alg: "+a;void 0===b&&(b=KJUR.crypto.Util.DEFAULTPROVIDER[a]),this.algProv=a+"/"+b;var c=a.substr(4);if(":md5:sha1:sha224:sha256:sha384:sha512:ripemd160:".indexOf(c)!=-1&&"cryptojs"==b){try{var d=KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[c];this.mac=CryptoJS.algo.HMAC.create(d,this.pass)}catch(a){throw"setAlgAndProvider hash alg set fail hashAlg="+c+"/"+a}this.updateString=function(a){this.mac.update(a)},this.updateHex=function(a){var b=CryptoJS.enc.Hex.parse(a);this.mac.update(b)},this.doFinal=function(){var a=this.mac.finalize();return a.toString(CryptoJS.enc.Hex)},this.doFinalString=function(a){return this.updateString(a),this.doFinal()},this.doFinalHex=function(a){return this.updateHex(a),this.doFinal()}}},this.updateString=function(a){throw"updateString(str) not supported for this alg/prov: "+this.algProv},this.updateHex=function(a){throw"updateHex(hex) not supported for this alg/prov: "+this.algProv},this.doFinal=function(){throw"digest() not supported for this alg/prov: "+this.algProv},this.doFinalString=function(a){throw"digestString(str) not supported for this alg/prov: "+this.algProv},this.doFinalHex=function(a){throw"digestHex(hex) not supported for this alg/prov: "+this.algProv},this.setPassword=function(a){if("string"==typeof a){var b=a;return a.length%2!=1&&a.match(/^[0-9A-Fa-f]+$/)||(b=rstrtohex(a)),void(this.pass=CryptoJS.enc.Hex.parse(b))}if("object"!=typeof a)throw"KJUR.crypto.Mac unsupported password type: "+a;var b=null;if(void 0!==a.hex){if(a.hex.length%2!=0||!a.hex.match(/^[0-9A-Fa-f]+$/))throw"Mac: wrong hex password: "+a.hex;b=a.hex}if(void 0!==a.utf8&&(b=utf8tohex(a.utf8)),void 0!==a.rstr&&(b=rstrtohex(a.rstr)),void 0!==a.b64&&(b=b64tohex(a.b64)),void 0!==a.b64u&&(b=b64utohex(a.b64u)),null==b)throw"KJUR.crypto.Mac unsupported password type: "+a;this.pass=CryptoJS.enc.Hex.parse(b)},void 0!==a&&(void 0!==a.pass&&this.setPassword(a.pass),void 0!==a.alg&&(this.algName=a.alg,void 0===a.prov&&(this.provName=KJUR.crypto.Util.DEFAULTPROVIDER[this.algName]),this.setAlgAndProvider(this.algName,this.provName)))},KJUR.crypto.Signature=function(a){var b=null;if(this._setAlgNames=function(){var a=this.algName.match(/^(.+)with(.+)$/);a&&(this.mdAlgName=a[1].toLowerCase(),this.pubkeyAlgName=a[2].toLowerCase())},this._zeroPaddingOfSignature=function(a,b){for(var c="",d=b/4-a.length,e=0;e<d;e++)c+="0";return c+a},this.setAlgAndProvider=function(a,b){if(this._setAlgNames(),"cryptojs/jsrsa"!=b)throw"provider not supported: "+b;if(":md5:sha1:sha224:sha256:sha384:sha512:ripemd160:".indexOf(this.mdAlgName)!=-1){try{this.md=new KJUR.crypto.MessageDigest({alg:this.mdAlgName})}catch(a){throw"setAlgAndProvider hash alg set fail alg="+this.mdAlgName+"/"+a}this.init=function(a,b){var c=null;try{c=void 0===b?KEYUTIL.getKey(a):KEYUTIL.getKey(a,b)}catch(a){throw"init failed:"+a}if(c.isPrivate===!0)this.prvKey=c,this.state="SIGN";else{if(c.isPublic!==!0)throw"init failed.:"+c;this.pubKey=c,this.state="VERIFY"}},this.initSign=function(a){"string"==typeof a.ecprvhex&&"string"==typeof a.eccurvename?(this.ecprvhex=a.ecprvhex,this.eccurvename=a.eccurvename):this.prvKey=a,this.state="SIGN"},this.initVerifyByPublicKey=function(a){"string"==typeof a.ecpubhex&&"string"==typeof a.eccurvename?(this.ecpubhex=a.ecpubhex,this.eccurvename=a.eccurvename):a instanceof KJUR.crypto.ECDSA?this.pubKey=a:a instanceof RSAKey&&(this.pubKey=a),this.state="VERIFY"},this.initVerifyByCertificatePEM=function(a){var b=new X509;b.readCertPEM(a),this.pubKey=b.subjectPublicKeyRSA,this.state="VERIFY"},this.updateString=function(a){this.md.updateString(a)},this.updateHex=function(a){this.md.updateHex(a)},this.sign=function(){if(this.sHashHex=this.md.digest(),"undefined"!=typeof this.ecprvhex&&"undefined"!=typeof this.eccurvename){var a=new KJUR.crypto.ECDSA({curve:this.eccurvename});this.hSign=a.signHex(this.sHashHex,this.ecprvhex)}else if(this.prvKey instanceof RSAKey&&"rsaandmgf1"==this.pubkeyAlgName)this.hSign=this.prvKey.signWithMessageHashPSS(this.sHashHex,this.mdAlgName,this.pssSaltLen);else if(this.prvKey instanceof RSAKey&&"rsa"==this.pubkeyAlgName)this.hSign=this.prvKey.signWithMessageHash(this.sHashHex,this.mdAlgName);else if(this.prvKey instanceof KJUR.crypto.ECDSA)this.hSign=this.prvKey.signWithMessageHash(this.sHashHex);else{if(!(this.prvKey instanceof KJUR.crypto.DSA))throw"Signature: unsupported public key alg: "+this.pubkeyAlgName;this.hSign=this.prvKey.signWithMessageHash(this.sHashHex)}return this.hSign},this.signString=function(a){return this.updateString(a),this.sign()},this.signHex=function(a){return this.updateHex(a),this.sign()},this.verify=function(a){if(this.sHashHex=this.md.digest(),"undefined"!=typeof this.ecpubhex&&"undefined"!=typeof this.eccurvename){var b=new KJUR.crypto.ECDSA({curve:this.eccurvename});return b.verifyHex(this.sHashHex,a,this.ecpubhex)}if(this.pubKey instanceof RSAKey&&"rsaandmgf1"==this.pubkeyAlgName)return this.pubKey.verifyWithMessageHashPSS(this.sHashHex,a,this.mdAlgName,this.pssSaltLen);if(this.pubKey instanceof RSAKey&&"rsa"==this.pubkeyAlgName)return this.pubKey.verifyWithMessageHash(this.sHashHex,a);if(this.pubKey instanceof KJUR.crypto.ECDSA)return this.pubKey.verifyWithMessageHash(this.sHashHex,a);if(this.pubKey instanceof KJUR.crypto.DSA)return this.pubKey.verifyWithMessageHash(this.sHashHex,a);throw"Signature: unsupported public key alg: "+this.pubkeyAlgName}}},this.init=function(a,b){throw"init(key, pass) not supported for this alg:prov="+this.algProvName},this.initVerifyByPublicKey=function(a){throw"initVerifyByPublicKey(rsaPubKeyy) not supported for this alg:prov="+this.algProvName},this.initVerifyByCertificatePEM=function(a){throw"initVerifyByCertificatePEM(certPEM) not supported for this alg:prov="+this.algProvName},this.initSign=function(a){throw"initSign(prvKey) not supported for this alg:prov="+this.algProvName},this.updateString=function(a){throw"updateString(str) not supported for this alg:prov="+this.algProvName},this.updateHex=function(a){throw"updateHex(hex) not supported for this alg:prov="+this.algProvName},this.sign=function(){throw"sign() not supported for this alg:prov="+this.algProvName},this.signString=function(a){throw"digestString(str) not supported for this alg:prov="+this.algProvName},this.signHex=function(a){throw"digestHex(hex) not supported for this alg:prov="+this.algProvName},this.verify=function(a){throw"verify(hSigVal) not supported for this alg:prov="+this.algProvName},this.initParams=a,void 0!==a&&(void 0!==a.alg&&(this.algName=a.alg,void 0===a.prov?this.provName=KJUR.crypto.Util.DEFAULTPROVIDER[this.algName]:this.provName=a.prov,this.algProvName=this.algName+":"+this.provName,this.setAlgAndProvider(this.algName,this.provName),this._setAlgNames()),void 0!==a.psssaltlen&&(this.pssSaltLen=a.psssaltlen),void 0!==a.prvkeypem)){if(void 0!==a.prvkeypas)throw"both prvkeypem and prvkeypas parameters not supported";try{var b=new RSAKey;b.readPrivateKeyFromPEMString(a.prvkeypem),this.initSign(b)}catch(a){throw"fatal error to load pem private key: "+a}}},KJUR.crypto.Cipher=function(a){},KJUR.crypto.Cipher.encrypt=function(a,b,c){if(b instanceof RSAKey&&b.isPublic){var d=KJUR.crypto.Cipher.getAlgByKeyAndName(b,c);if("RSA"===d)return b.encrypt(a);if("RSAOAEP"===d)return b.encryptOAEP(a,"sha1");var e=d.match(/^RSAOAEP(\d+)$/);if(null!==e)return b.encryptOAEP(a,"sha"+e[1]);throw"Cipher.encrypt: unsupported algorithm for RSAKey: "+c}throw"Cipher.encrypt: unsupported key or algorithm"},KJUR.crypto.Cipher.decrypt=function(a,b,c){if(b instanceof RSAKey&&b.isPrivate){var d=KJUR.crypto.Cipher.getAlgByKeyAndName(b,c);if("RSA"===d)return b.decrypt(a);if("RSAOAEP"===d)return b.decryptOAEP(a,"sha1");var e=d.match(/^RSAOAEP(\d+)$/);if(null!==e)return b.decryptOAEP(a,"sha"+e[1]);throw"Cipher.decrypt: unsupported algorithm for RSAKey: "+c}throw"Cipher.decrypt: unsupported key or algorithm"},KJUR.crypto.Cipher.getAlgByKeyAndName=function(a,b){if(a instanceof RSAKey){if(":RSA:RSAOAEP:RSAOAEP224:RSAOAEP256:RSAOAEP384:RSAOAEP512:".indexOf(b)!=-1)return b;if(null===b||void 0===b)return"RSA";throw"getAlgByKeyAndName: not supported algorithm name for RSAKey: "+b}throw"getAlgByKeyAndName: not supported algorithm name: "+b},KJUR.crypto.OID=new function(){this.oidhex2name={"2a864886f70d010101":"rsaEncryption","2a8648ce3d0201":"ecPublicKey","2a8648ce380401":"dsa","2a8648ce3d030107":"secp256r1","2b8104001f":"secp192k1","2b81040021":"secp224r1","2b8104000a":"secp256k1","2b81040023":"secp521r1","2b81040022":"secp384r1","2a8648ce380403":"SHA1withDSA","608648016503040301":"SHA224withDSA","608648016503040302":"SHA256withDSA"}};
/* base64x-1.1.min.js  */
/*! base64x-1.1.8 (c) 2012-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
var KJUR; if (typeof KJUR == "undefined" || !KJUR) KJUR = {}; if (typeof KJUR.lang == "undefined" || !KJUR.lang) KJUR.lang = {}; KJUR.lang.String = function() {}; function Base64x() { } function stoBA(s) { var a = new Array(); for (var i = 0; i < s.length; i++) { a[i] = s.charCodeAt(i); } return a; } function BAtos(a) { var s = ""; for (var i = 0; i < a.length; i++) { s = s + String.fromCharCode(a[i]); } return s; } function BAtohex(a) { var s = ""; for (var i = 0; i < a.length; i++) { var hex1 = a[i].toString(16); if (hex1.length == 1) hex1 = "0" + hex1; s = s + hex1; } return s; } function stohex(s) { return BAtohex(stoBA(s)); } function stob64(s) { return hex2b64(stohex(s)); } function stob64u(s) { return b64tob64u(hex2b64(stohex(s))); } function b64utos(s) { return BAtos(b64toBA(b64utob64(s))); } function b64tob64u(s) { s = s.replace(/\=/g, ""); s = s.replace(/\+/g, "-"); s = s.replace(/\//g, "_"); return s; } function b64utob64(s) { if (s.length % 4 == 2) s = s + "=="; else if (s.length % 4 == 3) s = s + "="; s = s.replace(/-/g, "+"); s = s.replace(/_/g, "/"); return s; } function hextob64u(s) { if (s.length % 2 == 1) s = "0" + s; return b64tob64u(hex2b64(s)); } function b64utohex(s) { return b64tohex(b64utob64(s)); } var utf8tob64u, b64utoutf8; if (typeof Buffer === 'function') { utf8tob64u = function (s) { return b64tob64u(new Buffer(s, 'utf8').toString('base64')); }; b64utoutf8 = function (s) { return new Buffer(b64utob64(s), 'base64').toString('utf8'); }; } else { utf8tob64u = function (s) { return hextob64u(uricmptohex(encodeURIComponentAll(s))); }; b64utoutf8 = function (s) { return decodeURIComponent(hextouricmp(b64utohex(s))); }; } function utf8tob64(s) { return hex2b64(uricmptohex(encodeURIComponentAll(s))); } function b64toutf8(s) { return decodeURIComponent(hextouricmp(b64tohex(s))); } function utf8tohex(s) { return uricmptohex(encodeURIComponentAll(s)); } function hextoutf8(s) { return decodeURIComponent(hextouricmp(s)); } function hextorstr(sHex) { var s = ""; for (var i = 0; i < sHex.length - 1; i += 2) { s += String.fromCharCode(parseInt(sHex.substr(i, 2), 16)); } return s; } function rstrtohex(s) { var result = ""; for (var i = 0; i < s.length; i++) { result += ("0" + s.charCodeAt(i).toString(16)).slice(-2); } return result; } function hextob64(s) { return hex2b64(s); } function hextob64nl(s) { var b64 = hextob64(s); var b64nl = b64.replace(/(.{64})/g, "$1\r\n"); b64nl = b64nl.replace(/\r\n$/, ''); return b64nl; } function b64nltohex(s) { var b64 = s.replace(/[^0-9A-Za-z\/+=]*/g, ''); var hex = b64tohex(b64); return hex; } function hextoArrayBuffer(hex) { if (hex.length % 2 != 0) throw "input is not even length"; if (hex.match(/^[0-9A-Fa-f]+$/) == null) throw "input is not hexadecimal"; var buffer = new ArrayBuffer(hex.length / 2); var view = new DataView(buffer); for (var i = 0; i < hex.length / 2; i++) { view.setUint8(i, parseInt(hex.substr(i * 2, 2), 16)); } return buffer; } function ArrayBuffertohex(buffer) { var hex = ""; var view = new DataView(buffer); for (var i = 0; i < buffer.byteLength; i++) { hex += ("00" + view.getUint8(i).toString(16)).slice(-2); } return hex; } function uricmptohex(s) { return s.replace(/%/g, ""); } function hextouricmp(s) { return s.replace(/(..)/g, "%$1"); } function encodeURIComponentAll(u8) { var s = encodeURIComponent(u8); var s2 = ""; for (var i = 0; i < s.length; i++) { if (s[i] == "%") { s2 = s2 + s.substr(i, 3); i = i + 2; } else { s2 = s2 + "%" + stohex(s[i]); } } return s2; } function newline_toUnix(s) { s = s.replace(/\r\n/mg, "\n"); return s; } function newline_toDos(s) { s = s.replace(/\r\n/mg, "\n"); s = s.replace(/\n/mg, "\r\n"); return s; } KJUR.lang.String.isInteger = function(s) { if (s.match(/^[0-9]+$/)) { return true; } else if (s.match(/^-[0-9]+$/)) { return true; } else { return false; } }; KJUR.lang.String.isHex = function(s) { if (s.length % 2 == 0 && (s.match(/^[0-9a-f]+$/) || s.match(/^[0-9A-F]+$/))) { return true; } else { return false; } }; KJUR.lang.String.isBase64 = function(s) { s = s.replace(/\s+/g, ""); if (s.match(/^[0-9A-Za-z+\/]+={0,3}$/) && s.length % 4 == 0) { return true; } else { return false; } }; KJUR.lang.String.isBase64URL = function(s) { if (s.match(/[+/=]/)) return false; s = b64utob64(s); return KJUR.lang.String.isBase64(s); }; KJUR.lang.String.isIntegerArray = function(s) { s = s.replace(/\s+/g, ""); if (s.match(/^\[[0-9,]+\]$/)) { return true; } else { return false; } }; function intarystrtohex(s) { s = s.replace(/^\s*\[\s*/, ''); s = s.replace(/\s*\]\s*$/, ''); s = s.replace(/\s*/g, ''); try { var hex = s.split(/,/).map(function(element, index, array) { var i = parseInt(element); if (i < 0 || 255 < i) throw "integer not in range 0-255"; var hI = ("00" + i.toString(16)).slice(-2); return hI; }).join(''); return hex; } catch(ex) { throw "malformed integer array string: " + ex; } } var strdiffidx = function(s1, s2) { var n = s1.length; if (s1.length > s2.length) n = s2.length; for (var i = 0; i < n; i++) { if (s1.charCodeAt(i) != s2.charCodeAt(i)) return i; } if (s1.length != s2.length) return n; return -1; };/* ext/prng4-min.js  */
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function Arcfour(){this.i=0;this.j=0;this.S=new Array()}function ARC4init(d){var c,a,b;for(c=0;c<256;++c){this.S[c]=c}a=0;for(c=0;c<256;++c){a=(a+this.S[c]+d[c%d.length])&255;b=this.S[c];this.S[c]=this.S[a];this.S[a]=b}this.i=0;this.j=0}function ARC4next(){var a;this.i=(this.i+1)&255;this.j=(this.j+this.S[this.i])&255;a=this.S[this.i];this.S[this.i]=this.S[this.j];this.S[this.j]=a;return this.S[(a+this.S[this.i])&255]}Arcfour.prototype.init=ARC4init;Arcfour.prototype.next=ARC4next;function prng_newstate(){return new Arcfour()}var rng_psize=256;
/* ext/rng-min.js  */
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
var rng_state;var rng_pool;var rng_pptr;function rng_seed_int(a){rng_pool[rng_pptr++]^=a&255;rng_pool[rng_pptr++]^=(a>>8)&255;rng_pool[rng_pptr++]^=(a>>16)&255;rng_pool[rng_pptr++]^=(a>>24)&255;if(rng_pptr>=rng_psize){rng_pptr-=rng_psize}}function rng_seed_time(){rng_seed_int(new Date().getTime())}if(rng_pool==null){rng_pool=new Array();rng_pptr=0;var t;if(navigator.appName=="Netscape"&&navigator.appVersion<"5"&&window.crypto){var z=window.crypto.random(32);for(t=0;t<z.length;++t){rng_pool[rng_pptr++]=z.charCodeAt(t)&255}}while(rng_pptr<rng_psize){t=Math.floor(65536*Math.random());rng_pool[rng_pptr++]=t>>>8;rng_pool[rng_pptr++]=t&255}rng_pptr=0;rng_seed_time()}function rng_get_byte(){if(rng_state==null){rng_seed_time();rng_state=prng_newstate();rng_state.init(rng_pool);for(rng_pptr=0;rng_pptr<rng_pool.length;++rng_pptr){rng_pool[rng_pptr]=0}rng_pptr=0}return rng_state.next()}function rng_get_bytes(b){var a;for(a=0;a<b.length;++a){b[a]=rng_get_byte()}}function SecureRandom(){}SecureRandom.prototype.nextBytes=rng_get_bytes;
/* ext/json-sans-eval-min.js  */
/*! Mike Samuel (c) 2009 | code.google.com/p/json-sans-eval
 */
var jsonParse=(function(){var e="(?:-?\\b(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\\b)";var j='(?:[^\\0-\\x08\\x0a-\\x1f"\\\\]|\\\\(?:["/\\\\bfnrt]|u[0-9A-Fa-f]{4}))';var i='(?:"'+j+'*")';var d=new RegExp("(?:false|true|null|[\\{\\}\\[\\]]|"+e+"|"+i+")","g");var k=new RegExp("\\\\(?:([^u])|u(.{4}))","g");var g={'"':'"',"/":"/","\\":"\\",b:"\b",f:"\f",n:"\n",r:"\r",t:"\t"};function h(l,m,n){return m?g[m]:String.fromCharCode(parseInt(n,16))}var c=new String("");var a="\\";var f={"{":Object,"[":Array};var b=Object.hasOwnProperty;return function(u,q){var p=u.match(d);var x;var v=p[0];var l=false;if("{"===v){x={}}else{if("["===v){x=[]}else{x=[];l=true}}var t;var r=[x];for(var o=1-l,m=p.length;o<m;++o){v=p[o];var w;switch(v.charCodeAt(0)){default:w=r[0];w[t||w.length]=+(v);t=void 0;break;case 34:v=v.substring(1,v.length-1);if(v.indexOf(a)!==-1){v=v.replace(k,h)}w=r[0];if(!t){if(w instanceof Array){t=w.length}else{t=v||c;break}}w[t]=v;t=void 0;break;case 91:w=r[0];r.unshift(w[t||w.length]=[]);t=void 0;break;case 93:r.shift();break;case 102:w=r[0];w[t||w.length]=false;t=void 0;break;case 110:w=r[0];w[t||w.length]=null;t=void 0;break;case 116:w=r[0];w[t||w.length]=true;t=void 0;break;case 123:w=r[0];r.unshift(w[t||w.length]={});t=void 0;break;case 125:r.shift();break}}if(l){if(r.length!==1){throw new Error()}x=x[0]}else{if(r.length){throw new Error()}}if(q){var s=function(C,B){var D=C[B];if(D&&typeof D==="object"){var n=null;for(var z in D){if(b.call(D,z)&&D!==C){var y=s(D,z);if(y!==void 0){D[z]=y}else{if(!n){n=[]}n.push(z)}}}if(n){for(var A=n.length;--A>=0;){delete D[n[A]]}}}return q.call(C,B,D)};x=s({"":x},"")}return x}})();
/* jws-3.3.min.js  */
/*! jws-3.3.5 (c) 2013-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
"undefined"!=typeof KJUR&&KJUR||(KJUR={}),"undefined"!=typeof KJUR.jws&&KJUR.jws||(KJUR.jws={}),KJUR.jws.JWS=function(){var a=KJUR.jws.JWS;this.parseJWS=function(b,c){if(void 0===this.parsedJWS||!c&&void 0===this.parsedJWS.sigvalH){var d=b.match(/^([^.]+)\.([^.]+)\.([^.]+)$/);if(null==d)throw"JWS signature is not a form of 'Head.Payload.SigValue'.";var e=d[1],f=d[2],g=d[3],h=e+"."+f;if(this.parsedJWS={},this.parsedJWS.headB64U=e,this.parsedJWS.payloadB64U=f,this.parsedJWS.sigvalB64U=g,this.parsedJWS.si=h,!c){var i=b64utohex(g),j=parseBigInt(i,16);this.parsedJWS.sigvalH=i,this.parsedJWS.sigvalBI=j}var k=b64utoutf8(e),l=b64utoutf8(f);if(this.parsedJWS.headS=k,this.parsedJWS.payloadS=l,!a.isSafeJSONString(k,this.parsedJWS,"headP"))throw"malformed JSON string for JWS Head: "+k}}},KJUR.jws.JWS.sign=function(a,b,c,d,e){var g,h,i,f=KJUR.jws.JWS;if("string"!=typeof b&&"object"!=typeof b)throw"spHeader must be JSON string or object: "+b;if("object"==typeof b&&(h=b,g=JSON.stringify(h)),"string"==typeof b){if(g=b,!f.isSafeJSONString(g))throw"JWS Head is not safe JSON string: "+g;h=f.readSafeJSONString(g)}if(i=c,"object"==typeof c&&(i=JSON.stringify(c)),""!=a&&null!=a||void 0===h.alg||(a=h.alg),""!=a&&null!=a&&void 0===h.alg&&(h.alg=a,g=JSON.stringify(h)),a!==h.alg)throw"alg and sHeader.alg doesn't match: "+a+"!="+h.alg;var j=null;if(void 0===f.jwsalg2sigalg[a])throw"unsupported alg name: "+a;j=f.jwsalg2sigalg[a];var k=utf8tob64u(g),l=utf8tob64u(i),m=k+"."+l,n="";if("Hmac"==j.substr(0,4)){if(void 0===d)throw"mac key shall be specified for HS* alg";var o=new KJUR.crypto.Mac({alg:j,prov:"cryptojs",pass:d});o.updateString(m),n=o.doFinal()}else if(j.indexOf("withECDSA")!=-1){var p=new KJUR.crypto.Signature({alg:j});p.init(d,e),p.updateString(m),hASN1Sig=p.sign(),n=KJUR.crypto.ECDSA.asn1SigToConcatSig(hASN1Sig)}else if("none"!=j){var p=new KJUR.crypto.Signature({alg:j});p.init(d,e),p.updateString(m),n=p.sign()}var q=hextob64u(n);return m+"."+q},KJUR.jws.JWS.verify=function(a,b,c){var d=KJUR.jws.JWS,e=a.split("."),f=e[0],g=e[1],h=f+"."+g,i=b64utohex(e[2]),j=d.readSafeJSONString(b64utoutf8(e[0])),k=null,l=null;if(void 0===j.alg)throw"algorithm not specified in header";if(k=j.alg,l=k.substr(0,2),null!=c&&"[object Array]"===Object.prototype.toString.call(c)&&c.length>0){var m=":"+c.join(":")+":";if(m.indexOf(":"+k+":")==-1)throw"algorithm '"+k+"' not accepted in the list"}if("none"!=k&&null===b)throw"key shall be specified to verify.";if("string"==typeof b&&b.indexOf("-----BEGIN ")!=-1&&(b=KEYUTIL.getKey(b)),!("RS"!=l&&"PS"!=l||b instanceof RSAKey))throw"key shall be a RSAKey obj for RS* and PS* algs";if("ES"==l&&!(b instanceof KJUR.crypto.ECDSA))throw"key shall be a ECDSA obj for ES* algs";var n=null;if(void 0===d.jwsalg2sigalg[j.alg])throw"unsupported alg name: "+k;if(n=d.jwsalg2sigalg[k],"none"==n)throw"not supported";if("Hmac"==n.substr(0,4)){var o=null;if(void 0===b)throw"hexadecimal key shall be specified for HMAC";var p=new KJUR.crypto.Mac({alg:n,pass:b});return p.updateString(h),o=p.doFinal(),i==o}if(n.indexOf("withECDSA")!=-1){var q=null;try{q=KJUR.crypto.ECDSA.concatSigToASN1Sig(i)}catch(a){return!1}var r=new KJUR.crypto.Signature({alg:n});return r.init(b),r.updateString(h),r.verify(q)}var r=new KJUR.crypto.Signature({alg:n});return r.init(b),r.updateString(h),r.verify(i)},KJUR.jws.JWS.parse=function(a){var d,e,f,b=a.split("."),c={};if(2!=b.length&&3!=b.length)throw"malformed sJWS: wrong number of '.' splitted elements";return d=b[0],e=b[1],3==b.length&&(f=b[2]),c.headerObj=KJUR.jws.JWS.readSafeJSONString(b64utoutf8(d)),c.payloadObj=KJUR.jws.JWS.readSafeJSONString(b64utoutf8(e)),c.headerPP=JSON.stringify(c.headerObj,null,"  "),null==c.payloadObj?c.payloadPP=b64utoutf8(e):c.payloadPP=JSON.stringify(c.payloadObj,null,"  "),void 0!==f&&(c.sigHex=b64utohex(f)),c},KJUR.jws.JWS.verifyJWT=function(a,b,c){var d=KJUR.jws.JWS,e=a.split("."),f=e[0],g=e[1],j=(b64utohex(e[2]),d.readSafeJSONString(b64utoutf8(f))),k=d.readSafeJSONString(b64utoutf8(g));if(void 0===j.alg)return!1;if(void 0===c.alg)throw"acceptField.alg shall be specified";if(!d.inArray(j.alg,c.alg))return!1;if(void 0!==k.iss&&"object"==typeof c.iss&&!d.inArray(k.iss,c.iss))return!1;if(void 0!==k.sub&&"object"==typeof c.sub&&!d.inArray(k.sub,c.sub))return!1;if(void 0!==k.aud&&"object"==typeof c.aud)if("string"==typeof k.aud){if(!d.inArray(k.aud,c.aud))return!1}else if("object"==typeof k.aud&&!d.includedArray(k.aud,c.aud))return!1;var l=KJUR.jws.IntDate.getNow();return void 0!==c.verifyAt&&"number"==typeof c.verifyAt&&(l=c.verifyAt),void 0!==c.gracePeriod&&"number"==typeof c.gracePeriod||(c.gracePeriod=0),!(void 0!==k.exp&&"number"==typeof k.exp&&k.exp+c.gracePeriod<l)&&(!(void 0!==k.nbf&&"number"==typeof k.nbf&&l<k.nbf-c.gracePeriod)&&(!(void 0!==k.iat&&"number"==typeof k.iat&&l<k.iat-c.gracePeriod)&&((void 0===k.jti||void 0===c.jti||k.jti===c.jti)&&!!KJUR.jws.JWS.verify(a,b,c.alg))))},KJUR.jws.JWS.includedArray=function(a,b){var c=KJUR.jws.JWS.inArray;if(null===a)return!1;if("object"!=typeof a)return!1;if("number"!=typeof a.length)return!1;for(var d=0;d<a.length;d++)if(!c(a[d],b))return!1;return!0},KJUR.jws.JWS.inArray=function(a,b){if(null===b)return!1;if("object"!=typeof b)return!1;if("number"!=typeof b.length)return!1;for(var c=0;c<b.length;c++)if(b[c]==a)return!0;return!1},KJUR.jws.JWS.jwsalg2sigalg={HS256:"HmacSHA256",HS384:"HmacSHA384",HS512:"HmacSHA512",RS256:"SHA256withRSA",RS384:"SHA384withRSA",RS512:"SHA512withRSA",ES256:"SHA256withECDSA",ES384:"SHA384withECDSA",PS256:"SHA256withRSAandMGF1",PS384:"SHA384withRSAandMGF1",PS512:"SHA512withRSAandMGF1",none:"none"},KJUR.jws.JWS.isSafeJSONString=function(a,b,c){var d=null;try{return d=jsonParse(a),"object"!=typeof d?0:d.constructor===Array?0:(b&&(b[c]=d),1)}catch(a){return 0}},KJUR.jws.JWS.readSafeJSONString=function(a){var b=null;try{return b=jsonParse(a),"object"!=typeof b?null:b.constructor===Array?null:b}catch(a){return null}},KJUR.jws.JWS.getEncodedSignatureValueFromJWS=function(a){var b=a.match(/^[^.]+\.[^.]+\.([^.]+)$/);if(null==b)throw"JWS signature is not a form of 'Head.Payload.SigValue'.";return b[1]},KJUR.jws.JWS.getJWKthumbprint=function(a){if("RSA"!==a.kty&&"EC"!==a.kty&&"oct"!==a.kty)throw"unsupported algorithm for JWK Thumprint";var b="{";if("RSA"===a.kty){if("string"!=typeof a.n||"string"!=typeof a.e)throw"wrong n and e value for RSA key";b+='"e":"'+a.e+'",',b+='"kty":"'+a.kty+'",',b+='"n":"'+a.n+'"}'}else if("EC"===a.kty){if("string"!=typeof a.crv||"string"!=typeof a.x||"string"!=typeof a.y)throw"wrong crv, x and y value for EC key";b+='"crv":"'+a.crv+'",',b+='"kty":"'+a.kty+'",',b+='"x":"'+a.x+'",',b+='"y":"'+a.y+'"}'}else if("oct"===a.kty){if("string"!=typeof a.k)throw"wrong k value for oct(symmetric) key";b+='"kty":"'+a.kty+'",',b+='"k":"'+a.k+'"}'}var c=rstrtohex(b),d=KJUR.crypto.Util.hashHex(c,"sha256"),e=hextob64u(d);return e},KJUR.jws.IntDate={},KJUR.jws.IntDate.get=function(a){if("now"==a)return KJUR.jws.IntDate.getNow();if("now + 1hour"==a)return KJUR.jws.IntDate.getNow()+3600;if("now + 1day"==a)return KJUR.jws.IntDate.getNow()+86400;if("now + 1month"==a)return KJUR.jws.IntDate.getNow()+2592e3;if("now + 1year"==a)return KJUR.jws.IntDate.getNow()+31536e3;if(a.match(/Z$/))return KJUR.jws.IntDate.getZulu(a);if(a.match(/^[0-9]+$/))return parseInt(a);throw"unsupported format: "+a},KJUR.jws.IntDate.getZulu=function(a){var b=a.match(/(\d+)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z/);if(b){var c=b[1],d=parseInt(c);if(4==c.length);else{if(2!=c.length)throw"malformed year string";if(50<=d&&d<100)d=1900+d;else{if(!(0<=d&&d<50))throw"malformed year string for UTCTime";d=2e3+d}}var e=parseInt(b[2])-1,f=parseInt(b[3]),g=parseInt(b[4]),h=parseInt(b[5]),i=parseInt(b[6]),j=new Date(Date.UTC(d,e,f,g,h,i));return~~(j/1e3)}throw"unsupported format: "+a},KJUR.jws.IntDate.getNow=function(){var a=~~(new Date/1e3);return a},KJUR.jws.IntDate.intDate2UTCString=function(a){var b=new Date(1e3*a);return b.toUTCString()},KJUR.jws.IntDate.intDate2Zulu=function(a){var b=new Date(1e3*a),c=("0000"+b.getUTCFullYear()).slice(-4),d=("00"+(b.getUTCMonth()+1)).slice(-2),e=("00"+b.getUTCDate()).slice(-2),f=("00"+b.getUTCHours()).slice(-2),g=("00"+b.getUTCMinutes()).slice(-2),h=("00"+b.getUTCSeconds()).slice(-2);return c+d+e+f+g+h+"Z"};
/* keyutil-1.0.js  */
/*! keyutil-1.0.14.js (c) 2013-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
var KEYUTIL=function(){var a=function(a,b,c){return d(CryptoJS.AES,a,b,c)},b=function(a,b,c){return d(CryptoJS.TripleDES,a,b,c)},c=function(a,b,c){return d(CryptoJS.DES,a,b,c)},d=function(a,b,c,d){var e=CryptoJS.enc.Hex.parse(b),f=CryptoJS.enc.Hex.parse(c),g=CryptoJS.enc.Hex.parse(d),h={};h.key=f,h.iv=g,h.ciphertext=e;var i=a.decrypt(h,f,{iv:g});return CryptoJS.enc.Hex.stringify(i)},e=function(a,b,c){return h(CryptoJS.AES,a,b,c)},f=function(a,b,c){return h(CryptoJS.TripleDES,a,b,c)},g=function(a,b,c){return h(CryptoJS.DES,a,b,c)},h=function(a,b,c,d){var e=CryptoJS.enc.Hex.parse(b),f=CryptoJS.enc.Hex.parse(c),g=CryptoJS.enc.Hex.parse(d),h=a.encrypt(e,f,{iv:g}),i=CryptoJS.enc.Hex.parse(h.toString()),j=CryptoJS.enc.Base64.stringify(i);return j},i={"AES-256-CBC":{proc:a,eproc:e,keylen:32,ivlen:16},"AES-192-CBC":{proc:a,eproc:e,keylen:24,ivlen:16},"AES-128-CBC":{proc:a,eproc:e,keylen:16,ivlen:16},"DES-EDE3-CBC":{proc:b,eproc:f,keylen:24,ivlen:8},"DES-CBC":{proc:c,eproc:g,keylen:8,ivlen:8}},j=function(a){return i[a].proc},k=function(a){var b=CryptoJS.lib.WordArray.random(a),c=CryptoJS.enc.Hex.stringify(b);return c},l=function(a){var b={},c=a.match(new RegExp("DEK-Info: ([^,]+),([0-9A-Fa-f]+)","m"));c&&(b.cipher=c[1],b.ivsalt=c[2]);var d=a.match(new RegExp("-----BEGIN ([A-Z]+) PRIVATE KEY-----"));d&&(b.type=d[1]);var e=-1,f=0;a.indexOf("\r\n\r\n")!=-1&&(e=a.indexOf("\r\n\r\n"),f=2),a.indexOf("\n\n")!=-1&&(e=a.indexOf("\n\n"),f=1);var g=a.indexOf("-----END");if(e!=-1&&g!=-1){var h=a.substring(e+2*f,g-f);h=h.replace(/\s+/g,""),b.data=h}return b},m=function(a,b,c){for(var d=c.substring(0,16),e=CryptoJS.enc.Hex.parse(d),f=CryptoJS.enc.Utf8.parse(b),g=i[a].keylen+i[a].ivlen,h="",j=null;;){var k=CryptoJS.algo.MD5.create();if(null!=j&&k.update(j),k.update(f),k.update(e),j=k.finalize(),h+=CryptoJS.enc.Hex.stringify(j),h.length>=2*g)break}var l={};return l.keyhex=h.substr(0,2*i[a].keylen),l.ivhex=h.substr(2*i[a].keylen,2*i[a].ivlen),l},n=function(a,b,c,d){var e=CryptoJS.enc.Base64.parse(a),f=CryptoJS.enc.Hex.stringify(e),g=i[b].proc,h=g(f,c,d);return h},o=function(a,b,c,d){var e=i[b].eproc,f=e(a,c,d);return f};return{version:"1.0.0",getHexFromPEM:function(a,b){var c=a;if(c.indexOf("-----BEGIN ")==-1)throw"can't find PEM header: "+b;"string"==typeof b&&""!=b?(c=c.replace("-----BEGIN "+b+"-----",""),c=c.replace("-----END "+b+"-----","")):(c=c.replace(/-----BEGIN [^-]+-----/,""),c=c.replace(/-----END [^-]+-----/,""));var d=c.replace(/\s+/g,""),e=b64tohex(d);return e},getDecryptedKeyHexByKeyIV:function(a,b,c,d){var e=j(b);return e(a,c,d)},parsePKCS5PEM:function(a){return l(a)},getKeyAndUnusedIvByPasscodeAndIvsalt:function(a,b,c){return m(a,b,c)},decryptKeyB64:function(a,b,c,d){return n(a,b,c,d)},getDecryptedKeyHex:function(a,b){var c=l(a),e=(c.type,c.cipher),f=c.ivsalt,g=c.data,h=m(e,b,f),i=h.keyhex,j=n(g,e,i,f);return j},getRSAKeyFromEncryptedPKCS5PEM:function(a,b){var c=this.getDecryptedKeyHex(a,b),d=new RSAKey;return d.readPrivateKeyFromASN1HexString(c),d},getEncryptedPKCS5PEMFromPrvKeyHex:function(a,b,c,d,e){var f="";if("undefined"!=typeof d&&null!=d||(d="AES-256-CBC"),"undefined"==typeof i[d])throw"KEYUTIL unsupported algorithm: "+d;if("undefined"==typeof e||null==e){var g=i[d].ivlen,h=k(g);e=h.toUpperCase()}var j=m(d,c,e),l=j.keyhex,n=o(b,d,l,e),p=n.replace(/(.{64})/g,"$1\r\n"),f="-----BEGIN "+a+" PRIVATE KEY-----\r\n";return f+="Proc-Type: 4,ENCRYPTED\r\n",f+="DEK-Info: "+d+","+e+"\r\n",f+="\r\n",f+=p,f+="\r\n-----END "+a+" PRIVATE KEY-----\r\n"},getEncryptedPKCS5PEMFromRSAKey:function(a,b,c,d){var e=new KJUR.asn1.DERInteger({int:0}),f=new KJUR.asn1.DERInteger({bigint:a.n}),g=new KJUR.asn1.DERInteger({int:a.e}),h=new KJUR.asn1.DERInteger({bigint:a.d}),i=new KJUR.asn1.DERInteger({bigint:a.p}),j=new KJUR.asn1.DERInteger({bigint:a.q}),k=new KJUR.asn1.DERInteger({bigint:a.dmp1}),l=new KJUR.asn1.DERInteger({bigint:a.dmq1}),m=new KJUR.asn1.DERInteger({bigint:a.coeff}),n=new KJUR.asn1.DERSequence({array:[e,f,g,h,i,j,k,l,m]}),o=n.getEncodedHex();return this.getEncryptedPKCS5PEMFromPrvKeyHex("RSA",o,b,c,d)},newEncryptedPKCS5PEM:function(a,b,c,d){"undefined"!=typeof b&&null!=b||(b=1024),"undefined"!=typeof c&&null!=c||(c="10001");var e=new RSAKey;e.generate(b,c);var f=null;return f="undefined"==typeof d||null==d?this.getEncryptedPKCS5PEMFromRSAKey(e,a):this.getEncryptedPKCS5PEMFromRSAKey(e,a,d)},getRSAKeyFromPlainPKCS8PEM:function(a){if(a.match(/ENCRYPTED/))throw"pem shall be not ENCRYPTED";var b=this.getHexFromPEM(a,"PRIVATE KEY"),c=this.getRSAKeyFromPlainPKCS8Hex(b);return c},getRSAKeyFromPlainPKCS8Hex:function(a){var b=ASN1HEX.getPosArrayOfChildren_AtObj(a,0);if(3!=b.length)throw"outer DERSequence shall have 3 elements: "+b.length;var c=ASN1HEX.getHexOfTLV_AtObj(a,b[1]);if("300d06092a864886f70d0101010500"!=c)throw"PKCS8 AlgorithmIdentifier is not rsaEnc: "+c;var c=ASN1HEX.getHexOfTLV_AtObj(a,b[1]),d=ASN1HEX.getHexOfTLV_AtObj(a,b[2]),e=ASN1HEX.getHexOfV_AtObj(d,0),f=new RSAKey;return f.readPrivateKeyFromASN1HexString(e),f},parseHexOfEncryptedPKCS8:function(a){var b={},c=ASN1HEX.getPosArrayOfChildren_AtObj(a,0);if(2!=c.length)throw"malformed format: SEQUENCE(0).items != 2: "+c.length;b.ciphertext=ASN1HEX.getHexOfV_AtObj(a,c[1]);var d=ASN1HEX.getPosArrayOfChildren_AtObj(a,c[0]);if(2!=d.length)throw"malformed format: SEQUENCE(0.0).items != 2: "+d.length;if("2a864886f70d01050d"!=ASN1HEX.getHexOfV_AtObj(a,d[0]))throw"this only supports pkcs5PBES2";var e=ASN1HEX.getPosArrayOfChildren_AtObj(a,d[1]);if(2!=d.length)throw"malformed format: SEQUENCE(0.0.1).items != 2: "+e.length;var f=ASN1HEX.getPosArrayOfChildren_AtObj(a,e[1]);if(2!=f.length)throw"malformed format: SEQUENCE(0.0.1.1).items != 2: "+f.length;if("2a864886f70d0307"!=ASN1HEX.getHexOfV_AtObj(a,f[0]))throw"this only supports TripleDES";b.encryptionSchemeAlg="TripleDES",b.encryptionSchemeIV=ASN1HEX.getHexOfV_AtObj(a,f[1]);var g=ASN1HEX.getPosArrayOfChildren_AtObj(a,e[0]);if(2!=g.length)throw"malformed format: SEQUENCE(0.0.1.0).items != 2: "+g.length;if("2a864886f70d01050c"!=ASN1HEX.getHexOfV_AtObj(a,g[0]))throw"this only supports pkcs5PBKDF2";var h=ASN1HEX.getPosArrayOfChildren_AtObj(a,g[1]);if(h.length<2)throw"malformed format: SEQUENCE(0.0.1.0.1).items < 2: "+h.length;b.pbkdf2Salt=ASN1HEX.getHexOfV_AtObj(a,h[0]);var i=ASN1HEX.getHexOfV_AtObj(a,h[1]);try{b.pbkdf2Iter=parseInt(i,16)}catch(a){throw"malformed format pbkdf2Iter: "+i}return b},getPBKDF2KeyHexFromParam:function(a,b){var c=CryptoJS.enc.Hex.parse(a.pbkdf2Salt),d=a.pbkdf2Iter,e=CryptoJS.PBKDF2(b,c,{keySize:6,iterations:d}),f=CryptoJS.enc.Hex.stringify(e);return f},getPlainPKCS8HexFromEncryptedPKCS8PEM:function(a,b){var c=this.getHexFromPEM(a,"ENCRYPTED PRIVATE KEY"),d=this.parseHexOfEncryptedPKCS8(c),e=KEYUTIL.getPBKDF2KeyHexFromParam(d,b),f={};f.ciphertext=CryptoJS.enc.Hex.parse(d.ciphertext);var g=CryptoJS.enc.Hex.parse(e),h=CryptoJS.enc.Hex.parse(d.encryptionSchemeIV),i=CryptoJS.TripleDES.decrypt(f,g,{iv:h}),j=CryptoJS.enc.Hex.stringify(i);return j},getRSAKeyFromEncryptedPKCS8PEM:function(a,b){var c=this.getPlainPKCS8HexFromEncryptedPKCS8PEM(a,b),d=this.getRSAKeyFromPlainPKCS8Hex(c);return d},getKeyFromEncryptedPKCS8PEM:function(a,b){var c=this.getPlainPKCS8HexFromEncryptedPKCS8PEM(a,b),d=this.getKeyFromPlainPrivatePKCS8Hex(c);return d},parsePlainPrivatePKCS8Hex:function(a){var b={};if(b.algparam=null,"30"!=a.substr(0,2))throw"malformed plain PKCS8 private key(code:001)";var c=ASN1HEX.getPosArrayOfChildren_AtObj(a,0);if(3!=c.length)throw"malformed plain PKCS8 private key(code:002)";if("30"!=a.substr(c[1],2))throw"malformed PKCS8 private key(code:003)";var d=ASN1HEX.getPosArrayOfChildren_AtObj(a,c[1]);if(2!=d.length)throw"malformed PKCS8 private key(code:004)";if("06"!=a.substr(d[0],2))throw"malformed PKCS8 private key(code:005)";if(b.algoid=ASN1HEX.getHexOfV_AtObj(a,d[0]),"06"==a.substr(d[1],2)&&(b.algparam=ASN1HEX.getHexOfV_AtObj(a,d[1])),"04"!=a.substr(c[2],2))throw"malformed PKCS8 private key(code:006)";return b.keyidx=ASN1HEX.getStartPosOfV_AtObj(a,c[2]),b},getKeyFromPlainPrivatePKCS8PEM:function(a){var b=this.getHexFromPEM(a,"PRIVATE KEY"),c=this.getKeyFromPlainPrivatePKCS8Hex(b);return c},getKeyFromPlainPrivatePKCS8Hex:function(a){var b=this.parsePlainPrivatePKCS8Hex(a);if("2a864886f70d010101"==b.algoid){this.parsePrivateRawRSAKeyHexAtObj(a,b);var c=b.key,d=new RSAKey;return d.setPrivateEx(c.n,c.e,c.d,c.p,c.q,c.dp,c.dq,c.co),d}if("2a8648ce3d0201"==b.algoid){if(this.parsePrivateRawECKeyHexAtObj(a,b),void 0===KJUR.crypto.OID.oidhex2name[b.algparam])throw"KJUR.crypto.OID.oidhex2name undefined: "+b.algparam;var e=KJUR.crypto.OID.oidhex2name[b.algparam],d=new KJUR.crypto.ECDSA({curve:e});return d.setPublicKeyHex(b.pubkey),d.setPrivateKeyHex(b.key),d.isPublic=!1,d}if("2a8648ce380401"==b.algoid){var f=ASN1HEX.getVbyList(a,0,[1,1,0],"02"),g=ASN1HEX.getVbyList(a,0,[1,1,1],"02"),h=ASN1HEX.getVbyList(a,0,[1,1,2],"02"),i=ASN1HEX.getVbyList(a,0,[2,0],"02"),j=new BigInteger(f,16),k=new BigInteger(g,16),l=new BigInteger(h,16),m=new BigInteger(i,16),d=new KJUR.crypto.DSA;return d.setPrivate(j,k,l,null,m),d}throw"unsupported private key algorithm"},getRSAKeyFromPublicPKCS8PEM:function(a){var b=this.getHexFromPEM(a,"PUBLIC KEY"),c=this.getRSAKeyFromPublicPKCS8Hex(b);return c},getKeyFromPublicPKCS8PEM:function(a){var b=this.getHexFromPEM(a,"PUBLIC KEY"),c=this.getKeyFromPublicPKCS8Hex(b);return c},getKeyFromPublicPKCS8Hex:function(a){var b=this.parsePublicPKCS8Hex(a);if("2a864886f70d010101"==b.algoid){var c=this.parsePublicRawRSAKeyHex(b.key),d=new RSAKey;return d.setPublic(c.n,c.e),d}if("2a8648ce3d0201"==b.algoid){if(void 0===KJUR.crypto.OID.oidhex2name[b.algparam])throw"KJUR.crypto.OID.oidhex2name undefined: "+b.algparam;var e=KJUR.crypto.OID.oidhex2name[b.algparam],d=new KJUR.crypto.ECDSA({curve:e,pub:b.key});return d}if("2a8648ce380401"==b.algoid){var f=b.algparam,g=ASN1HEX.getHexOfV_AtObj(b.key,0),d=new KJUR.crypto.DSA;return d.setPublic(new BigInteger(f.p,16),new BigInteger(f.q,16),new BigInteger(f.g,16),new BigInteger(g,16)),d}throw"unsupported public key algorithm"},parsePublicRawRSAKeyHex:function(a){var b={};if("30"!=a.substr(0,2))throw"malformed RSA key(code:001)";var c=ASN1HEX.getPosArrayOfChildren_AtObj(a,0);if(2!=c.length)throw"malformed RSA key(code:002)";if("02"!=a.substr(c[0],2))throw"malformed RSA key(code:003)";if(b.n=ASN1HEX.getHexOfV_AtObj(a,c[0]),"02"!=a.substr(c[1],2))throw"malformed RSA key(code:004)";return b.e=ASN1HEX.getHexOfV_AtObj(a,c[1]),b},parsePrivateRawRSAKeyHexAtObj:function(a,b){var c=b.keyidx;if("30"!=a.substr(c,2))throw"malformed RSA private key(code:001)";var d=ASN1HEX.getPosArrayOfChildren_AtObj(a,c);if(9!=d.length)throw"malformed RSA private key(code:002)";b.key={},b.key.n=ASN1HEX.getHexOfV_AtObj(a,d[1]),b.key.e=ASN1HEX.getHexOfV_AtObj(a,d[2]),b.key.d=ASN1HEX.getHexOfV_AtObj(a,d[3]),b.key.p=ASN1HEX.getHexOfV_AtObj(a,d[4]),b.key.q=ASN1HEX.getHexOfV_AtObj(a,d[5]),b.key.dp=ASN1HEX.getHexOfV_AtObj(a,d[6]),b.key.dq=ASN1HEX.getHexOfV_AtObj(a,d[7]),b.key.co=ASN1HEX.getHexOfV_AtObj(a,d[8])},parsePrivateRawECKeyHexAtObj:function(a,b){var c=b.keyidx,d=ASN1HEX.getVbyList(a,c,[1],"04"),e=ASN1HEX.getVbyList(a,c,[2,0],"03").substr(2);b.key=d,b.pubkey=e},parsePublicPKCS8Hex:function(a){var b={};b.algparam=null;var c=ASN1HEX.getPosArrayOfChildren_AtObj(a,0);if(2!=c.length)throw"outer DERSequence shall have 2 elements: "+c.length;var d=c[0];if("30"!=a.substr(d,2))throw"malformed PKCS8 public key(code:001)";var e=ASN1HEX.getPosArrayOfChildren_AtObj(a,d);if(2!=e.length)throw"malformed PKCS8 public key(code:002)";if("06"!=a.substr(e[0],2))throw"malformed PKCS8 public key(code:003)";if(b.algoid=ASN1HEX.getHexOfV_AtObj(a,e[0]),"06"==a.substr(e[1],2)?b.algparam=ASN1HEX.getHexOfV_AtObj(a,e[1]):"30"==a.substr(e[1],2)&&(b.algparam={},b.algparam.p=ASN1HEX.getVbyList(a,e[1],[0],"02"),b.algparam.q=ASN1HEX.getVbyList(a,e[1],[1],"02"),b.algparam.g=ASN1HEX.getVbyList(a,e[1],[2],"02")),"03"!=a.substr(c[1],2))throw"malformed PKCS8 public key(code:004)";return b.key=ASN1HEX.getHexOfV_AtObj(a,c[1]).substr(2),b},getRSAKeyFromPublicPKCS8Hex:function(a){var b=ASN1HEX.getPosArrayOfChildren_AtObj(a,0);if(2!=b.length)throw"outer DERSequence shall have 2 elements: "+b.length;var c=ASN1HEX.getHexOfTLV_AtObj(a,b[0]);if("300d06092a864886f70d0101010500"!=c)throw"PKCS8 AlgorithmId is not rsaEncryption";if("03"!=a.substr(b[1],2))throw"PKCS8 Public Key is not BITSTRING encapslated.";var d=ASN1HEX.getStartPosOfV_AtObj(a,b[1])+2;if("30"!=a.substr(d,2))throw"PKCS8 Public Key is not SEQUENCE.";var e=ASN1HEX.getPosArrayOfChildren_AtObj(a,d);if(2!=e.length)throw"inner DERSequence shall have 2 elements: "+e.length;if("02"!=a.substr(e[0],2))throw"N is not ASN.1 INTEGER";if("02"!=a.substr(e[1],2))throw"E is not ASN.1 INTEGER";var f=ASN1HEX.getHexOfV_AtObj(a,e[0]),g=ASN1HEX.getHexOfV_AtObj(a,e[1]),h=new RSAKey;return h.setPublic(f,g),h}}}();KEYUTIL.getKey=function(a,b,c){if("undefined"!=typeof RSAKey&&a instanceof RSAKey)return a;if("undefined"!=typeof KJUR.crypto.ECDSA&&a instanceof KJUR.crypto.ECDSA)return a;if("undefined"!=typeof KJUR.crypto.DSA&&a instanceof KJUR.crypto.DSA)return a;if(void 0!==a.curve&&void 0!==a.xy&&void 0===a.d)return new KJUR.crypto.ECDSA({pub:a.xy,curve:a.curve});if(void 0!==a.curve&&void 0!==a.d)return new KJUR.crypto.ECDSA({prv:a.d,curve:a.curve});if(void 0===a.kty&&void 0!==a.n&&void 0!==a.e&&void 0===a.d){var d=new RSAKey;return d.setPublic(a.n,a.e),d}if(void 0===a.kty&&void 0!==a.n&&void 0!==a.e&&void 0!==a.d&&void 0!==a.p&&void 0!==a.q&&void 0!==a.dp&&void 0!==a.dq&&void 0!==a.co&&void 0===a.qi){var d=new RSAKey;return d.setPrivateEx(a.n,a.e,a.d,a.p,a.q,a.dp,a.dq,a.co),d}if(void 0===a.kty&&void 0!==a.n&&void 0!==a.e&&void 0!==a.d&&void 0===a.p){var d=new RSAKey;return d.setPrivate(a.n,a.e,a.d),d}if(void 0!==a.p&&void 0!==a.q&&void 0!==a.g&&void 0!==a.y&&void 0===a.x){var d=new KJUR.crypto.DSA;return d.setPublic(a.p,a.q,a.g,a.y),d}if(void 0!==a.p&&void 0!==a.q&&void 0!==a.g&&void 0!==a.y&&void 0!==a.x){var d=new KJUR.crypto.DSA;return d.setPrivate(a.p,a.q,a.g,a.y,a.x),d}if("RSA"===a.kty&&void 0!==a.n&&void 0!==a.e&&void 0===a.d){var d=new RSAKey;return d.setPublic(b64utohex(a.n),b64utohex(a.e)),d}if("RSA"===a.kty&&void 0!==a.n&&void 0!==a.e&&void 0!==a.d&&void 0!==a.p&&void 0!==a.q&&void 0!==a.dp&&void 0!==a.dq&&void 0!==a.qi){var d=new RSAKey;return d.setPrivateEx(b64utohex(a.n),b64utohex(a.e),b64utohex(a.d),b64utohex(a.p),b64utohex(a.q),b64utohex(a.dp),b64utohex(a.dq),b64utohex(a.qi)),d}if("RSA"===a.kty&&void 0!==a.n&&void 0!==a.e&&void 0!==a.d){var d=new RSAKey;return d.setPrivate(b64utohex(a.n),b64utohex(a.e),b64utohex(a.d)),d}if("EC"===a.kty&&void 0!==a.crv&&void 0!==a.x&&void 0!==a.y&&void 0===a.d){var e=new KJUR.crypto.ECDSA({curve:a.crv}),f=e.ecparams.keylen/4,g=("0000000000"+b64utohex(a.x)).slice(-f),h=("0000000000"+b64utohex(a.y)).slice(-f),i="04"+g+h;return e.setPublicKeyHex(i),e}if("EC"===a.kty&&void 0!==a.crv&&void 0!==a.x&&void 0!==a.y&&void 0!==a.d){var e=new KJUR.crypto.ECDSA({curve:a.crv}),f=e.ecparams.keylen/4,g=("0000000000"+b64utohex(a.x)).slice(-f),h=("0000000000"+b64utohex(a.y)).slice(-f),i="04"+g+h,j=("0000000000"+b64utohex(a.d)).slice(-f);return e.setPublicKeyHex(i),e.setPrivateKeyHex(j),e}if(a.indexOf("-END CERTIFICATE-",0)!=-1||a.indexOf("-END X509 CERTIFICATE-",0)!=-1||a.indexOf("-END TRUSTED CERTIFICATE-",0)!=-1)return X509.getPublicKeyFromCertPEM(a);if("pkcs8pub"===c)return KEYUTIL.getKeyFromPublicPKCS8Hex(a);if(a.indexOf("-END PUBLIC KEY-")!=-1)return KEYUTIL.getKeyFromPublicPKCS8PEM(a);if("pkcs5prv"===c){var d=new RSAKey;return d.readPrivateKeyFromASN1HexString(a),d}if("pkcs5prv"===c){var d=new RSAKey;return d.readPrivateKeyFromASN1HexString(a),d}if(a.indexOf("-END RSA PRIVATE KEY-")!=-1&&a.indexOf("4,ENCRYPTED")==-1){var k=KEYUTIL.getHexFromPEM(a,"RSA PRIVATE KEY");return KEYUTIL.getKey(k,null,"pkcs5prv")}if(a.indexOf("-END DSA PRIVATE KEY-")!=-1&&a.indexOf("4,ENCRYPTED")==-1){var l=this.getHexFromPEM(a,"DSA PRIVATE KEY"),m=ASN1HEX.getVbyList(l,0,[1],"02"),n=ASN1HEX.getVbyList(l,0,[2],"02"),o=ASN1HEX.getVbyList(l,0,[3],"02"),p=ASN1HEX.getVbyList(l,0,[4],"02"),q=ASN1HEX.getVbyList(l,0,[5],"02"),d=new KJUR.crypto.DSA;return d.setPrivate(new BigInteger(m,16),new BigInteger(n,16),new BigInteger(o,16),new BigInteger(p,16),new BigInteger(q,16)),d}if(a.indexOf("-END PRIVATE KEY-")!=-1)return KEYUTIL.getKeyFromPlainPrivatePKCS8PEM(a);if(a.indexOf("-END RSA PRIVATE KEY-")!=-1&&a.indexOf("4,ENCRYPTED")!=-1)return KEYUTIL.getRSAKeyFromEncryptedPKCS5PEM(a,b);if(a.indexOf("-END EC PRIVATE KEY-")!=-1&&a.indexOf("4,ENCRYPTED")!=-1){var l=KEYUTIL.getDecryptedKeyHex(a,b),d=ASN1HEX.getVbyList(l,0,[1],"04"),r=ASN1HEX.getVbyList(l,0,[2,0],"06"),s=ASN1HEX.getVbyList(l,0,[3,0],"03").substr(2),t="";if(void 0===KJUR.crypto.OID.oidhex2name[r])throw"undefined OID(hex) in KJUR.crypto.OID: "+r;t=KJUR.crypto.OID.oidhex2name[r];var e=new KJUR.crypto.ECDSA({name:t});return e.setPublicKeyHex(s),e.setPrivateKeyHex(d),e.isPublic=!1,e}if(a.indexOf("-END DSA PRIVATE KEY-")!=-1&&a.indexOf("4,ENCRYPTED")!=-1){var l=KEYUTIL.getDecryptedKeyHex(a,b),m=ASN1HEX.getVbyList(l,0,[1],"02"),n=ASN1HEX.getVbyList(l,0,[2],"02"),o=ASN1HEX.getVbyList(l,0,[3],"02"),p=ASN1HEX.getVbyList(l,0,[4],"02"),q=ASN1HEX.getVbyList(l,0,[5],"02"),d=new KJUR.crypto.DSA;return d.setPrivate(new BigInteger(m,16),new BigInteger(n,16),new BigInteger(o,16),new BigInteger(p,16),new BigInteger(q,16)),d}if(a.indexOf("-END ENCRYPTED PRIVATE KEY-")!=-1)return KEYUTIL.getKeyFromEncryptedPKCS8PEM(a,b);throw"not supported argument"},KEYUTIL.generateKeypair=function(a,b){if("RSA"==a){var c=b,d=new RSAKey;d.generate(c,"10001"),d.isPrivate=!0,d.isPublic=!0;var e=new RSAKey,f=d.n.toString(16),g=d.e.toString(16);e.setPublic(f,g),e.isPrivate=!1,e.isPublic=!0;var h={};return h.prvKeyObj=d,h.pubKeyObj=e,h}if("EC"==a){var i=b,j=new KJUR.crypto.ECDSA({curve:i}),k=j.generateKeyPairHex(),d=new KJUR.crypto.ECDSA({curve:i});d.setPublicKeyHex(k.ecpubhex),d.setPrivateKeyHex(k.ecprvhex),d.isPrivate=!0,d.isPublic=!1;var e=new KJUR.crypto.ECDSA({curve:i});e.setPublicKeyHex(k.ecpubhex),e.isPrivate=!1,e.isPublic=!0;var h={};return h.prvKeyObj=d,h.pubKeyObj=e,h}throw"unknown algorithm: "+a},KEYUTIL.getPEM=function(a,b,c,d,e){function h(a){var b=KJUR.asn1.ASN1Util.newObject({seq:[{int:0},{int:{bigint:a.n}},{int:a.e},{int:{bigint:a.d}},{int:{bigint:a.p}},{int:{bigint:a.q}},{int:{bigint:a.dmp1}},{int:{bigint:a.dmq1}},{int:{bigint:a.coeff}}]});return b}function i(a){var b=KJUR.asn1.ASN1Util.newObject({seq:[{int:1},{octstr:{hex:a.prvKeyHex}},{tag:["a0",!0,{oid:{name:a.curveName}}]},{tag:["a1",!0,{bitstr:{hex:"00"+a.pubKeyHex}}]}]});return b}function j(a){var b=KJUR.asn1.ASN1Util.newObject({seq:[{int:0},{int:{bigint:a.p}},{int:{bigint:a.q}},{int:{bigint:a.g}},{int:{bigint:a.y}},{int:{bigint:a.x}}]});return b}var f=KJUR.asn1,g=KJUR.crypto;if(("undefined"!=typeof RSAKey&&a instanceof RSAKey||"undefined"!=typeof g.DSA&&a instanceof g.DSA||"undefined"!=typeof g.ECDSA&&a instanceof g.ECDSA)&&1==a.isPublic&&(void 0===b||"PKCS8PUB"==b)){var k=new KJUR.asn1.x509.SubjectPublicKeyInfo(a),l=k.getEncodedHex();return f.ASN1Util.getPEMStringFromHex(l,"PUBLIC KEY")}if("PKCS1PRV"==b&&"undefined"!=typeof RSAKey&&a instanceof RSAKey&&(void 0===c||null==c)&&1==a.isPrivate){var k=h(a),l=k.getEncodedHex();return f.ASN1Util.getPEMStringFromHex(l,"RSA PRIVATE KEY")}if("PKCS1PRV"==b&&"undefined"!=typeof RSAKey&&a instanceof KJUR.crypto.ECDSA&&(void 0===c||null==c)&&1==a.isPrivate){var m=new KJUR.asn1.DERObjectIdentifier({name:a.curveName}),n=m.getEncodedHex(),o=i(a),p=o.getEncodedHex(),q="";return q+=f.ASN1Util.getPEMStringFromHex(n,"EC PARAMETERS"),q+=f.ASN1Util.getPEMStringFromHex(p,"EC PRIVATE KEY")}if("PKCS1PRV"==b&&"undefined"!=typeof KJUR.crypto.DSA&&a instanceof KJUR.crypto.DSA&&(void 0===c||null==c)&&1==a.isPrivate){var k=j(a),l=k.getEncodedHex();return f.ASN1Util.getPEMStringFromHex(l,"DSA PRIVATE KEY")}if("PKCS5PRV"==b&&"undefined"!=typeof RSAKey&&a instanceof RSAKey&&void 0!==c&&null!=c&&1==a.isPrivate){var k=h(a),l=k.getEncodedHex();return void 0===d&&(d="DES-EDE3-CBC"),this.getEncryptedPKCS5PEMFromPrvKeyHex("RSA",l,c,d)}if("PKCS5PRV"==b&&"undefined"!=typeof KJUR.crypto.ECDSA&&a instanceof KJUR.crypto.ECDSA&&void 0!==c&&null!=c&&1==a.isPrivate){var k=i(a),l=k.getEncodedHex();return void 0===d&&(d="DES-EDE3-CBC"),this.getEncryptedPKCS5PEMFromPrvKeyHex("EC",l,c,d)}if("PKCS5PRV"==b&&"undefined"!=typeof KJUR.crypto.DSA&&a instanceof KJUR.crypto.DSA&&void 0!==c&&null!=c&&1==a.isPrivate){var k=j(a),l=k.getEncodedHex();return void 0===d&&(d="DES-EDE3-CBC"),this.getEncryptedPKCS5PEMFromPrvKeyHex("DSA",l,c,d)}var r=function(a,b){var c=s(a,b),d=new KJUR.asn1.ASN1Util.newObject({seq:[{seq:[{oid:{name:"pkcs5PBES2"}},{seq:[{seq:[{oid:{name:"pkcs5PBKDF2"}},{seq:[{octstr:{hex:c.pbkdf2Salt}},{int:c.pbkdf2Iter}]}]},{seq:[{oid:{name:"des-EDE3-CBC"}},{octstr:{hex:c.encryptionSchemeIV}}]}]}]},{octstr:{hex:c.ciphertext}}]});return d.getEncodedHex()},s=function(a,b){var c=100,d=CryptoJS.lib.WordArray.random(8),e="DES-EDE3-CBC",f=CryptoJS.lib.WordArray.random(8),g=CryptoJS.PBKDF2(b,d,{keySize:6,iterations:c}),h=CryptoJS.enc.Hex.parse(a),i=CryptoJS.TripleDES.encrypt(h,g,{iv:f})+"",j={};return j.ciphertext=i,j.pbkdf2Salt=CryptoJS.enc.Hex.stringify(d),j.pbkdf2Iter=c,j.encryptionSchemeAlg=e,j.encryptionSchemeIV=CryptoJS.enc.Hex.stringify(f),j};if("PKCS8PRV"==b&&"undefined"!=typeof RSAKey&&a instanceof RSAKey&&1==a.isPrivate){var t=h(a),u=t.getEncodedHex(),k=KJUR.asn1.ASN1Util.newObject({seq:[{int:0},{seq:[{oid:{name:"rsaEncryption"}},{null:!0}]},{octstr:{hex:u}}]}),l=k.getEncodedHex();if(void 0===c||null==c)return f.ASN1Util.getPEMStringFromHex(l,"PRIVATE KEY");var p=r(l,c);return f.ASN1Util.getPEMStringFromHex(p,"ENCRYPTED PRIVATE KEY")}if("PKCS8PRV"==b&&"undefined"!=typeof KJUR.crypto.ECDSA&&a instanceof KJUR.crypto.ECDSA&&1==a.isPrivate){var t=new KJUR.asn1.ASN1Util.newObject({seq:[{int:1},{octstr:{hex:a.prvKeyHex}},{tag:["a1",!0,{bitstr:{hex:"00"+a.pubKeyHex}}]}]}),u=t.getEncodedHex(),k=KJUR.asn1.ASN1Util.newObject({seq:[{int:0},{seq:[{oid:{name:"ecPublicKey"}},{oid:{name:a.curveName}}]},{octstr:{hex:u}}]}),l=k.getEncodedHex();if(void 0===c||null==c)return f.ASN1Util.getPEMStringFromHex(l,"PRIVATE KEY");var p=r(l,c);return f.ASN1Util.getPEMStringFromHex(p,"ENCRYPTED PRIVATE KEY")}if("PKCS8PRV"==b&&"undefined"!=typeof KJUR.crypto.DSA&&a instanceof KJUR.crypto.DSA&&1==a.isPrivate){var t=new KJUR.asn1.DERInteger({bigint:a.x}),u=t.getEncodedHex(),k=KJUR.asn1.ASN1Util.newObject({seq:[{int:0},{seq:[{oid:{name:"dsa"}},{seq:[{int:{bigint:a.p}},{int:{bigint:a.q}},{int:{bigint:a.g}}]}]},{octstr:{hex:u}}]}),l=k.getEncodedHex();if(void 0===c||null==c)return f.ASN1Util.getPEMStringFromHex(l,"PRIVATE KEY");var p=r(l,c);return f.ASN1Util.getPEMStringFromHex(p,"ENCRYPTED PRIVATE KEY")}throw"unsupported object nor format"},KEYUTIL.getKeyFromCSRPEM=function(a){var b=KEYUTIL.getHexFromPEM(a,"CERTIFICATE REQUEST"),c=KEYUTIL.getKeyFromCSRHex(b);return c},KEYUTIL.getKeyFromCSRHex=function(a){var b=KEYUTIL.parseCSRHex(a),c=KEYUTIL.getKey(b.p8pubkeyhex,null,"pkcs8pub");return c},KEYUTIL.parseCSRHex=function(a){var b={},c=a;if("30"!=c.substr(0,2))throw"malformed CSR(code:001)";var d=ASN1HEX.getPosArrayOfChildren_AtObj(c,0);if(d.length<1)throw"malformed CSR(code:002)";if("30"!=c.substr(d[0],2))throw"malformed CSR(code:003)";var e=ASN1HEX.getPosArrayOfChildren_AtObj(c,d[0]);if(e.length<3)throw"malformed CSR(code:004)";return b.p8pubkeyhex=ASN1HEX.getHexOfTLV_AtObj(c,e[2]),b},KEYUTIL.getJWKFromKey=function(a){var b={};if(a instanceof RSAKey&&a.isPrivate)return b.kty="RSA",b.n=hextob64u(a.n.toString(16)),b.e=hextob64u(a.e.toString(16)),b.d=hextob64u(a.d.toString(16)),b.p=hextob64u(a.p.toString(16)),b.q=hextob64u(a.q.toString(16)),b.dp=hextob64u(a.dmp1.toString(16)),b.dq=hextob64u(a.dmq1.toString(16)),b.qi=hextob64u(a.coeff.toString(16)),b;if(a instanceof RSAKey&&a.isPublic)return b.kty="RSA",b.n=hextob64u(a.n.toString(16)),b.e=hextob64u(a.e.toString(16)),b;if(a instanceof KJUR.crypto.ECDSA&&a.isPrivate){var c=a.getShortNISTPCurveName();if("P-256"!==c&&"P-384"!==c)throw"unsupported curve name for JWT: "+c;var d=a.getPublicKeyXYHex();return b.kty="EC",b.crv=c,b.x=hextob64u(d.x),b.y=hextob64u(d.y),b.d=hextob64u(a.prvKeyHex),b}if(a instanceof KJUR.crypto.ECDSA&&a.isPublic){var c=a.getShortNISTPCurveName();if("P-256"!==c&&"P-384"!==c)throw"unsupported curve name for JWT: "+c;var d=a.getPublicKeyXYHex();return b.kty="EC",b.crv=c,b.x=hextob64u(d.x),b.y=hextob64u(d.y),b}throw"not supported key object"};
