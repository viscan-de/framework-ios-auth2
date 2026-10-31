//
//  OAuth2Base.swift
//  OAuth2
//
//  Created by Pascal Pfiffner on 6/4/14.
//  Copyright 2014 Pascal Pfiffner
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

import Foundation
import CommonCrypto


/**
Class extending on OAuth2Requestable, exposing configuration and maintaining context, serving as base class for `OAuth2`.
*/
open class OAuth2Base: OAuth2Securable {
	
	/// The grant type represented by the class, e.g. "authorization_code" for code grants.
	open class var grantType: String {
		return "__undefined"
	}
	
	/// The response type expected from an authorize call, e.g. "code" for code grants.
	open class var responseType: String? {
		return nil
	}
	
	/// Settings related to the client-server relationship.
	public let clientConfig: OAuth2ClientConfig
	
	/// Client-side authorization options.
	open var authConfig = OAuth2AuthConfig()
	
	/// The client id.
	public final var clientId: String? {
		get { return clientConfig.clientId }
		set { clientConfig.clientId = newValue }
	}
	
	/// The client secret, usually only needed for code grant.
	public final var clientSecret: String? {
		get { return clientConfig.clientSecret }
		set { clientConfig.clientSecret = newValue }
	}
	
	/// The name of the client, as used during dynamic client registration. Use "client_name" during initialization to set.
	open var clientName: String? {
		get { return clientConfig.clientName }
	}
	
	/// The URL to authorize against.
	public final var authURL: URL {
		get { return clientConfig.authorizeURL }
	}
    
	/// The URL to obtain the device code.
	public final var deviceAuthorizeURL: URL? {
		get { return clientConfig.deviceAuthorizeURL }
	}

	/// The URL string where we can exchange a code for a token; if nil `authURL` will be used.
	public final var tokenURL: URL? {
		get { return clientConfig.tokenURL }
	}
	
	/// The scope currently in use.
	public final var scope: String? {
		get { return clientConfig.scope }
		set { clientConfig.scope = newValue }
	}
	
	/// The redirect URL string to use.
	public final var redirect: String? {
		get { return clientConfig.redirect }
		set { clientConfig.redirect = newValue }
	}
	
	/// Context for the current auth dance.
	open var context = OAuth2ContextStore()
	
	/// The receiver's access token.
	open var accessToken: String? {
		get { return clientConfig.accessToken }
		set { clientConfig.accessToken = newValue }
	}
	
	/// The receiver's id token.
	open var idToken: String? {
		get { return clientConfig.idToken }	
		set { clientConfig.idToken = newValue }
	}

	/// The access token's expiry date.
	open var accessTokenExpiry: Date? {
		get { return clientConfig.accessTokenExpiry }
		set { clientConfig.accessTokenExpiry = newValue }
	}
	
	/// The receiver's long-time refresh token.
	open var refreshToken: String? {
		get { return clientConfig.refreshToken }
		set { clientConfig.refreshToken = newValue }
	}
	
	/// Custom or overridden HTML headers to be used during authorization.
	public var authHeaders: OAuth2Headers? {
		get { return clientConfig.authHeaders }
		set { clientConfig.authHeaders = newValue }
	}
	
	/// Custom authorization parameters.
	public var authParameters: OAuth2StringDict? {
		get { return clientConfig.customParameters }
		set { clientConfig.customParameters = newValue }
	}

	/// The optional User-Agent string to use for embedded mode.
	public final var customUserAgent: String? {
		get { return clientConfig.customUserAgent }
		set { clientConfig.customUserAgent = newValue }
	}
	
	
	/// This closure is internally used with `authorize(params:callback:)` and only exposed for subclassing reason, do not mess with it!
	///
	/// Setting it starts an authorization with an identity of its own, `currentAuthorization`; clearing it ends that.
	public final var didAuthorizeOrFail: ((_ parameters: OAuth2JSON?, _ error: OAuth2Error?) -> Void)? {
		didSet {
			let starts = (nil != didAuthorizeOrFail)
			authorizationLock.lock()
			_currentAuthorization = starts ? OAuth2AuthorizationID(serial: nextSerial()) : nil
			authorizationLock.unlock()
		}
	}
	
	/// Returns true if the receiver is currently authorizing.
	public final var isAuthorizing: Bool {
		return nil != didAuthorizeOrFail
	}
	
	/// Guards `_currentAuthorization`, `_presentation` and `lastSerial`. An authorization can start on any thread (`OAuth2DataLoader`
	/// starts one from a URL session's queue), its requests answer on theirs, and its sign-in screens live on the main thread.
	private let authorizationLock = NSLock()
	
	/// Backs `currentAuthorization`. Only touch while holding `authorizationLock`.
	private var _currentAuthorization: OAuth2AuthorizationID?
	
	/// The sign-in screen registered with `beginPresentation(dismiss:)`, with the closure that takes it down. Only touch while holding
	/// `authorizationLock`.
	private var _presentation: (id: OAuth2PresentationID, dismiss: () -> Void)?
	
	/// The last serial handed to an authorization or a presentation. Only touch while holding `authorizationLock`.
	private var lastSerial: UInt64 = 0
	
	/// Only call while holding `authorizationLock`.
	private func nextSerial() -> UInt64 {
		lastSerial += 1
		return lastSerial
	}
	
	/// The authorization in progress, nil while none is.
	public final var currentAuthorization: OAuth2AuthorizationID? {
		authorizationLock.lock()
		defer { authorizationLock.unlock() }
		return _currentAuthorization
	}
	
	/**
	Whether `authorization` is still the authorization in progress.
	
	- parameter authorization: What `currentAuthorization` was when the work asking started; work started while no authorization was
	                           in progress stays current until one starts
	*/
	public final func isCurrentAuthorization(_ authorization: OAuth2AuthorizationID?) -> Bool {
		return currentAuthorization == authorization
	}
	
	/**
	Whether a sign-in screen that an authorizer registered with `beginPresentation(dismiss:)` is up for the authorization in progress.
	
	`OAuth2Authorizer` registers its embedded screens. The `ASWebAuthenticationSession` sheet counts until it completes, so not during
	the token exchange that follows. The Safari view controller, the web view controller and the macOS web view window or sheet stay up
	during the token exchange and count until the user closes them or the authorization ends. Once the authorization has ended none
	counts, even a screen the caller has yet to dismiss because `authorizeEmbeddedAutoDismiss` is off.
	
	Not covered: the system browser (`openAuthorizeURLInBrowser(_:)`), whose closing the library cannot see, and the password grant's
	login controller, presented by `OAuth2CustomAuthorizerUI`.
	*/
	public final var isPresentingAuthorization: Bool {
		authorizationLock.lock()
		defer { authorizationLock.unlock() }
		guard let presentation = _presentation else {
			return false
		}
		return presentation.id.authorization == _currentAuthorization
	}
	
	/**
	For authorizers: registers the sign-in screen about to be presented for the authorization in progress, with the closure that takes it
	down.
	
	When that authorization ends, in `didAuthorize(withParameters:)`, `didFail(with:)` or `abortAuthorization()`, `dismiss` runs on the
	main thread, so no screen outlives its authorization. There is only ever one screen: one still registered is dismissed first.
	
	Before acting on anything the screen reports, check `isCurrentPresentation(_:)`. When the screen closes by itself, call
	`endPresentation(_:)`.
	
	- parameter dismiss: Takes the screen down, as far as the authorizer owns that, and lets go of what the authorizer holds for it
	- returns:           The screen's identity
	*/
	public final func beginPresentation(dismiss: @escaping () -> Void) -> OAuth2PresentationID {
		authorizationLock.lock()
		let previous = _presentation
		let presentation = OAuth2PresentationID(serial: nextSerial(), authorization: _currentAuthorization)
		_presentation = (presentation, dismiss)
		authorizationLock.unlock()
		if let previous = previous {
			callOnMainThread() {
				previous.dismiss()
			}
		}
		return presentation
	}
	
	/**
	Whether what `presentation` reports still counts: it is still the registered screen, and the authorization it was presented for is
	still in progress. A screen whose authorization has ended has been dismissed, and its late callbacks are nobody's answer.
	*/
	public final func isCurrentPresentation(_ presentation: OAuth2PresentationID) -> Bool {
		authorizationLock.lock()
		defer { authorizationLock.unlock() }
		return _presentation?.id == presentation && _currentAuthorization == presentation.authorization
	}
	
	/**
	For authorizers: the screen closed by itself, or never came up, so there is nothing left to take down. Does nothing if `presentation`
	is no longer the registered screen.
	*/
	public final func endPresentation(_ presentation: OAuth2PresentationID) {
		authorizationLock.lock()
		defer { authorizationLock.unlock() }
		if _presentation?.id == presentation {
			_presentation = nil
		}
	}
	
	/**
	Ends the authorization in progress: it loses its identity, so its work's late answers are dropped; its state is retired, so the next
	authorization sends another and a late redirect carrying this one is recognized (`isLateRedirect(_:)`); and the screen presented for
	it is taken down. Main thread.
	*/
	private func retireCurrentAuthorization() {
		authorizationLock.lock()
		_currentAuthorization = nil
		let presentation = _presentation
		_presentation = nil
		authorizationLock.unlock()
		context.retireState()
		presentation?.dismiss()
	}
	
	/**
	Whether a redirect's parameters carry the state of an authorization that has ended: a late redirect, which answers nobody and is
	dropped rather than failing the authorization in progress. A redirect carrying a state that was never issued is not one; it fails as
	`.invalidState`.
	
	- parameter params: The redirect's query or fragment parameters
	*/
	public final func isLateRedirect(_ params: OAuth2JSON) -> Bool {
		guard let state = params["state"] as? String, !state.isEmpty else {
			return false
		}
		return !context.matchesState(state) && context.wasRetired(state)
	}
	
	/**
	Closure called after the regular authorization callback, on the main thread. You can use this callback when you're performing
	authorization manually and/or for cleanup operations.
	
	- parameter authParameters: All authorization parameters; non-nil (but possibly empty) on success, nil on error
	- parameter error:          OAuth2Error giving the failure reason; if nil and `authParameters` is also nil, the process was aborted.
	*/
	public final var afterAuthorizeOrFail: ((_ authParameters: OAuth2JSON?, _ error: OAuth2Error?) -> Void)?
	
	/**
	For internal use, don't mess with it, it's public only for subclassing and compilation reasons. Executed once the authorization has
	ended, before the authorization callback and
	`afterAuthorizeOrFail`.
	*/
	public final var internalAfterAuthorizeOrFail: ((_ wasFailure: Bool, _ error: OAuth2Error?) -> Void)?
	
	
	/**
	Designated initializer.
	
	The following settings keys are currently supported:
	
	- client_id (String)
	- client_secret (String), usually only needed for code grant
	- authorize_uri (URL-String)
	- token_uri (URL-String), if omitted the authorize_uri will be used to obtain tokens
	- refresh_uri (URL-String), if omitted the token_uri will be used to obtain tokens
	- redirect_uris (Array of URL-Strings)
	- scope (String)
	- custom_user_agent (String)

	- client_name (String)
	- registration_uri (URL-String)
	- logo_uri (URL-String)
	
	- keychain (Bool, true by default, applies to using the system keychain)
	- keychain_access_mode (String, value for keychain kSecAttrAccessible attribute, kSecAttrAccessibleWhenUnlocked by default)
	- keychain_access_group (String, value for keychain kSecAttrAccessGroup attribute, nil by default)
	- keychain_account_for_client_credentials(String, "clientCredentials" by default)
	- keychain_account_for_tokens(String, "currentTokens" by default)
	- secret_in_body (Bool, false by default, forces the flow to use the request body for the client secret)
	- parameters ([String: String], custom request parameters to be added during authorization)
	- token_assume_unexpired (Bool, true by default, whether to use access tokens that do not come with an "expires_in" parameter)
	- use_pkce (Bool, false by default)
	
	- verbose (Bool, false by default, applies to client logging)
	*/
	override public init(settings: OAuth2JSON) {
		clientConfig = OAuth2ClientConfig(settings: settings)
		
		// auth configuration options
		if let ttl = settings["title"] as? String {
			authConfig.ui.title = ttl
		}
		super.init(settings: settings)
	}
	
	
	// MARK: - Keychain Integration
	
	/** Overrides base implementation to return the authorize URL. */
	override open func keychainServiceName() -> String {
		return authURL.description
	}
	
	override open func updateFromKeychainItems(_ items: [String: Any]) {
		for message in clientConfig.updateFromStorableItems(items) {
			logger?.debug("OAuth2", msg: message)
		}
		clientConfig.secretInBody = (clientConfig.endpointAuthMethod == OAuth2EndpointAuthMethod.clientSecretPost)
	}
	
	override open func storableCredentialItems() -> [String: Any]? {
		return clientConfig.storableCredentialItems()
	}
	
	override open func storableTokenItems() -> [String: Any]? {
		return clientConfig.storableTokenItems()
	}
	
	override open func forgetClient() {
		super.forgetClient()
		clientConfig.forgetCredentials()
	}
	
	override open func forgetTokens() {
		super.forgetTokens()
		clientConfig.forgetTokens()
	}
	
	
	// MARK: - Request Signing
	
	/**
	Return an OAuth2Request, a NSMutableURLRequest subclass, that has already been signed and can be used against your OAuth2 endpoint.
	
	This method by default ignores locally cached data and specifies a timeout interval of 20 seconds. This should be ideal for small JSON
	data requests, but you probably don't want to disable cache for binary data like avatars.
	
	- parameter forURL: The URL to create a request for
	- parameter cachePolicy: The cache policy to use, defaults to `NSURLRequestCachePolicy.ReloadIgnoringLocalCacheData`
	- returns: OAuth2Request for the given URL
	*/
	open func request(forURL url: URL, cachePolicy: NSURLRequest.CachePolicy = .reloadIgnoringLocalCacheData) -> URLRequest {
		var req = URLRequest(url: url, cachePolicy: cachePolicy, timeoutInterval: 20)
		try? req.sign(with: self)
		return req
	}
	
	
	// MARK: - Callbacks
	
	/**
	Subclasses override this method to extract information from the supplied redirect URL.
	
	- parameter redirect: The redirect URL returned by the server that you want to handle
	*/
	open func handleRedirectURL(_ redirect: URL) throws {
		throw OAuth2Error.generic("Abstract class use")
	}
	
	/**
	Internally used on success, calls the callbacks on the main thread.
	
	This method is only made public in case you want to create a subclass and call `didAuthorize(parameters:)` at an override point. If you
	call this method yourself on your OAuth2 instance you might screw things up badly.
	
	- parameter withParameters: The parameters received during authorization
	*/
	public final func didAuthorize(withParameters parameters: OAuth2JSON) {
		endAuthorization(.any, parameters: parameters, error: nil)
	}
	
	/**
	`didAuthorize(withParameters:)` for work that belongs to an authorization: does nothing if that authorization has ended meanwhile,
	so a late answer never ends a newer one.
	
	- parameter withParameters: The parameters received during authorization
	- parameter for:            What `currentAuthorization` was when the work started
	*/
	public final func didAuthorize(withParameters parameters: OAuth2JSON, for authorization: OAuth2AuthorizationID?) {
		endAuthorization(.only(authorization), parameters: parameters, error: nil)
	}
	
	/**
	Internally used on error, calls the callbacks on the main thread with the appropriate error message.
	
	This method is only made public in case you want to create a subclass and need to call `didFail(error:)` at an override point. If you
	call this method yourself on your OAuth2 instance you might screw things up royally.
	
	- parameter error: The error that led to authorization failure; will use `.requestCancelled` on the callbacks if nil is passed
	*/
	public final func didFail(with error: OAuth2Error?) {
		endAuthorization(.any, parameters: nil, error: error)
	}
	
	/**
	`didFail(with:)` for work that belongs to an authorization: does nothing if that authorization has ended meanwhile, so a late answer
	never ends a newer one.
	
	- parameter error: The error that led to authorization failure; will use `.requestCancelled` on the callbacks if nil is passed
	- parameter for:   What `currentAuthorization` was when the work started
	*/
	public final func didFail(with error: OAuth2Error?, for authorization: OAuth2AuthorizationID?) {
		endAuthorization(.only(authorization), parameters: nil, error: error)
	}
	
	/// Which authorization an answer may end.
	private enum AuthorizationScope {
		
		/// Whichever is in progress.
		case any
		
		/// Only this one, if it is still in progress.
		case only(OAuth2AuthorizationID?)
	}
	
	private func isInScope(_ scope: AuthorizationScope) -> Bool {
		switch scope {
		case .any:
			return true
		case .only(let authorization):
			return isCurrentAuthorization(authorization)
		}
	}
	
	/**
	Ends the authorization in scope with success (`parameters` non-nil) or failure, then calls the callbacks on the main thread.
	
	Checked twice: here, so a late success stores no tokens, and on the main thread, where authorizations start and end.
	*/
	private func endAuthorization(_ scope: AuthorizationScope, parameters: OAuth2JSON?, error: OAuth2Error?) {
		guard isInScope(scope) else {
			logger?.debug("OAuth2", msg: "Ignoring the answer of an authorization that has ended")
			return
		}
		let finalError: OAuth2Error?
		if nil != parameters {
			finalError = nil
			if useKeychain {
				storeTokensToKeychain()
			}
		}
		else if let error = error {
			finalError = error
			logger?.debug("OAuth2", msg: "\(error)")
		}
		else {
			finalError = OAuth2Error.requestCancelled
		}
		// Asynchronous off the main thread: a synchronous hop from a URL session's queue, or from a thread the main thread waits on,
		// deadlocks.
		callAsyncOnMainThread() {
			guard self.isInScope(scope) else {
				self.logger?.debug("OAuth2", msg: "Ignoring the answer of an authorization that has ended")
				return
			}
			// The authorization has fully ended before anyone hears of it: the callback may start the next one, or abort.
			let callback = self.didAuthorizeOrFail
			let internalAfter = self.internalAfterAuthorizeOrFail
			let after = self.afterAuthorizeOrFail
			self.didAuthorizeOrFail = nil
			self.retireCurrentAuthorization()
			internalAfter?(nil == parameters, finalError)
			callback?(parameters, finalError)
			after?(parameters, finalError)
		}
	}
	
	/**
	Allows to abort authorization currently in progress.
	
	Answers its callback with `.requestCancelled` and takes down the sign-in screen presented for it; the flows drop whatever its
	requests and that screen report later. Cancels the authorization's token requests, but never a refresh-token request: that one
	finishes and stores the tokens it receives, since the provider may already have rotated the refresh token. Does nothing when no
	authorization is in progress.
	
	Can be called on any thread: off the main thread it returns at once and answers on the main thread, so it never waits on it.
	*/
	open func abortAuthorization() {
		guard let authorization = currentAuthorization else {
			logger?.debug("OAuth2", msg: "No authorization in progress to abort")
			return
		}
		logger?.debug("OAuth2", msg: "Aborting authorization")
		_ = abortTasks(of: authorization)
		callAsyncOnMainThread {
			self.didFail(with: nil, for: authorization)
		}
	}
	
	/// Requests started now belong to the authorization in progress, so that aborting it cancels them and no other.
	override var authorizationOfNewRequests: OAuth2AuthorizationID? {
		return currentAuthorization
	}
	
	
	// MARK: - Response Parsing
	
	/**
	Handles access token error response.
	
	- parameter params: The URL parameters returned from the server
	- parameter fallback: The message string to use in case no error description is found in the parameters
	- returns: An OAuth2Error
	*/
	open func assureNoErrorInResponse(_ params: OAuth2JSON, fallback: String? = nil) throws {
		let err_code = params["error"] as? String
		let err_msg = params["error_description"] as? String

		// "error_description" is optional, we use it if it's present and code is not.
		if let message = err_msg, message.count > 0 && (err_code?.isEmpty ?? true) {
			throw OAuth2Error.responseError(message)
		}

		// the "error" response is required for error responses, so it should be present
		if let code = err_code, code.count > 0 {
			throw OAuth2Error.fromResponseError(code, description: err_msg, fallback: fallback)
		}
	}
	
	/**
	Parse response data returned while exchanging the code for a token.
	
	This method expects token data to be JSON, decodes JSON and fills the receiver's properties accordingly. If the response contains an
	"error" key, will parse the error and throw it.
	
	- parameter data: NSData returned from the call
	- returns:        An OAuth2JSON instance with token data; may contain additional information
	*/
	open func parseAccessTokenResponse(data: Data) throws -> OAuth2JSON {
		let dict = try parseJSON(data)
		return try parseAccessTokenResponse(params: dict)
	}
	
	/**
	Parse response data returned while exchanging the code for a token.
	
	This method extracts token data and fills the receiver's properties accordingly. If the response contains an "error" key, will parse the
	error and throw it. The method is final to ensure correct order of error parsing and not parsing the response if an error happens. This
	is not possible in overrides. Instead, override the various `assureXy(dict:)` methods, especially `assureAccessTokenParamsAreValid()`.
	
	- parameter params: Dictionary data parsed from the response
	- returns: An OAuth2JSON instance with token data; may contain additional information
	*/
	public final func parseAccessTokenResponse(params: OAuth2JSON) throws -> OAuth2JSON {
		try assureNoErrorInResponse(params)
		try assureCorrectBearerType(params)
		try assureAccessTokenParamsAreValid(params)
		
		clientConfig.updateFromResponse(normalizeAccessTokenResponseKeys(params))
		return params
	}
	
	/**
	This method does nothing, but allows subclasses to fix parameter names before passing the access token response to `OAuth2ClientConfig`s
	`updateFromResponse()`.
	
	- parameter dict: The dictionary that was returned from an access token response
	- returns: The dictionary with fixed key names
	*/
	open func normalizeAccessTokenResponseKeys(_ dict: OAuth2JSON) -> OAuth2JSON {
		return dict
	}
	
	/**
	Parse response data returned while using a refresh token.
	
	This method extracts token data, expected to be JSON, and fills the receiver's properties accordingly. If the response contains an
	"error" key, will parse the error and throw it.
	
	- parameter data: NSData returned from the call
	- returns: An OAuth2JSON instance with token data; may contain additional information
	*/
	open func parseRefreshTokenResponseData(_ data: Data) throws -> OAuth2JSON {
		let dict = try parseJSON(data)
		return try parseRefreshTokenResponse(dict)
	}
	
	/**
	Parse response data returned while using a refresh token.
	
	This method extracts token data and fills the receiver's properties accordingly. If the response contains an "error" key, will parse the
	error and throw it. The method is final to ensure correct order of error parsing and not parsing the response if an error happens. This
	is not possible in overrides. Instead, override the various `assureXy(dict:)` methods, especially `assureRefreshTokenParamsAreValid()`.
	
	- parameter json: Dictionary data parsed from the response
	- returns: An OAuth2JSON instance with token data; may contain additional information
	*/
	final func parseRefreshTokenResponse(_ dict: OAuth2JSON) throws -> OAuth2JSON {
		try assureNoErrorInResponse(dict)
		try assureCorrectBearerType(dict)
		try assureRefreshTokenParamsAreValid(dict)
		
		clientConfig.updateFromResponse(normalizeRefreshTokenResponseKeys(dict))
		return dict
	}
	
	/**
	This method does nothing, but allows subclasses to fix parameter names before passing the refresh token response to
	`OAuth2ClientConfig`s `updateFromResponse()`.
	
	- parameter dict: The dictionary that was returned from a refresh token response
	- returns: The dictionary with fixed key names
	*/
	open func normalizeRefreshTokenResponseKeys(_ dict: OAuth2JSON) -> OAuth2JSON {
		return dict
	}
	
	/**
	This method checks `state`, throws `OAuth2Error.missingState` or `OAuth2Error.invalidState`. Resets state if it matches.
	*/
	public final func assureMatchesState(_ params: OAuth2JSON) throws {
		guard let state = params["state"] as? String, !state.isEmpty else {
			throw OAuth2Error.missingState
		}
		logger?.trace("OAuth2", msg: "Checking state, got “\(state)”, expecting “\(context.state)”")
		if !context.matchesState(state) {
			throw OAuth2Error.invalidState
		}
		context.resetState()
	}
	
	/**
	Throws unless "token_type" is "bearer" (case-insensitive).
	*/
	open func assureCorrectBearerType(_ params: OAuth2JSON) throws {
		if let tokType = params["token_type"] as? String {
			if "bearer" == tokType.lowercased() {
				return
			}
			throw OAuth2Error.unsupportedTokenType("Only “bearer” token is supported, but received “\(tokType)”")
		}
		throw OAuth2Error.noTokenType
	}
	
	/**
	Called when parsing the access token response. Does nothing by default, implicit grant flows check state.
	*/
	open func assureAccessTokenParamsAreValid(_ params: OAuth2JSON) throws {
	}
	
	/**
	Called when parsing the refresh token response. Does nothing by default.
	*/
	open func assureRefreshTokenParamsAreValid(_ params: OAuth2JSON) throws {
	}

}


/**
Identifies one authorization, from the moment `didAuthorizeOrFail` is set (`authorize(params:callback:)` sets it) until
`didAuthorize(withParameters:)` or `didFail(with:)` ends it.

Work an authorization starts that answers later, such as a token request or a sign-in screen, keeps the identity that was current
when it started, and answers only while that authorization is still in progress. A late answer of an authorization that has ended is
dropped, so it can never end a newer one.
*/
public struct OAuth2AuthorizationID: Equatable {
	fileprivate let serial: UInt64
}


/**
Identifies one sign-in screen an authorizer presented, from `OAuth2Base.beginPresentation(dismiss:)` until it closes by itself or its
authorization ends.
*/
public struct OAuth2PresentationID: Equatable {
	fileprivate let serial: UInt64
	
	/// The authorization the screen was presented for; nil if none was in progress.
	public let authorization: OAuth2AuthorizationID?
}


/**
Class, internally used, to store current authorization context, such as state and redirect-url.
*/
open class OAuth2ContextStore {
	
	/// Currently used redirect_url.
	open var redirectURL: String?
	
	/// Current code verifier used for PKCE
	public internal(set) var codeVerifier: String?
	public let codeChallengeMethod = "S256"

	/// The current state.
	internal var _state = ""
	
	/**
	The state sent to the server when requesting a token.
	
	We internally generate a UUID and use the first 8 chars if `_state` is empty.
	*/
	open var state: String {
		if _state.isEmpty {
			_state = UUID().uuidString
			_state = String(_state[_state.startIndex..<_state.index(_state.startIndex, offsetBy: 8)])        // only use the first 8 chars, should be enough
		}
		return _state
	}
	
	/**
	Checks that given state matches the internal state.
	
	- parameter state: The state to check (may be nil)
	- returns: true if state matches, false otherwise or if given state is nil.
	*/
	func matchesState(_ state: String?) -> Bool {
		if let st = state {
			return st == _state
		}
		return false
	}
	
	/**
	Resets current state so it gets regenerated next time it's needed.
	*/
	func resetState() {
		_state = ""
	}
	
	/// The states of authorizations that have ended, most recent last.
	private var retiredStates = [String]()
	
	/// How many retired states are remembered; a redirect older than that many authorizations fails as `.invalidState`.
	private let retiredStatesKept = 16
	
	/**
	Retires the current state when its authorization ends, so the next authorization sends another one.
	*/
	func retireState() {
		if !_state.isEmpty {
			retiredStates.append(_state)
			if retiredStates.count > retiredStatesKept {
				retiredStates.removeFirst(retiredStates.count - retiredStatesKept)
			}
		}
		resetState()
	}
	
	/**
	Whether `state` was the state of an authorization that has ended.
	*/
	func wasRetired(_ state: String) -> Bool {
		return retiredStates.contains(state)
	}
	
	// MARK: - PKCE
	
	/**
	Generates a new code verifier string
	*/
	open func generateCodeVerifier() {
		var buffer = [UInt8](repeating: 0, count: 32)
		_ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)
		codeVerifier = Data(buffer).base64EncodedString()
			.replacingOccurrences(of: "+", with: "-")
			.replacingOccurrences(of: "/", with: "_")
			.replacingOccurrences(of: "=", with: "")
			.trimmingCharacters(in: .whitespaces)
	}
	
	
	open func codeChallenge() -> String? {
		guard let verifier = codeVerifier, let data = verifier.data(using: .utf8) else { return nil }
		var buffer = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
		data.withUnsafeBytes {
			_ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &buffer)
		}
		let hash = Data(buffer)
		let challenge = hash.base64EncodedString()
			.replacingOccurrences(of: "+", with: "-")
			.replacingOccurrences(of: "/", with: "_")
			.replacingOccurrences(of: "=", with: "")
			.trimmingCharacters(in: .whitespaces)
		return challenge
	}
	
}

