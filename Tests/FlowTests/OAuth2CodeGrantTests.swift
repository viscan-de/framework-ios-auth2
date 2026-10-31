//
//  OAuth2CodeGrantTests.swift
//  OAuth2
//
//  Created by Pascal Pfiffner on 6/18/14.
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

import XCTest

#if !NO_MODULE_IMPORT
@testable
import Base
@testable
import Flows
#if os(macOS)
import macOS
#elseif os(iOS)
import iOS
#endif
#else
@testable
import OAuth2
#endif
#if os(iOS) || os(macOS)
import AuthenticationServices
#endif
#if os(iOS)
import UIKit
import SafariServices
#elseif os(macOS)
import AppKit
#endif


class OAuth2CodeGrantTests: XCTestCase {
	
	lazy var baseSettings: OAuth2JSON = [
		"client_id": "abc",
		"client_secret": "xyz",
		"authorize_uri": "https://auth.ful.io",
		"token_uri": "https://token.ful.io",
		"keychain": false,
	]
	
	func testInit() {
		let oauth = OAuth2CodeGrant(settings: baseSettings)
		XCTAssertEqual(oauth.clientId, "abc", "Must init `client_id`")
		XCTAssertEqual(oauth.clientSecret!, "xyz", "Must init `client_secret`")
		XCTAssertFalse(oauth.useKeychain, "No keychain")
		XCTAssertNil(oauth.scope, "Empty scope")
		
		XCTAssertEqual(oauth.authURL, URL(string: "https://auth.ful.io")!, "Must init `authorize_uri`")
		XCTAssertEqual(oauth.tokenURL!, URL(string: "https://token.ful.io")!, "Must init `token_uri`")
	}
	
	func testNotTLS() {
		let oauth = OAuth2CodeGrant(settings: [
			"client_id": "abc",
			"client_secret": "xyz",
			"authorize_uri": "http://auth.ful.io",
			"token_uri": "http://token.ful.io",
			"keychain": false,
		])
		
		XCTAssertNotNil(oauth.authURL, "Must init `authorize_uri`")
		do {
			_ = try oauth.authorizeURL(withRedirect: "oauth2://callback", scope: nil, params: nil)
			XCTAssertTrue(false, "Should no longer be here")
		}
		catch OAuth2Error.notUsingTLS {
		}
		catch let error {
			XCTAssertNil(error, "Should not be catching")
		}
		
		do {
			_ = try oauth.accessTokenRequest(with: "pp").asURL()
			XCTAssertTrue(false, "Should no longer be here")
		}
		catch OAuth2Error.notUsingTLS {
		}
		catch let error {
			XCTAssertNil(error, "Should not be catching")
		}
	}
	
	func testAuthorizeURI() {
		let oauth = OAuth2CodeGrant(settings: baseSettings)
		XCTAssertNotNil(oauth.authURL, "Must init `authorize_uri`")
		
		let comp = URLComponents(url: try! oauth.authorizeURL(withRedirect: "oauth2://callback", scope: nil, params: nil), resolvingAgainstBaseURL: true)!
		XCTAssertEqual(comp.host!, "auth.ful.io", "Correct host")
		let query = OAuth2CodeGrant.params(fromQuery: comp.percentEncodedQuery!)
		XCTAssertEqual(query["client_id"]!, "abc", "Expecting correct `client_id`")
		XCTAssertNil(query["client_secret"], "Must not have `client_secret`")
		XCTAssertEqual(query["response_type"]!, "code", "Expecting correct `response_type`")
		XCTAssertEqual(query["redirect_uri"]!, "oauth2://callback", "Expecting correct `redirect_uri`")
		XCTAssertTrue(8 == (query["state"]!).count, "Expecting an auto-generated UUID for `state`")
	}
	
	func testAuthorizeURIWithPKCE() {
		let oauth = OAuth2CodeGrant(settings: [
			"client_id": "abc",
			"authorize_uri": "https://auth.ful.io",
			"token_uri": "https://token.ful.io",
			"keychain": false,
			"use_pkce" : true,
			])
		XCTAssertNotNil(oauth.authURL, "Must init `authorize_uri`")
		
		let comp = URLComponents(url: try! oauth.authorizeURL(withRedirect: "oauth2://callback", scope: nil, params: nil), resolvingAgainstBaseURL: true)!
		XCTAssertEqual(comp.host!, "auth.ful.io", "Correct host")
		let query = OAuth2CodeGrant.params(fromQuery: comp.percentEncodedQuery!)
		XCTAssertEqual(query["client_id"]!, "abc", "Expecting correct `client_id`")
		XCTAssertNotNil(query["code_challenge"], "Must have `code_challenge`")
		XCTAssertEqual(query["code_challenge_method"]!, "S256", "Expecting correct `code_challenge_method`")
		XCTAssertEqual(query["redirect_uri"]!, "oauth2://callback", "Expecting correct `redirect_uri`")
		XCTAssertTrue(8 == (query["state"]!).count, "Expecting an auto-generated UUID for `state`")
	}
	
	func testRedirectURI() {
		let oauth = OAuth2CodeGrant(settings: baseSettings)
		oauth.redirect = "oauth2://callback"
		oauth.context.redirectURL = oauth.redirect
		
		// parse error
		var redirect = URL(string: "oauth2://callback?error=invalid_scope")!
		do {
			_ = try oauth.validateRedirectURL(redirect)
			XCTAssertTrue(false, "Should not be here")
		}
		catch OAuth2Error.invalidScope {
		}
		catch let error {
			XCTAssertTrue(false, "Must not end up here with \(error)")
		}
		
		// parse custom error
		redirect = URL(string: "oauth2://callback?error=invalid_scope&error_description=BadScopeDude")!
		do {
			_ = try oauth.validateRedirectURL(redirect)
			XCTAssertTrue(false, "Should not be here")
		}
		catch let error {
			XCTAssertEqual("BadScopeDude", "\(error)", "Must parse `error_description`")
		}
		
		// parse wrong callback
		redirect = URL(string: "oauth3://callback?error=invalid_scope")!
		do {
			_ = try oauth.validateRedirectURL(redirect)
			XCTAssertTrue(false, "Should not be here")
		}
		catch OAuth2Error.invalidRedirectURL {
		}
		catch let error {
			XCTAssertTrue(false, "Should have caught invalid redirect URL error, but got \(error)")
		}
		
		// parse no state
		redirect = URL(string: "oauth2://callback?code=C0D3")!
		do {
			_ = try oauth.validateRedirectURL(redirect)
			XCTAssertTrue(false, "Should not be here")
		}
		catch OAuth2Error.missingState {
		}
		catch let error {
			XCTAssertTrue(false, "Must not end up here with \(error)")
		}
		
		// parse all good
		redirect = URL(string: "oauth2://callback?code=C0D3&state=\(oauth.context.state)")!
		do {
			_ = try oauth.validateRedirectURL(redirect)
		}
		catch let error {
			XCTAssertTrue(false, "Should not throw, but threw \(error)")
		}
		
		// parse oob with invalid redirect
		oauth.redirect = "urn:ietf:wg:oauth:2.0:oob"
		oauth.context.redirectURL = oauth.redirect
		redirect = URL(string: "oauth2://callback?code=C0D3&state=\(oauth.context.state)")!
		do {
			_ = try oauth.validateRedirectURL(redirect)
		}
		catch OAuth2Error.invalidRedirectURL {
		}
		catch let error {
			XCTAssertTrue(false, "Must not end up here with \(error)")
		}
		
		// oob with valid redirect
		redirect = URL(string: "http://localhost?code=C0D3&state=\(oauth.context.state)")!
		do {
			_ = try oauth.validateRedirectURL(redirect)
		}
		catch let error {
			XCTAssertTrue(false, "Should not throw, but threw \(error)")
		}
	}
	
	func testTokenRequest() {
		let oauth = OAuth2CodeGrant(settings: [
			"client_id": "abc",
			"authorize_uri": "https://auth.ful.io",
			"token_uri": "https://token.ful.io",
			"keychain": false,
		])
		oauth.redirect = "oauth2://callback"
		
		// no redirect in context - fail
		do {
			_ = try oauth.accessTokenRequest(with: "pp")
			XCTAssertTrue(false, "Should not be here any more")
		}
		catch OAuth2Error.noRedirectURL {
			XCTAssertTrue(true, "Must be here")
		}
		catch {
			XCTAssertTrue(false, "Should not be here")
		}
		
		// with redirect in context - success
		oauth.context.redirectURL = "oauth2://callback"
		
		let req = try! oauth.accessTokenRequest(with: "pp").asURLRequest(for: oauth)
		let comp = URLComponents(url: req.url!, resolvingAgainstBaseURL: true)!
		XCTAssertEqual(comp.host!, "token.ful.io", "Correct host")
		
		let body = String(data: req.httpBody!, encoding: String.Encoding.utf8)
		let query = OAuth2CodeGrant.params(fromQuery: body!)
		XCTAssertEqual(query["client_id"]!, "abc", "Expecting correct `client_id`")
		XCTAssertNil(query["client_secret"], "Must not have `client_secret`")
		XCTAssertEqual(query["code"]!, "pp", "Expecting correct `code`")
		XCTAssertEqual(query["grant_type"]!, "authorization_code", "Expecting correct `grant_type`")
		XCTAssertEqual(query["redirect_uri"]!, "oauth2://callback", "Expecting correct `redirect_uri`")
		XCTAssertNil(query["state"], "`state` must be empty")
	}
	
	func testTokenRequestWithSecret() {
		let oauth = OAuth2CodeGrant(settings: baseSettings)
		oauth.redirect = "oauth2://callback"
		oauth.context.redirectURL = "oauth2://callback"
		
		// not in body
		let req = try! oauth.accessTokenRequest(with: "pp").asURLRequest(for: oauth)
		let comp = URLComponents(url: req.url!, resolvingAgainstBaseURL: true)!
		XCTAssertEqual(comp.host!, "token.ful.io", "Correct host")
		
		let body = String(data: req.httpBody!, encoding: String.Encoding.utf8)
		let query = OAuth2CodeGrant.params(fromQuery: body!)
		XCTAssertNil(query["client_id"], "No `client_id` in body")
		XCTAssertNil(query["client_secret"], "Must not have `client_secret`")
		XCTAssertEqual(query["code"]!, "pp", "Expecting correct `code`")
		XCTAssertEqual(query["grant_type"]!, "authorization_code", "Expecting correct `grant_type`")
		XCTAssertEqual(query["redirect_uri"]!, "oauth2://callback", "Expecting correct `redirect_uri`")
		XCTAssertNil(query["state"], "`state` must be empty")
		
		// in body
		oauth.clientConfig.secretInBody = true
		
		let req2 = try! oauth.accessTokenRequest(with: "pp").asURLRequest(for: oauth)
		let comp2 = URLComponents(url: req2.url!, resolvingAgainstBaseURL: true)!
		XCTAssertEqual(comp2.host!, "token.ful.io", "Correct host")
		
		let body2 = String(data: req2.httpBody!, encoding: String.Encoding.utf8)
		let query2 = OAuth2CodeGrant.params(fromQuery: body2!)
		XCTAssertEqual(query2["client_id"]!, "abc", "Expecting correct `client_id`")
		XCTAssertEqual(query2["client_secret"]!, "xyz", "Expecting correct `client_secret`")
		XCTAssertEqual(query2["code"]!, "pp", "Expecting correct `code`")
		XCTAssertEqual(query2["grant_type"]!, "authorization_code", "Expecting correct `grant_type`")
		XCTAssertEqual(query2["redirect_uri"]!, "oauth2://callback", "Expecting correct `redirect_uri`")
		XCTAssertNil(query2["state"], "`state` must be empty")
	}
	
	func testTokenRequestWithPKCE() {
		let oauth = OAuth2CodeGrant(settings: [
			"client_id": "abc",
			"authorize_uri": "https://auth.ful.io",
			"token_uri": "https://token.ful.io",
			"keychain": false,
			"use_pkce" : true,
			])
		oauth.redirect = "oauth2://callback"
		
		// no redirect in context - fail
		do {
			_ = try oauth.accessTokenRequest(with: "pp")
			XCTAssertTrue(false, "Should not be here any more")
		}
		catch OAuth2Error.noRedirectURL {
			XCTAssertTrue(true, "Must be here")
		}
		catch {
			XCTAssertTrue(false, "Should not be here")
		}
		
		// with redirect in context - success
		oauth.context.redirectURL = "oauth2://callback"
		
		// initialize code verifier in context
		oauth.context.generateCodeVerifier()
		
		let req = try! oauth.accessTokenRequest(with: "pp").asURLRequest(for: oauth)
		let comp = URLComponents(url: req.url!, resolvingAgainstBaseURL: true)!
		XCTAssertEqual(comp.host!, "token.ful.io", "Correct host")
		
		let body = String(data: req.httpBody!, encoding: String.Encoding.utf8)
		let query = OAuth2CodeGrant.params(fromQuery: body!)
		XCTAssertEqual(query["client_id"]!, "abc", "Expecting correct `client_id`")
		XCTAssertNil(query["client_secret"], "Must not have `client_secret`")
		XCTAssertEqual(query["code"]!, "pp", "Expecting correct `code`")
		XCTAssertEqual(query["grant_type"]!, "authorization_code", "Expecting correct `grant_type`")
		XCTAssertEqual(query["redirect_uri"]!, "oauth2://callback", "Expecting correct `redirect_uri`")
		XCTAssertNil(query["state"], "`state` must be empty")
		XCTAssertNotNil(query["code_verifier"], "Must  have `code_verifier`")
	}
	
	func testCustomAuthParameters() {
		let oauth = OAuth2CodeGrant(settings: baseSettings)
		oauth.redirect = "oauth2://callback"
		oauth.context.redirectURL = "oauth2://callback"

		// not in body
		let req = try! oauth.accessTokenRequest(with: "pp").asURLRequest(for: oauth)
		let body = String(data: req.httpBody!, encoding: String.Encoding.utf8)
		let query = OAuth2CodeGrant.params(fromQuery: body!)
		XCTAssertNil(query["foo"], "`foo` should be nil")

		oauth.clientConfig.customParameters = [ "foo": "bar" ]

		// in body
		let req2 = try! oauth.accessTokenRequest(with: "pp").asURLRequest(for: oauth)
		let body2 = String(data: req2.httpBody!, encoding: String.Encoding.utf8)
		let query2 = OAuth2CodeGrant.params(fromQuery: body2!)
		XCTAssertEqual(query2["foo"], "bar", "Expecting key `foo` to be `bar`")
		
		oauth.authParameters = ["bar": "hat"]
		
		// in body
		let req3 = try! oauth.accessTokenRequest(with: "pp").asURLRequest(for: oauth)
		let body3 = String(data: req3.httpBody!, encoding: String.Encoding.utf8)
		let query3 = OAuth2CodeGrant.params(fromQuery: body3!)
		XCTAssertEqual(query3["bar"], "hat", "Expecting key `bar` to be `hat`")
	}
	
	func testCustomAuthParametersInit() {
		var settings = baseSettings
		settings["parameters"] = ["foo": "bar"]
		let oauth = OAuth2CodeGrant(settings: settings)
		oauth.redirect = "oauth2://callback"
		oauth.context.redirectURL = "oauth2://callback"
		
		let req = try! oauth.accessTokenRequest(with: "pp").asURLRequest(for: oauth)
		let body = String(data: req.httpBody!, encoding: String.Encoding.utf8)
		let query = OAuth2CodeGrant.params(fromQuery: body!)
		XCTAssertEqual(query["foo"], "bar", "Expecting key `foo` to be `bar`")
	}
	
	func testTokenRequestAgainstAuthURL() {
		
		// test fallback to authURL
		let oauth = OAuth2CodeGrant(settings: [
			"client_id": "abc",
			"client_secret": "xyz",
			"authorize_uri": "https://auth.ful.io",
			"keychain": false,
		])
		oauth.redirect = "oauth2://callback"
		oauth.context.redirectURL = "oauth2://callback"
		
		let req = try! oauth.accessTokenRequest(with: "pp").asURLRequest(for: oauth)
		let comp = URLComponents(url: req.url!, resolvingAgainstBaseURL: true)!
		XCTAssertEqual(comp.host!, "auth.ful.io", "Correct host")
	}
	
	func testTokenResponse() {
		let settings = [
			"client_id": "abc",
			"client_secret": "xyz",
			"authorize_uri": "https://auth.ful.io",
			"keychain": false,
		] as [String: Any]
		let oauth = OAuth2CodeGrant(settings: settings)
		var response = [
			"access_token": "2YotnFZFEjr1zCsicMWpAA",
			"expires_in": 3600,
			"refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
			"foo": "bar & hat"
		] as [String: Any]
		
		// must throw when "token_type" is missing
		do {
			_ = try oauth.parseAccessTokenResponse(params: response)
			XCTAssertTrue(false, "Should not be here any more")
		}
		catch OAuth2Error.noTokenType {
		}
		catch let error {
			XCTAssertNil(error, "Should not throw wrong error")
		}
		
		// LinkedIn on the other hand must not throw
		let linkedin = OAuth2CodeGrantLinkedIn(settings: settings)
		do {
			_ = try linkedin.parseAccessTokenResponse(params: response)
		}
		catch let error {
			XCTAssertNil(error, "Should not throw")
		}
		
		// Nor the generic no-token-type class
		let noType = OAuth2CodeGrantNoTokenType(settings: settings)
		do {
			_ = try noType.parseAccessTokenResponse(params: response)
		}
		catch let error {
			XCTAssertNil(error, "Should not throw")
		}
		
		// must throw when "token_type" is not known
		response["token_type"] = "guardian"
		do {
			_ = try oauth.parseAccessTokenResponse(params: response)
			XCTAssertTrue(false, "Should not be here any more")
		}
		catch OAuth2Error.unsupportedTokenType(_) {
		}
		catch let error {
			XCTAssertNil(error, "Should not throw wrong error")
		}
		
		// the no-token-type class must still ignore it
		do {
			_ = try noType.parseAccessTokenResponse(params: response)
		}
		catch let error {
			XCTAssertNil(error, "Should not throw")
		}
		
		// add "token_type"
		response["token_type"] = "bearer"
		do {
			let dict = try oauth.parseAccessTokenResponse(params: response)
			XCTAssertEqual("bar & hat", dict["foo"] as? String)
			XCTAssertEqual("2YotnFZFEjr1zCsicMWpAA", oauth.accessToken, "Must extract access token")
			XCTAssertNotNil(oauth.accessTokenExpiry, "Must extract access token expiry date")
			XCTAssertEqual("tGzv3JOkF0XG5Qx2TlKWIA", oauth.refreshToken, "Must extract refresh token")
		}
		catch {
			XCTAssertTrue(false, "Not expected to throw")
		}
		
		// unsupported bearer type
		let response2 = [
			"access_token": "2YotnFZFEjr1zCsicMWpAA",
			"token_type": "not_my_type",
			"expires_in": 3600,
			"refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
			"foo": "bar & hat"
		] as [String : Any]
		
		do {
			_ = try oauth.parseAccessTokenResponse(params: response2)
			XCTAssertTrue(false, "Should not be here any more")
		}
		catch OAuth2Error.unsupportedTokenType {
			XCTAssertTrue(true, "Throw correct error")
		}
		catch {
			XCTAssertTrue(false, "Should not throw wrong error")
		}
		
		let performer = OAuth2MockPerformer()
		oauth.requestPerformer = performer
		
		// test round trip - should fail because of 403
		performer.responseJSON = response
		performer.responseStatus = 403
		oauth.context.redirectURL = "https://localhost"
		oauth.didAuthorizeOrFail = { json, error in
			XCTAssertNil(json)
			XCTAssertNotNil(error)
			XCTAssertEqual(OAuth2Error.forbidden, error)
		}
		oauth.exchangeCodeForToken("MNOP")
		
		// test round trip - should succeed because of good HTTP status
		performer.responseStatus = 301
		oauth.didAuthorizeOrFail = { json, error in
			XCTAssertNotNil(json)
			XCTAssertNil(error)
			XCTAssertEqual("tGzv3JOkF0XG5Qx2TlKWIA", json?["refresh_token"] as? String)
		}
		oauth.exchangeCodeForToken("MNOP")
	}
}


class OAuth2MockPerformer: OAuth2RequestPerformer {
	
	var responseJSON: OAuth2JSON?
	
	var responseStatus = 200
	
	func perform(request: URLRequest, completionHandler callback: @escaping (Data?, URLResponse?, Error?) -> Void) -> URLSessionTask? {
		let http = HTTPURLResponse(url: request.url!, statusCode: responseStatus, httpVersion: nil, headerFields: nil)!
		do {
			guard let json = responseJSON else {
				throw OAuth2Error.noDataInResponse
			}
			let data = try JSONSerialization.data(withJSONObject: json, options: [])
			callback(data, http, nil)
		}
		catch let error {
			callback(nil, http, error)
		}
		return nil
	}
}


/**
Holds every request's completion until the test answers it. Its tasks are never resumed, so nothing goes over the network.
*/
class OAuth2DeferredPerformer: OAuth2RequestPerformer {
	
	static let session = URLSession(configuration: .ephemeral)
	
	private(set) var requests = [URLRequest]()
	
	/// The task returned for each request; one `abortAuthorization()` cancelled is no longer `.suspended`.
	private(set) var tasks = [URLSessionTask]()
	
	private var completions = [(Data?, URLResponse?, Error?) -> Void]()
	
	func perform(request: URLRequest, completionHandler: @escaping (Data?, URLResponse?, Error?) -> Void) -> URLSessionTask? {
		let task = type(of: self).session.dataTask(with: request)
		requests.append(request)
		tasks.append(task)
		completions.append(completionHandler)
		return task
	}
	
	/// Answers the request performed `index`th with `json` and `status`.
	func complete(_ index: Int, with json: OAuth2JSON, status: Int = 200) {
		let http = HTTPURLResponse(url: requests[index].url!, statusCode: status, httpVersion: nil, headerFields: nil)!
		completions[index](try! JSONSerialization.data(withJSONObject: json, options: []), http, nil)
	}
}


#if os(iOS) || os(macOS)

/**
A code grant signing in through `OAuth2Authorizer`'s ASWebAuthenticationSession path, with a session that presents nothing and a
performer that holds the token request until the test answers it.
*/
class OAuth2AuthenticationSessionTests: XCTestCase {
	
	let redirect = "oauth2app://callback"
	
	let tokenResponse: OAuth2JSON = [
		"access_token": "2YotnFZFEjr1zCsicMWpAA",
		"token_type": "bearer",
		"expires_in": 3600,
		"refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
	]
	
	#if os(iOS)
	/// The anchor the iOS authorizer requires before it starts a session; `authorizeContext` holds it weakly.
	let window = UIWindow(frame: .zero)
	#endif
	
	func codeGrant() -> (OAuth2CodeGrant, OAuth2FakeSessionAuthorizer, OAuth2DeferredPerformer) {
		let oauth = OAuth2CodeGrant(settings: [
			"client_id": "abc",
			"authorize_uri": "https://auth.ful.io",
			"token_uri": "https://token.ful.io",
			"keychain": false,
		])
		oauth.redirect = redirect
		oauth.authConfig.authorizeEmbedded = true
		oauth.authConfig.ui.useAuthenticationSession = true
		#if os(iOS)
		oauth.authConfig.authorizeContext = window
		#endif
		let authorizer = OAuth2FakeSessionAuthorizer(oauth2: oauth)
		oauth.authorizer = authorizer
		let performer = OAuth2DeferredPerformer()
		oauth.requestPerformer = performer
		return (oauth, authorizer, performer)
	}
	
	func redirectURL(_ oauth: OAuth2CodeGrant) -> URL {
		return URL(string: "\(redirect)?code=MNOP&state=\(oauth.context.state)")!
	}
	
	func testACompletedSessionAnswersItsAuthorization() {
		let (oauth, authorizer, performer) = codeGrant()
		var answers = [OAuth2Error?]()
		oauth.authorize() { params, error in
			XCTAssertNotNil(params)
			answers.append(error)
		}
		XCTAssertEqual(1, authorizer.sessions.count)
		
		authorizer.sessions[0].completionHandler(redirectURL(oauth), nil)
		XCTAssertEqual(1, performer.requests.count, "The code is exchanged for a token")
		performer.complete(0, with: tokenResponse)
		
		XCTAssertEqual([nil], answers)
		XCTAssertEqual("2YotnFZFEjr1zCsicMWpAA", oauth.accessToken)
		XCTAssertFalse(oauth.isAuthorizing)
		XCTAssertEqual(0, authorizer.sessions[0].cancelCount, "A sheet that closed by itself is not cancelled")
	}
	
	func testCancellingTheSessionAnswersCancelled() {
		let (oauth, authorizer, _) = codeGrant()
		var answers = [OAuth2Error?]()
		oauth.authorize() { _, error in answers.append(error) }
		
		authorizer.sessions[0].completionHandler(nil, ASWebAuthenticationSessionError(.canceledLogin))
		XCTAssertEqual([.requestCancelled], answers)
		XCTAssertFalse(oauth.isAuthorizing)
	}
	
	func testAbortCancelsThePresentedSession() {
		let (oauth, authorizer, _) = codeGrant()
		var answers = [OAuth2Error?]()
		oauth.authorize() { _, error in answers.append(error) }
		XCTAssertEqual(0, authorizer.sessions[0].cancelCount)
		
		oauth.abortAuthorization()
		XCTAssertEqual([.requestCancelled], answers)
		XCTAssertEqual(1, authorizer.sessions[0].cancelCount, "Aborting takes the sign-in sheet down")
		XCTAssertFalse(oauth.isAuthorizing)
	}
	
	func testALateRedirectOfAnAbortedAuthorizationIsNotExchanged() {
		let (oauth, authorizer, performer) = codeGrant()
		var answers = [OAuth2Error?]()
		oauth.authorize() { _, error in answers.append(error) }
		oauth.abortAuthorization()
		
		// the user finished signing in on the sheet just before it went
		authorizer.sessions[0].completionHandler(redirectURL(oauth), nil)
		XCTAssertEqual(0, performer.requests.count, "Nobody waits on the code any more")
		XCTAssertEqual([.requestCancelled], answers)
		XCTAssertNil(oauth.accessToken)
	}
	
	func testALateCancelOfAnAbortedAuthorizationDoesNotAnswerTheNextOne() {
		let (oauth, authorizer, _) = codeGrant()
		var firstAnswers = [OAuth2Error?]()
		oauth.authorize() { _, error in firstAnswers.append(error) }
		oauth.abortAuthorization()
		
		var secondAnswers = [OAuth2Error?]()
		oauth.authorize() { _, error in secondAnswers.append(error) }
		XCTAssertEqual(2, authorizer.sessions.count)
		
		authorizer.sessions[0].completionHandler(nil, ASWebAuthenticationSessionError(.canceledLogin))
		XCTAssertEqual([.requestCancelled], firstAnswers)
		XCTAssertEqual([], secondAnswers, "The first sheet's cancel is not the second sign-in's answer")
		XCTAssertTrue(oauth.isAuthorizing)
		
		oauth.abortAuthorization()
		XCTAssertEqual([.requestCancelled], secondAnswers)
		XCTAssertEqual(1, authorizer.sessions[1].cancelCount)
	}
	
	func testAbortDuringTheTokenExchangeAnswersAtOnceAndDropsTheExchange() {
		let (oauth, authorizer, performer) = codeGrant()
		var firstAnswers = [OAuth2Error?]()
		oauth.authorize() { _, error in firstAnswers.append(error) }
		authorizer.sessions[0].completionHandler(redirectURL(oauth), nil)
		XCTAssertEqual(1, performer.requests.count)
		
		oauth.abortAuthorization()
		XCTAssertEqual([.requestCancelled], firstAnswers, "Aborting answers without waiting on the token request")
		
		var secondAnswers = [OAuth2Error?]()
		oauth.authorize() { _, error in secondAnswers.append(error) }
		performer.complete(0, with: tokenResponse)
		XCTAssertEqual([], secondAnswers, "The first sign-in's token is not the second one's answer")
		XCTAssertNil(oauth.accessToken, "An aborted sign-in installs no tokens")
		XCTAssertTrue(oauth.isAuthorizing)
		
		oauth.abortAuthorization()
		XCTAssertEqual([.requestCancelled], secondAnswers)
	}
	
	func testIsPresentingAuthorizationWhileTheSheetIsUp() {
		let (oauth, authorizer, performer) = codeGrant()
		XCTAssertFalse(oauth.isPresentingAuthorization)
		oauth.authorize() { _, _ in }
		XCTAssertTrue(oauth.isPresentingAuthorization)
		
		authorizer.sessions[0].completionHandler(redirectURL(oauth), nil)
		XCTAssertFalse(oauth.isPresentingAuthorization, "The sheet has closed; the token request runs without one")
		XCTAssertTrue(oauth.isAuthorizing)
		
		performer.complete(0, with: tokenResponse)
		XCTAssertFalse(oauth.isPresentingAuthorization)
		XCTAssertFalse(oauth.isAuthorizing)
	}
	
	func testIsPresentingAuthorizationEndsWithAnAbort() {
		let (oauth, _, _) = codeGrant()
		oauth.authorize() { _, _ in }
		XCTAssertTrue(oauth.isPresentingAuthorization)
		
		oauth.abortAuthorization()
		XCTAssertFalse(oauth.isPresentingAuthorization)
	}
	
	func testAbortDuringARefreshLetsTheRefreshFinishAndStoreItsTokens() {
		let (oauth, authorizer, performer) = codeGrant()
		oauth.refreshToken = "spent-on-the-wire"
		var answers = [OAuth2Error?]()
		oauth.authorize() { _, error in answers.append(error) }
		XCTAssertEqual(1, performer.requests.count, "The refresh is running")
		
		oauth.abortAuthorization()
		XCTAssertEqual([.requestCancelled], answers)
		XCTAssertEqual(.suspended, performer.tasks[0].state, "A refresh is never cancelled: the provider may have rotated the refresh token already")
		
		performer.complete(0, with: [
			"access_token": "fresh-access",
			"token_type": "bearer",
			"expires_in": 3600,
			"refresh_token": "rotated",
		])
		XCTAssertEqual("fresh-access", oauth.accessToken)
		XCTAssertEqual("rotated", oauth.refreshToken, "The rotated refresh token is kept")
		XCTAssertEqual([.requestCancelled], answers, "The refresh's answer is dropped")
		XCTAssertEqual(0, authorizer.sessions.count)
	}
	
	func testARefreshEndingAfterAnAbortPresentsNoSheet() {
		let (oauth, authorizer, performer) = codeGrant()
		oauth.refreshToken = "dead"
		var answers = [OAuth2Error?]()
		oauth.authorize() { _, error in answers.append(error) }
		oauth.abortAuthorization()
		
		// a rejected refresh goes on to the sign-in sheet, for an authorization still in progress
		performer.complete(0, with: ["error": "unauthorized_client"], status: 400)
		XCTAssertEqual(0, authorizer.sessions.count, "Nobody waits on a sign-in any more")
		XCTAssertEqual([.requestCancelled], answers)
	}
	
	func testALateRedirectThroughHandleRedirectURLDoesNotAnswerTheNextSignIn() {
		let (oauth, _, performer) = codeGrant()
		oauth.authorize() { _, _ in }
		let firstState = oauth.context.state
		oauth.abortAuthorization()
		
		var secondAnswers = [OAuth2Error?]()
		oauth.authorize() { _, error in secondAnswers.append(error) }
		XCTAssertNotEqual(firstState, oauth.context.state, "Every sign-in has its own state")
		
		// the first sign-in's redirect, reaching the app by its URL scheme
		oauth.handleRedirectURL(URL(string: "\(redirect)?code=MNOP&state=\(firstState)")!)
		XCTAssertEqual(0, performer.requests.count, "A late redirect is not exchanged")
		XCTAssertEqual([], secondAnswers, "and it does not answer the next sign-in")
		XCTAssertTrue(oauth.isAuthorizing)
		oauth.abortAuthorization()
	}
	
	func testARedirectWithAStateNeverIssuedStillFails() {
		let (oauth, _, performer) = codeGrant()
		var answers = [OAuth2Error?]()
		oauth.authorize() { _, error in answers.append(error) }
		
		oauth.handleRedirectURL(URL(string: "\(redirect)?code=MNOP&state=FORGED")!)
		XCTAssertEqual(0, performer.requests.count)
		XCTAssertEqual([.invalidState], answers)
	}
	
	func testAuthorizingFromTheCallbackStartsANewSignIn() {
		let (oauth, authorizer, _) = codeGrant()
		var secondAnswers = [OAuth2Error?]()
		oauth.authorize() { _, _ in
			oauth.authorize() { _, error in secondAnswers.append(error) }
		}
		oauth.abortAuthorization()
		
		XCTAssertEqual([], secondAnswers, "The first sign-in has ended by the time its callback runs")
		XCTAssertEqual(2, authorizer.sessions.count)
		XCTAssertTrue(oauth.isPresentingAuthorization)
		XCTAssertEqual(0, authorizer.sessions[1].cancelCount)
		oauth.abortAuthorization()
		XCTAssertEqual([.requestCancelled], secondAnswers)
	}
	
	func testAbortingFromTheCallbackAnswersOnce() {
		let (oauth, _, _) = codeGrant()
		var answers = 0
		oauth.authorize() { _, _ in
			answers += 1
			if 1 == answers {
				oauth.abortAuthorization()
			}
		}
		oauth.abortAuthorization()
		XCTAssertEqual(1, answers)
	}
	
	func testAbortWithNothingInProgressCallsNoCallbacks() {
		let (oauth, _, _) = codeGrant()
		var afterCalls = 0
		oauth.afterAuthorizeOrFail = { _, _ in afterCalls += 1 }
		
		oauth.abortAuthorization()
		XCTAssertEqual(0, afterCalls)
	}
	
	func testAbortFromABackgroundThreadDoesNotWaitOnTheMainThread() {
		let (oauth, authorizer, _) = codeGrant()
		let answered = expectation(description: "answered")
		oauth.authorize() { _, error in
			XCTAssertTrue(Thread.isMainThread)
			XCTAssertEqual(.requestCancelled, error)
			answered.fulfill()
		}
		
		let returned = DispatchSemaphore(value: 0)
		DispatchQueue.global().async {
			oauth.abortAuthorization()
			returned.signal()
		}
		// the main thread blocked, as it is while it waits on the work that aborts
		XCTAssertEqual(.success, returned.wait(timeout: .now() + 2), "abortAuthorization() must not wait on the main thread")
		
		wait(for: [answered], timeout: 2)
		XCTAssertEqual(1, authorizer.sessions[0].cancelCount)
		XCTAssertFalse(authorizer.sessions[0].wasCancelledOffTheMainThread)
	}
	
	func testACancelThatCallsTheCompletionAnswersOnce() {
		let (oauth, authorizer, _) = codeGrant()
		authorizer.sessionsCallBackOnCancel = true
		var answers = [OAuth2Error?]()
		oauth.authorize() { _, error in answers.append(error) }
		
		oauth.abortAuthorization()
		XCTAssertEqual([.requestCancelled], answers)
		XCTAssertEqual(1, authorizer.sessions[0].cancelCount)
		XCTAssertFalse(oauth.isAuthorizing)
	}
	
	func testATokenResponseOffTheMainThreadAnswersOnTheMainThread() {
		let (oauth, authorizer, performer) = codeGrant()
		let answered = expectation(description: "answered")
		oauth.authorize() { params, error in
			XCTAssertTrue(Thread.isMainThread)
			XCTAssertNotNil(params)
			XCTAssertNil(error)
			answered.fulfill()
		}
		authorizer.sessions[0].completionHandler(redirectURL(oauth), nil)
		
		let tokenResponse = self.tokenResponse
		DispatchQueue.global().async {
			performer.complete(0, with: tokenResponse)
		}
		wait(for: [answered], timeout: 2)
		XCTAssertEqual("2YotnFZFEjr1zCsicMWpAA", oauth.accessToken)
	}
	
	func testAnUnparseableRedirectURLFailsTheAuthorization() {
		let (oauth, authorizer, _) = codeGrant()
		oauth.redirect = ""
		var answers = [OAuth2Error?]()
		oauth.authorize() { _, error in answers.append(error) }
		
		#if os(iOS)
		XCTAssertEqual([.unableToOpenAuthorizeURL], answers)
		#else
		XCTAssertEqual([.invalidRedirectURL("")], answers)
		#endif
		XCTAssertEqual(0, authorizer.sessions.count)
		XCTAssertFalse(oauth.isAuthorizing)
	}
	
	#if os(iOS)
	func testSafariDoneOrSwipeAfterTheEndAnswersNobody() {
		let (oauth, authorizer, _) = codeGrant()
		let presenter = UIViewController()
		var firstAnswers = 0
		oauth.didAuthorizeOrFail = { _, _ in firstAnswers += 1 }
		let web = try! authorizer.authorizeSafariEmbedded(from: presenter, at: URL(string: "https://auth.ful.io")!)
		let delegate = web.delegate
		XCTAssertNotNil(delegate)
		oauth.abortAuthorization()
		XCTAssertEqual(1, firstAnswers)
		
		var secondAnswers = [OAuth2Error?]()
		oauth.authorize() { _, error in secondAnswers.append(error) }
		delegate?.safariViewControllerDidFinish?(web)
		let swipe = UIPresentationController(presentedViewController: web, presenting: presenter)
		(delegate as? UIAdaptivePresentationControllerDelegate)?.presentationControllerDidDismiss?(swipe)
		
		XCTAssertEqual(1, firstAnswers)
		XCTAssertEqual([], secondAnswers, "Done or a swipe on the first sign-in's Safari view answers nobody")
		XCTAssertTrue(oauth.isAuthorizing)
		oauth.abortAuthorization()
	}
	#endif
	
	#if os(macOS)
	func testTheWebViewWindowOfAnEndedAuthorizationCanBeClosed() {
		let (oauth, authorizer, _) = codeGrant()
		oauth.didAuthorizeOrFail = { _, _ in }
		let controller = try! authorizer.presentableAuthorizeViewController(at: URL(string: "https://auth.ful.io")!)
		let windowController = authorizer.windowController(forViewController: controller, with: oauth.authConfig)
		let window = windowController.window!
		window.isReleasedWhenClosed = false
		oauth.abortAuthorization()
		
		var closed = false
		let observer = NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: nil) { _ in
			closed = true
		}
		defer { NotificationCenter.default.removeObserver(observer) }
		controller.onWillCancel?()
		XCTAssertTrue(closed, "Its close button refuses to close it otherwise, and nobody answers for it any more")
	}
	#endif
	
	func testASignInStartedOffTheMainThreadWhileAnotherEndsKeepsItsIdentity() {
		let (oauth, authorizer, performer) = codeGrant()
		var firstAnswers = [OAuth2Error?]()
		oauth.authorize() { _, error in firstAnswers.append(error) }
		
		var secondAnswers = [OAuth2Error?]()
		var secondIdentity: OAuth2AuthorizationID?
		let secondAnswered = expectation(description: "the second sign-in answered")
		oauth.onAuthorizationCallbackCleared = {
			oauth.onAuthorizationCallbackCleared = nil
			// as `OAuth2DataLoader` does from a URL session's queue after a 401
			DispatchQueue.global().async {
				oauth.authorize() { _, error in
					secondAnswers.append(error)
					secondAnswered.fulfill()
				}
			}
			let deadline = Date().addingTimeInterval(2)
			while nil == oauth.currentAuthorization && Date() < deadline {
				usleep(1000)
			}
			secondIdentity = oauth.currentAuthorization
		}
		oauth.abortAuthorization()
		XCTAssertEqual([.requestCancelled], firstAnswers)
		XCTAssertNotNil(secondIdentity)
		XCTAssertEqual(secondIdentity, oauth.currentAuthorization, "The second sign-in keeps the one identity it began with")
		
		let presented = expectation(for: NSPredicate { _, _ in 2 == authorizer.sessions.count }, evaluatedWith: nil)
		wait(for: [presented], timeout: 2)
		XCTAssertEqual(secondIdentity, oauth.currentAuthorization)
		XCTAssertTrue(oauth.isPresentingAuthorization, "The second sign-in presents its sheet")
		XCTAssertEqual(0, authorizer.sessions[1].cancelCount)
		
		authorizer.sessions[1].completionHandler(redirectURL(oauth), nil)
		XCTAssertEqual(1, performer.requests.count)
		performer.complete(0, with: tokenResponse)
		wait(for: [secondAnswered], timeout: 2)
		XCTAssertEqual([nil], secondAnswers, "and it answers")
		XCTAssertFalse(oauth.isAuthorizing)
	}
	
	func testAnAbortConcurrentWithAStartingSignInEndsItCleanlyOrLeavesItAlone() {
		for round in 0..<40 {
			let (oauth, authorizer, _) = codeGrant()
			var answers = [OAuth2Error?]()
			var afterCalls = 0
			oauth.afterAuthorizeOrFail = { _, _ in afterCalls += 1 }
			let started = DispatchSemaphore(value: 0)
			// as `OAuth2DataLoader` does from a URL session's queue after a 401
			DispatchQueue.global().async {
				oauth.authorize() { _, error in answers.append(error) }
				started.signal()
			}
			usleep(useconds_t(round * 5))
			oauth.abortAuthorization()
			
			// the starting sign-in hops to the main thread to present its sheet
			while .timedOut == started.wait(timeout: .now()) {
				RunLoop.current.run(until: Date().addingTimeInterval(0.001))
			}
			RunLoop.current.run(until: Date().addingTimeInterval(0.01))
			
			if oauth.isAuthorizing {
				// the abort came first and found nothing to abort
				XCTAssertEqual([], answers, "round \(round)")
				XCTAssertEqual(0, afterCalls, "round \(round)")
				XCTAssertNotNil(oauth.currentAuthorization, "round \(round)")
				XCTAssertTrue(oauth.isPresentingAuthorization, "round \(round)")
				XCTAssertEqual(1, authorizer.sessions.count, "round \(round)")
				oauth.abortAuthorization()
				XCTAssertEqual([.requestCancelled], answers, "round \(round)")
				XCTAssertEqual(1, authorizer.sessions[0].cancelCount, "round \(round)")
			}
			else {
				// the abort ended it, and nothing of it goes on
				XCTAssertEqual([.requestCancelled], answers, "round \(round)")
				XCTAssertEqual(1, afterCalls, "round \(round)")
				XCTAssertFalse(oauth.isPresentingAuthorization, "round \(round)")
				XCTAssertEqual(0, authorizer.sessions.count, "An ended sign-in presents no sheet (round \(round))")
			}
			XCTAssertNil(oauth.currentAuthorization, "round \(round)")
			XCTAssertFalse(oauth.isAuthorizing, "round \(round)")
		}
	}
	
	func testADuplicateRedirectOfACompletedSignInDoesNotFailTheNextOne() {
		let (oauth, authorizer, performer) = codeGrant()
		oauth.authorize() { _, _ in }
		let firstRedirect = redirectURL(oauth)
		authorizer.sessions[0].completionHandler(firstRedirect, nil)
		performer.complete(0, with: tokenResponse)
		XCTAssertFalse(oauth.isAuthorizing)
		
		var secondAnswers = [OAuth2Error?]()
		oauth.authorize() { _, error in secondAnswers.append(error) }
		// the provider's redirect, delivered a second time
		oauth.handleRedirectURL(firstRedirect)
		XCTAssertEqual(1, performer.requests.count, "A duplicate redirect is not exchanged")
		XCTAssertEqual([], secondAnswers, "and it does not fail the next sign-in")
		XCTAssertTrue(oauth.isAuthorizing)
		oauth.abortAuthorization()
	}
	
	func testASessionThatCannotStartFailsTheAuthorization() {
		let (oauth, authorizer, _) = codeGrant()
		authorizer.sessionsStart = false
		var answers = [OAuth2Error?]()
		oauth.authorize() { _, error in answers.append(error) }
		
		XCTAssertEqual([.unableToOpenAuthorizeURL], answers)
		XCTAssertFalse(oauth.isAuthorizing)
		XCTAssertFalse(oauth.isPresentingAuthorization)
	}
}


/**
A web authentication session that presents nothing; the test calls its completion handler.
*/
class OAuth2FakeAuthenticationSession: OAuth2WebAuthenticationSession {
	
	let completionHandler: (URL?, Error?) -> Void
	
	let startResult: Bool
	
	/// Whether `cancel()` calls the completion handler with `.canceledLogin`, as a real session may.
	let cancelCallsCompletion: Bool
	
	private(set) var cancelCount = 0
	
	private(set) var wasCancelledOffTheMainThread = false
	
	init(startResult: Bool, cancelCallsCompletion: Bool, completionHandler: @escaping (URL?, Error?) -> Void) {
		self.startResult = startResult
		self.cancelCallsCompletion = cancelCallsCompletion
		self.completionHandler = completionHandler
	}
	
	func start() -> Bool {
		return startResult
	}
	
	func cancel() {
		cancelCount += 1
		if !Thread.isMainThread {
			wasCancelledOffTheMainThread = true
		}
		if cancelCallsCompletion {
			completionHandler(nil, ASWebAuthenticationSessionError(.canceledLogin))
		}
	}
}


/**
An authorizer whose web authentication sessions are `OAuth2FakeAuthenticationSession`s.
*/
class OAuth2FakeSessionAuthorizer: OAuth2Authorizer {
	
	/// What the sessions' `start()` returns.
	var sessionsStart = true
	
	/// Whether the sessions' `cancel()` calls their completion handler.
	var sessionsCallBackOnCancel = false
	
	private(set) var sessions = [OAuth2FakeAuthenticationSession]()
	
	override func makeAuthenticationSession(at url: URL, callbackURLScheme: String?, prefersEphemeralWebBrowserSession: Bool, completionHandler: @escaping (URL?, Error?) -> Void) -> OAuth2WebAuthenticationSession {
		let session = OAuth2FakeAuthenticationSession(startResult: sessionsStart, cancelCallsCompletion: sessionsCallBackOnCancel, completionHandler: completionHandler)
		sessions.append(session)
		return session
	}
}


#endif
