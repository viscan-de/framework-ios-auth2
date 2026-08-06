//
//  OAuth2RefreshTokenTests.swift
//  OAuth2
//
//  Created by Pascal Pfiffner on 12/20/15.
//  Copyright © 2015 Pascal Pfiffner. All rights reserved.
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
#else
@testable
import OAuth2
#endif


class OAuth2RefreshTokenTests: XCTestCase {
	
	func genericOAuth2() -> OAuth2 {
		return OAuth2(settings: [
			"client_id": "abc",
			"authorize_uri": "https://auth.ful.io",
			"token_uri": "https://token.ful.io",
			"keychain": false,
		])
	}

	func refreshOAuth2() -> OAuth2 {
		return OAuth2(settings: [
			"client_id": "abc",
			"authorize_uri": "https://auth.ful.io",
			"token_uri": "https://token.ful.io",
			"refresh_uri": "https://refresh.ful.io",
			"keychain": false,
		])
	}
	
	func testCannotRefresh() {
		let oauth = genericOAuth2()
		do {
			_ = try oauth.tokenRequestForTokenRefresh().asURLRequest(for: oauth)
			XCTAssertTrue(false, "Should throw when trying to create refresh token request without refresh token")
		}
		catch OAuth2Error.noRefreshToken {
		}
		catch {
			XCTAssertTrue(false, "Should have thrown `NoRefreshToken`")
		}
	}
	
	func testRefreshRequest() {
		let oauth = genericOAuth2()
		oauth.clientConfig.refreshToken = "pov"
		
		let req = try? oauth.tokenRequestForTokenRefresh().asURLRequest(for: oauth)
		XCTAssertNotNil(req)
		XCTAssertNotNil(req?.url)
		XCTAssertNotNil(req?.httpBody)
		XCTAssertEqual("https://token.ful.io", req!.url!.absoluteString)
		let comp = URLComponents(url: req!.url!, resolvingAgainstBaseURL: true)
		let params = comp?.percentEncodedQuery
		XCTAssertNil(params)
		let body = String(data: req!.httpBody!, encoding: String.Encoding.utf8)
		XCTAssertNotNil(body)
		let dict = OAuth2.params(fromQuery: body!)
		XCTAssertEqual(dict["client_id"], "abc")
		XCTAssertEqual(dict["refresh_token"], "pov")
		XCTAssertEqual(dict["grant_type"], "refresh_token")
		XCTAssertNil(dict["client_secret"])
		XCTAssertNil(req!.allHTTPHeaderFields?["Authorization"])
	}

	func testRefreshRequestWithDedicatedRefreshURI() {
		let oauth = refreshOAuth2()
		oauth.clientConfig.refreshToken = "pov"

		let req = try? oauth.tokenRequestForTokenRefresh().asURLRequest(for: oauth)
		XCTAssertNotNil(req)
		XCTAssertNotNil(req?.url)
		XCTAssertNotNil(req?.httpBody)
		XCTAssertEqual("https://refresh.ful.io", req!.url!.absoluteString)
		let comp = URLComponents(url: req!.url!, resolvingAgainstBaseURL: true)
		let params = comp?.percentEncodedQuery
		XCTAssertNil(params)
		let body = String(data: req!.httpBody!, encoding: String.Encoding.utf8)
		XCTAssertNotNil(body)
		let dict = OAuth2.params(fromQuery: body!)
		XCTAssertEqual(dict["client_id"], "abc")
		XCTAssertEqual(dict["refresh_token"], "pov")
		XCTAssertEqual(dict["grant_type"], "refresh_token")
		XCTAssertNil(dict["client_secret"])
		XCTAssertNil(req!.allHTTPHeaderFields?["Authorization"])
	}
	
	func testRefreshRequestWithSecret() {
		let oauth = genericOAuth2()
		oauth.clientConfig.refreshToken = "pov"
		oauth.clientConfig.clientSecret = "uvw"
		
		let req = try? oauth.tokenRequestForTokenRefresh().asURLRequest(for: oauth)
		XCTAssertNotNil(req)
		XCTAssertNotNil(req?.httpBody)
		let body = String(data: req!.httpBody!, encoding: String.Encoding.utf8)
		XCTAssertNotNil(body)
		let dict = OAuth2.params(fromQuery: body!)
		XCTAssertNil(dict["client_id"])
		XCTAssertNil(dict["client_secret"])
		let auth = req!.allHTTPHeaderFields?["Authorization"]
		XCTAssertNotNil(auth)
		XCTAssertEqual("Basic YWJjOnV2dw==", auth, "Expecting correctly base64-encoded Authorization header")
	}
	
	func testRefreshRequestWithSecretInBody() {
		let oauth = genericOAuth2()
		oauth.clientConfig.refreshToken = "pov"
		oauth.clientConfig.clientSecret = "uvw"
		oauth.clientConfig.secretInBody = true
		
		let req = try? oauth.tokenRequestForTokenRefresh(params: ["param": "fool"]).asURLRequest(for: oauth)
		XCTAssertNotNil(req)
		XCTAssertNotNil(req?.httpBody)
		let body = String(data: req!.httpBody!, encoding: String.Encoding.utf8)
		XCTAssertNotNil(body)
		let dict = OAuth2.params(fromQuery: body!)
		XCTAssertEqual(dict["client_id"], "abc")
		XCTAssertEqual(dict["client_secret"], "uvw")
		XCTAssertEqual(dict["param"], "fool")
		XCTAssertNil(req!.allHTTPHeaderFields?["Authorization"])
	}

	// MARK: - Discarding a dead refresh token

	/// The regression: `responseData()` throws on 401 before the status is looked at, so a provider
	/// that answers a rejected grant with 401 rather than 400 kept its dead token and replayed it on
	/// every later request. Rotating providers read repeated replay as an attack on the family.
	func testA401FromTheTokenEndpointMeansTheRefreshTokenIsDead() {
		let oauth = genericOAuth2()
		XCTAssertTrue(oauth.refreshTokenIsUnusable(status: 401, error: nil, bodyWasJSON: true))
	}

	func testA400FromTheTokenEndpointStillMeansTheRefreshTokenIsDead() {
		let oauth = genericOAuth2()
		XCTAssertTrue(oauth.refreshTokenIsUnusable(status: 400, error: nil, bodyWasJSON: true))
	}

	/// A 4xx that is not JSON is far more likely a proxy, WAF or captive portal than the token
	/// endpoint, and must not cost the user their session.
	func testA401ThatIsNotJSONIsNotTakenAsTheProvidersWord() {
		let oauth = genericOAuth2()
		XCTAssertFalse(oauth.refreshTokenIsUnusable(status: 401, error: nil, bodyWasJSON: false))
	}

	func testATransientServerFailureKeepsTheRefreshToken() {
		let oauth = genericOAuth2()
		XCTAssertFalse(oauth.refreshTokenIsUnusable(status: 500, error: nil, bodyWasJSON: true))
		XCTAssertFalse(oauth.refreshTokenIsUnusable(status: 429, error: nil, bodyWasJSON: true))
	}

	/// A machine-readable error is the provider saying so outright, whatever status carried it.
	func testAnInvalidGrantIsDeadWhateverTheStatus() {
		let oauth = genericOAuth2()
		XCTAssertTrue(oauth.refreshTokenIsUnusable(status: 401, error: .invalidGrant(nil), bodyWasJSON: true))
		XCTAssertTrue(oauth.refreshTokenIsUnusable(status: 400, error: .unauthorizedClient(nil), bodyWasJSON: true))
	}
}

