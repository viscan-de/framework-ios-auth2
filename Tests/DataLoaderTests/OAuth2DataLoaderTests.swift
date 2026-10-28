//
//  OAuth2DataLoaderTests.swift
//  OAuth2
//
//  Created by Pascal Pfiffner on 9/12/16.
//  Copyright © 2016 Pascal Pfiffner. All rights reserved.
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
 @testable
 import DataLoader
#else
 @testable
 import OAuth2
#endif


class OAuth2DataLoaderTests: XCTestCase {
	
	var oauth2: OAuth2PasswordGrant?
	
	var loader: OAuth2DataLoader?
	
	var authPerformer: OAuth2MockPerformer?
	
	var dataPerformer: OAuth2AnyBearerPerformer?
	
	override func setUp() {
		super.setUp()
		authPerformer = OAuth2MockPerformer()
		authPerformer!.responseJSON = ["access_token": "toktok", "token_type": "bearer"]
		oauth2 = OAuth2PasswordGrant(settings: ["client_id": "abc", "authorize_url": "https://oauth.io/authorize", "keychain": false] as OAuth2JSON)
		oauth2!.logger = OAuth2DebugLogger(.debug)
//		oauth2!.logger = OAuth2DebugLogger(.trace)
		oauth2!.username = "p2"
		oauth2!.password = "test"
		oauth2!.requestPerformer = authPerformer
		
		dataPerformer = OAuth2AnyBearerPerformer()
		loader = OAuth2DataLoader(oauth2: oauth2!)
		loader!.requestPerformer = dataPerformer
	}
	
	func testAutoEnqueue() {
		XCTAssertNil(oauth2!.accessToken)
		let req1 = oauth2!.request(forURL: URL(string: "http://auth.io/data/user")!)
		let wait1 = expectation(description: "req1")
		loader!.perform(request: req1) { response in
			XCTAssertNotNil(self.oauth2!.accessToken)
			do {
				let json = try response.responseJSON()
				XCTAssertNotNil(json["data"])
			}
			catch let error {
				XCTAssertNil(error)
			}
			wait1.fulfill()
		}
		
		let req2 = oauth2!.request(forURL: URL(string: "http://auth.io/data/home")!)
		let wait2 = expectation(description: "req2")
		loader!.perform(request: req2) { response in
			XCTAssertNotNil(self.oauth2!.accessToken)
			do {
				let json = try response.responseJSON()
				XCTAssertNotNil(json["data"])
			}
			catch let error {
				XCTAssertNil(error)
			}
			wait2.fulfill()
		}
		waitForExpectations(timeout: 4.0) { error in
			XCTAssertNil(error)
		}
	}

	/// A queued request whose re-signing fails must still be answered. Here the tokens are forgotten
	/// (a sign-out) between the authorization's token write and `retryAll()`: re-signing throws
	/// `noAccessToken`, and before the fix its callback was never called, so the caller waited for
	/// the life of the process.
	func testRetryAllAnswersARequestItCannotReSign() {
		let signingOut = SignOutBeforeRetryDataLoader(oauth2: oauth2!)
		signingOut.requestPerformer = dataPerformer
		let req = oauth2!.request(forURL: URL(string: "http://auth.io/data/user")!)
		let answered = expectation(description: "answered")
		var answer: OAuth2Response?
		signingOut.perform(request: req) { response in
			answer = response
			answered.fulfill()
		}
		waitForExpectations(timeout: 4.0)
		XCTAssertEqual(answer?.error as? OAuth2Error, OAuth2Error.noAccessToken)
	}

	/// A 401 answering a request signed with an older token must not forget the token the client
	/// holds now: that token was installed by a refresh the request did not see. Before the fix it was
	/// forgotten, the client authorized again ("toktok") and the retried request was refused.
	func testStale401KeepsTheCurrentToken() {
		oauth2!.clientConfig.accessToken = "new"
		loader!.requestPerformer = OAuth2OnlyBearerPerformer(token: "new")
		var req = URLRequest(url: URL(string: "http://auth.io/data/user")!)
		req.setValue("Bearer old", forHTTPHeaderField: "Authorization")
		let answered = expectation(description: "answered")
		var status: Int?
		loader!.perform(request: req) { response in
			status = response.response.statusCode
			answered.fulfill()
		}
		waitForExpectations(timeout: 4.0)
		XCTAssertEqual(status, 201)
		XCTAssertEqual(oauth2!.clientConfig.accessToken, "new")
	}

	/// The stale-401 rule reads the scheme case-insensitively and ignores surrounding spaces.
	func testStale401InAnotherSpellingKeepsTheCurrentToken() {
		oauth2!.clientConfig.accessToken = "new"
		loader!.requestPerformer = OAuth2OnlyBearerPerformer(token: "new")
		var req = URLRequest(url: URL(string: "http://auth.io/data/user")!)
		req.setValue("  bearer   old ", forHTTPHeaderField: "Authorization")
		let answered = expectation(description: "answered")
		var status: Int?
		loader!.perform(request: req) { response in
			status = response.response.statusCode
			answered.fulfill()
		}
		waitForExpectations(timeout: 4.0)
		XCTAssertEqual(status, 201)
		XCTAssertEqual(oauth2!.clientConfig.accessToken, "new")
	}

	/// A 401 answering the token the client holds still forgets it and authorizes again: the path that
	/// worked before the stale-401 rule must keep working.
	func testA401ForTheCurrentTokenAuthorizesAgain() {
		oauth2!.clientConfig.accessToken = "dead"
		loader!.requestPerformer = OAuth2OnlyBearerPerformer(token: "toktok")
		var req = URLRequest(url: URL(string: "http://auth.io/data/user")!)
		req.setValue("Bearer dead", forHTTPHeaderField: "Authorization")
		let answered = expectation(description: "answered")
		var status: Int?
		loader!.perform(request: req) { response in
			status = response.response.statusCode
			answered.fulfill()
		}
		waitForExpectations(timeout: 4.0)
		XCTAssertEqual(status, 201)
		XCTAssertEqual(oauth2!.clientConfig.accessToken, "toktok")
	}

	/// A stale 401 whose current token is dead as well still ends in a fresh authorization: the request
	/// goes again with the current token, that 401 forgets it, and the client authorizes again.
	func testStale401OverADeadCurrentTokenAuthorizesAgain() {
		oauth2!.clientConfig.accessToken = "deadnew"
		loader!.requestPerformer = OAuth2OnlyBearerPerformer(token: "toktok")
		var req = URLRequest(url: URL(string: "http://auth.io/data/user")!)
		req.setValue("Bearer old", forHTTPHeaderField: "Authorization")
		let answered = expectation(description: "answered")
		var status: Int?
		loader!.perform(request: req) { response in
			status = response.response.statusCode
			answered.fulfill()
		}
		waitForExpectations(timeout: 4.0)
		XCTAssertEqual(status, 201)
		XCTAssertEqual(oauth2!.clientConfig.accessToken, "toktok")
	}

	/// A token with spaces around it, signed into the header as it is, is the current token, not an older one.
	func testA401ForTheCurrentTokenWithSpacesAuthorizesAgain() {
		oauth2!.clientConfig.accessToken = "dead "
		loader!.requestPerformer = OAuth2OnlyBearerPerformer(token: "toktok")
		var req = URLRequest(url: URL(string: "http://auth.io/data/user")!)
		req.setValue("Bearer dead ", forHTTPHeaderField: "Authorization")
		let answered = expectation(description: "answered")
		var status: Int?
		loader!.perform(request: req) { response in
			status = response.response.statusCode
			answered.fulfill()
		}
		waitForExpectations(timeout: 4.0)
		XCTAssertEqual(status, 201)
		XCTAssertEqual(oauth2!.clientConfig.accessToken, "toktok")
	}

	/// A client holding an empty token holds none: a stale 401 queues the request and authorizes again,
	/// as 1.1.2 did, instead of answering the caller with "no access token".
	func testStale401OverAnEmptyTokenAuthorizesAgain() {
		oauth2!.clientConfig.accessToken = ""
		loader!.requestPerformer = OAuth2OnlyBearerPerformer(token: "toktok")
		var req = URLRequest(url: URL(string: "http://auth.io/data/user")!)
		req.setValue("Bearer old", forHTTPHeaderField: "Authorization")
		let answered = expectation(description: "answered")
		var status: Int?
		loader!.perform(request: req) { response in
			status = response.response.statusCode
			answered.fulfill()
		}
		waitForExpectations(timeout: 4.0)
		XCTAssertEqual(status, 201)
		XCTAssertEqual(oauth2!.clientConfig.accessToken, "toktok")
	}

	/// A 401 answering a request sent unsigned forgets the token as before, so a dead token is never kept.
	func testA401ForAnUnsignedRequestAuthorizesAgain() {
		oauth2!.clientConfig.accessToken = "dead"
		loader!.requestPerformer = OAuth2OnlyBearerPerformer(token: "toktok")
		let req = URLRequest(url: URL(string: "http://auth.io/data/user")!)
		let answered = expectation(description: "answered")
		var status: Int?
		loader!.perform(request: req) { response in
			status = response.response.statusCode
			answered.fulfill()
		}
		waitForExpectations(timeout: 4.0)
		XCTAssertEqual(status, 201)
		XCTAssertEqual(oauth2!.clientConfig.accessToken, "toktok")
	}
}


/// Forgets the access token once the authorization has answered (whatever its outcome) and before the queue is retried.
class SignOutBeforeRetryDataLoader: OAuth2DataLoader {

	override func attemptToAuthorize(callback: @escaping ((OAuth2JSON?, OAuth2Error?) -> Void)) {
		super.attemptToAuthorize { json, error in
			self.oauth2.clientConfig.accessToken = nil
			callback(json, error)
		}
	}
}


/// Answers 201 only to a request signed with the given token, 401 to every other.
class OAuth2OnlyBearerPerformer: OAuth2RequestPerformer {

	let token: String

	init(token: String) {
		self.token = token
	}

	func perform(request: URLRequest, completionHandler callback: @escaping (Data?, URLResponse?, Error?) -> Void) -> URLSessionTask? {
		let accepted = ("Bearer \(token)" == request.value(forHTTPHeaderField: "Authorization"))
		let http = HTTPURLResponse(url: request.url!, statusCode: accepted ? 201 : 401, httpVersion: nil, headerFields: nil)!
		let data = accepted ? try? JSONSerialization.data(withJSONObject: ["data": ["in": "response"]], options: []) : nil
		callback(data, http, nil)
		return nil
	}
}


class OAuth2AnyBearerPerformer: OAuth2RequestPerformer {
	
	func perform(request: URLRequest, completionHandler callback: @escaping (Data?, URLResponse?, Error?) -> Void) -> URLSessionTask? {
		let authorized = (nil != request.value(forHTTPHeaderField: "Authorization"))
		let status = authorized ? 201 : 401
		let http = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
		if authorized {
			let data = try? JSONSerialization.data(withJSONObject: ["data": ["in": "response"]], options: [])
			callback(data, http, nil)
		}
		else {
			callback(nil, http, nil)
		}
		return nil
	}
}

