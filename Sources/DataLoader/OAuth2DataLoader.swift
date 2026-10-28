//
//  OAuth2DataLoader.swift
//  OAuth2
//
//  Created by Pascal Pfiffner on 8/31/16.
//  Copyright 2016 Pascal Pfiffner
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
#if !NO_MODULE_IMPORT
import Base
import Flows
#endif


/**
A class that makes loading data from a protected endpoint easier.
*/
open class OAuth2DataLoader: OAuth2Requestable {
	
	/// The OAuth2 instance used for OAuth2 access tokvarretrieval.
	public let oauth2: OAuth2
	
	/// If set to true, a 403 is treated as a 401. The default is false.
	public var alsoIntercept403: Bool = false
	
	
	/**
	Designated initializer.
	
	Provide `host` if 301 and 302 redirects should be followed automatically, as long as they appear on the same host.
	
	- parameter oauth2: The OAuth2 instance to use for authorization when loading data.
	- parameter host:   If given will handle redirects within the same host by way of `OAuth2DataLoaderSessionTaskDelegate`
	*/
	public init(oauth2: OAuth2, host: String? = nil) {
		self.oauth2 = oauth2
		super.init(logger: oauth2.logger)
		if let host = host {
			sessionDelegate = OAuth2DataLoaderSessionTaskDelegate(loader: self, host: host)
		}
	}
	
	
	// MARK: - Make Requests
	
	/// Guards `enqueued` and `isAuthorizing`.
	///
	/// Both are mutated from URLSession completion callbacks, which run on arbitrary background
	/// threads. A loader shared between concurrent requests — the only way this class can actually
	/// serialize refreshes — races on them otherwise, and two requests each starting a refresh
	/// spend the same rotating refresh token twice.
	///
	/// Recursive because `dequeueAndApply` re-enters `perform` by way of `retryAll`.
	private let stateLock = NSRecursiveLock()

	/// Our FIFO queue. Only touch while holding `stateLock`.
	private var enqueued: [OAuth2DataRequest]?

	/// Only touch while holding `stateLock`.
	private var isAuthorizing = false
	
	/**
	Overriding this method: it intercepts `unauthorizedClient` errors, stops and enqueues all calls, starts the authorization and, upon
	success, resumes all enqueued calls.
	
	The callback is easy to use, like so:
	
	    perform(request: req) { dataStatusResponse in
	        do {
	            let (data, status) = try dataStatusResponse()
	            // do what you must with `data` as Data and `status` as Int
	        }
	        catch let error {
	            // the request failed because of `error`
	        }
	    }
	
	- parameter request:  The request to execute
	- parameter callback: The callback to call when the request completes/fails. Looks terrifying, see above on how to use it
	*/
	override open func perform(request: URLRequest, callback: @escaping ((OAuth2Response) -> Void)) {
		perform(request: request, retry: true, callback: callback)
	}
	
	/**
	This method takes an additional `retry` flag, then uses the base implementation of `perform(request:callback:)` to perform the given
	request. It intercepts 401 (and 403, if `alsoIntercept403` is true), enqueues the request and performs authorization. During
	authorization, all requests to be performed are enqueued and they are all dequeued once authorization finishes, either by retrying
	them on authorization success or by aborting them all with the same error.
	
	The callback is easy to use, like so:
	
	    perform(request: req) { dataStatusResponse in
	        do {
	            let (data, status) = try dataStatusResponse()
	            // do what you must with `data` as Data and `status` as Int
	        }
	        catch let error {
	            // the request failed because of `error`
	        }
	    }
	
	- parameter request:  The request to execute
	- parameter retry:    Whether the request should be retried on 401 (and possibly 403)
	- parameter callback: The callback to call when the request completes/fails
	*/
	open func perform(request: URLRequest, retry: Bool, callback: @escaping ((OAuth2Response) -> Void)) {
		// Reading the flag and enqueuing must be one atomic step. Split apart, a request can observe
		// "not authorizing", then enqueue into a queue that has just been drained, and hang forever.
		stateLock.lock()
		if isAuthorizing {
			enqueue(request: request, callback: callback)
			stateLock.unlock()
			return
		}
		stateLock.unlock()

		super.perform(request: request) { response in
			do {
				if self.alsoIntercept403, 403 == response.response.statusCode {
					throw OAuth2Error.unauthorizedClient(nil)
				}
				let _ = try response.responseData()
				callback(response)
			}
			
			// not authorized; stop and enqueue all requests, start authorization once, then re-try all enqueued requests
			catch OAuth2Error.unauthorizedClient {
				if retry {
					// A 401 answering a token the client no longer holds says nothing about the one it
					// holds now, which a concurrent refresh installed: forgetting that one would leave
					// `retryAll()` no token to sign the queue with and refresh the new token again.
					// The request goes again, signed with the token held now and still allowed its
					// retry; a 401 to that answers the token held now, so it is forgotten and the
					// client authorizes again below. It goes again only when signing it gives it the
					// token held now, so a second 401 cannot send it once more. A request sent
					// unsigned, or with a header this cannot read, forgets the token at once, as before.
					let held = self.oauth2.clientConfig.accessToken
					if Self.answersAnOlderToken(request, current: held) {
						var resigned = request
						do {
							try resigned.sign(with: self.oauth2)
						}
						catch let error {
							let failure = (error as? OAuth2Error) ?? OAuth2Error.noAccessToken
							callback(OAuth2Response(data: nil, request: request, response: HTTPURLResponse(), error: failure))
							return
						}
						if !Self.answersAnOlderToken(resigned, current: held) {
							self.perform(request: resigned, retry: true, callback: callback)
							return
						}
					}
					self.enqueue(request: request, callback: callback)
					self.oauth2.clientConfig.accessToken = nil
					self.attemptToAuthorize() { json, error in
						
						// dequeue all if we're authorized, throw all away if something went wrong
						if nil != json {
							self.retryAll()
						}
						else {
							self.throwAllAway(with: error ?? OAuth2Error.requestCancelled)
						}
					}
				}
				else {
					callback(response)
				}
			}
			
			// some other error, pass along
			catch {
				callback(response)
			}
		}
	}
	
	/**
	If not already authorizing, will use its `oauth2` instance to start authorization after forgetting any tokens (!).
	
	This method will ignore calls while authorization is ongoing, meaning you will only get the callback once per authorization cycle.
	
	- parameter callback: The callback passed on from `authorize(callback:)`. Authorization finishes successfully (auth parameters will be
	                      non-nil but may be an empty dict), fails (error will be non-nil) or is canceled (both params and error are nil)
	*/
	open func attemptToAuthorize(callback: @escaping ((OAuth2JSON?, OAuth2Error?) -> Void)) {
		// Claim the authorization atomically. Two requests failing at the same moment would otherwise
		// both see `isAuthorizing == false` and each start a refresh — spending a rotating refresh
		// token twice, which providers treat as replay and answer with `invalid_grant`.
		stateLock.lock()
		let alreadyAuthorizing = isAuthorizing
		if !alreadyAuthorizing {
			isAuthorizing = true
		}
		stateLock.unlock()

		// A cycle is already running; this caller's request is queued and `retryAll()` will pick it up.
		guard !alreadyAuthorizing else {
			return
		}

		oauth2.authorize() { authParams, error in
			// Cleared *before* the callback, which drains the queue: `retryAll()` re-enters `perform`,
			// and that would re-enqueue every retried request if the flag were still set.
			self.stateLock.lock()
			self.isAuthorizing = false
			self.stateLock.unlock()
			callback(authParams, error)
		}
	}
	
	
	// MARK: - Queue
	
	/**
	Enqueues the given URLRequest and callback. You probably don't want to use this method yourself.
	
	- parameter request:  The URLRequest to enqueue for later execution
	- parameter callback: The closure to call when the request has been executed
	*/
	public func enqueue(request: URLRequest, callback: @escaping ((OAuth2Response) -> Void)) {
		enqueue(request: OAuth2DataRequest(request: request, callback: callback))
	}
	
	/**
	Enqueues the given OAuth2DataRequest. You probably don't want to use this method yourself.
	
	- parameter request:  The OAuth2DataRequest to enqueue for later execution
	*/
	public func enqueue(request: OAuth2DataRequest) {
		stateLock.lock()
		defer { stateLock.unlock() }
		if nil == enqueued {
			enqueued = [request]
		}
		else {
			enqueued!.append(request)
		}
	}
	
	/**
	Dequeue all enqueued requests, applying the given closure to all of them. The queue will be empty by the time the closure is called.
	
	- parameter closure: The closure to apply to each enqueued request
	*/
	public func dequeueAndApply(closure: ((OAuth2DataRequest) -> Void)) {
		// Take the queue under the lock, then apply outside it: the closure re-performs requests and
		// must not run with the lock held.
		stateLock.lock()
		let enq = enqueued
		enqueued = nil
		stateLock.unlock()

		guard let enq = enq else {
			return
		}
		enq.forEach(closure)
	}
	
	/**
	Uses `dequeueAndApply()` by signing and re-performing all enqueued requests.
	*/
	func retryAll() {
		dequeueAndApply() { req in
			var request = req.request
			do {
				try request.sign(with: oauth2)
				self.perform(request: request, retry: false, callback: req.callback)
			}
			catch let error {
				// Every queued request is answered exactly once. The token can be gone by now (a
				// sign-out that forgot the tokens, or a refresh answered without an access token),
				// and a request dropped here leaves its caller waiting for the life of the process.
				// Answered as `throwAllAway` answers it: a bare response carrying the error.
				NSLog("OAuth2.DataLoader.retryAll(): \(error)")
				let failure = (error as? OAuth2Error) ?? OAuth2Error.noAccessToken
				req.callback(OAuth2Response(data: nil, request: req.request, response: HTTPURLResponse(), error: failure))
			}
		}
	}
	
	/**
	Uses `dequeueAndApply()` to all enqueued requests, calling their callback with a response representing the given error.
	
	- parameter error: The error with which to finalize all enqueued requests
	*/
	func throwAllAway(with error: OAuth2Error) {
		dequeueAndApply() { req in
			let res = OAuth2Response(data: nil, request: req.request, response: HTTPURLResponse(), error: error)
			req.callback(res)
		}
	}

	/**
	Whether `request` was signed with a bearer token other than `current`: a 401 answering it says nothing about `current`.

	The scheme is read case-insensitively, and spaces around the scheme and around either token are ignored. A request with no
	`Authorization` header, a header in another scheme or one this cannot read, and a client holding no token all answer `false`,
	so the 401 forgets the token.

	- parameter request: The request a 401 answered
	- parameter current: The access token the client holds now
	*/
	static func answersAnOlderToken(_ request: URLRequest, current: String?) -> Bool {
		guard let current = current,
		      let header = request.value(forHTTPHeaderField: "Authorization")
		else { return false }
		let parts = header.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
		guard parts.count == 2, parts[0].lowercased() == "bearer" else { return false }
		return parts[1].trimmingCharacters(in: .whitespaces) != current.trimmingCharacters(in: .whitespaces)
	}
}

