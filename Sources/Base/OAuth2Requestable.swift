//
//  OAuth2Requestable.swift
//  OAuth2
//
//  Created by Pascal Pfiffner on 6/2/15.
//  Copyright 2015 Pascal Pfiffner
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


/// Typealias to ease working with JSON dictionaries.
public typealias OAuth2JSON = [String: Any]

/// Typealias to work with dictionaries full of strings.
public typealias OAuth2StringDict = [String: String]

/// Typealias to work with headers.
public typealias OAuth2Headers = [String: String]


/**
Abstract base class for OAuth2 authorization as well as client registration classes.
*/
open class OAuth2Requestable {
	
	/// Set to `true` to log all the things. `false` by default. Use `"verbose": bool` in settings or assign `logger` yourself.
	open var verbose = false {
		didSet {
			logger = verbose ? OAuth2DebugLogger() : nil
		}
	}
	
	/// The logger being used. Auto-assigned to a debug logger if you set `verbose` to true or false.
	open var logger: OAuth2Logger?
	
	
	/**
	Base initializer.
	*/
	public init(verbose: Bool) {
		self.verbose = verbose
		logger = verbose ? OAuth2DebugLogger() : nil
		logger?.debug("OAuth2", msg: "Initialization finished")
	}
	
	/**
	Designated initializer.
	
	- parameter logger: An optional `OAuth2Logger` instance to use
	*/
	public init(logger: OAuth2Logger?) {
		self.logger = logger
		self.verbose = (nil != logger)
		logger?.debug("OAuth2", msg: "Initialization finished")
	}
	
	
	// MARK: - Requests
	
	/// The instance's current session, creating one by the book if necessary. Defaults to using an ephemeral session, you can use
	/// `sessionConfiguration` and/or `sessionDelegate` to affect how the session is configured.
	open var session: URLSession {
		if nil == _session {
			let config = sessionConfiguration ?? URLSessionConfiguration.ephemeral
			_session = URLSession(configuration: config, delegate: sessionDelegate, delegateQueue: nil)
		}
		return _session!
	}
	
	/// The backing store for `session`.
	private var _session: URLSession? {
		didSet {
			requestPerformer = nil
		}
	}
	
	/// The configuration to use when creating `session`. Uses an `+ephemeralSessionConfiguration()` if nil.
	open var sessionConfiguration: URLSessionConfiguration? {
		didSet {
			_session = nil
		}
	}
	
	/// URL session delegate that should be used for the `NSURLSession` the instance uses for requests.
	open var sessionDelegate: URLSessionDelegate? {
		didSet {
			_session = nil
		}
	}
	
	/// The instance's OAuth2RequestPerformer, defaults to using OAuth2DataTaskRequestPerformer which uses `URLSession.dataTask()`.
	open var requestPerformer: OAuth2RequestPerformer?
	
	/**
	Perform the supplied request and call the callback with the response JSON dict or an error. This method is intended for authorization
	calls, not for data calls outside of the OAuth2 dance.
	
	This implementation uses the shared `NSURLSession` and executes a data task. If the server responds with an error, this will be
	converted into an error according to information supplied in the response JSON (if availale).
	
	The callback returns a response object that is easy to use, like so:
	
	    perform(request: req) { response in
	        do {
	            let data = try response.responseData()
	            // do what you must with `data` as Data and `response.response` as HTTPURLResponse
	        }
	        catch let error {
	            // the request failed because of `error`
	        }
	    }
	
	Easy, right?
	
	- parameter request:  The request to execute
	- parameter callback: The callback to call when the request completes/fails. Looks terrifying, see above on how to use it
	*/
	open func perform(request: URLRequest, callback: @escaping ((OAuth2Response) -> Void)) {
		self.logger?.trace("OAuth2", msg: "REQUEST\n\(request.debugDescription)\n---")
		let performer = requestPerformer ?? OAuth2DataTaskRequestPerformer(session: session)
		requestPerformer = performer
		let running = OAuth2RunningRequest(authorization: authorizationOfNewRequests, keepsRunningOnAbort: type(of: self).keepsRunningOnAbort(request))
		let task = performer.perform(request: request) { sessData, sessResponse, error in
			self.requestDidFinish(running)
			self.logger?.trace("OAuth2", msg: "RESPONSE\n\(sessResponse?.debugDescription ?? "no response")\n\n\(String(data: sessData ?? Data(), encoding: String.Encoding.utf8) ?? "no data")\n---")
			let http = (sessResponse as? HTTPURLResponse) ?? HTTPURLResponse(url: request.url!, statusCode: 499, httpVersion: nil, headerFields: nil)!
			let response = OAuth2Response(data: sessData, request: request, response: http, error: error)
			callback(response)
		}
		if let task = task {
			requestDidStart(running, task: task)
		}
	}
	
	/// Guards `abortableRequests` and the `OAuth2RunningRequest`s they hold. A request's completion runs on the URL session's queue,
	/// while `perform(request:callback:)` and `abortTasks(of:)` run on whichever thread their caller is on.
	private let abortableRequestLock = NSLock()
	
	/// The requests started by `perform(request:callback:)` that have not answered yet and that an abort may cancel. Only touch while
	/// holding `abortableRequestLock`.
	private var abortableRequests = [OAuth2RunningRequest]()
	
	/// The authorization a request started now belongs to; `OAuth2Base` answers its `currentAuthorization`.
	var authorizationOfNewRequests: OAuth2AuthorizationID? {
		return nil
	}
	
	/**
	Makes a request abortable once its performer has returned the task, unless the request has answered already (a performer may call
	the completion handler before it returns, and a request that has answered has nothing left to abort) or it is to keep running.
	*/
	private func requestDidStart(_ running: OAuth2RunningRequest, task: URLSessionTask) {
		abortableRequestLock.lock()
		defer { abortableRequestLock.unlock() }
		guard !running.hasFinished, !running.keepsRunningOnAbort else {
			return
		}
		running.task = task
		abortableRequests.append(running)
	}
	
	/**
	Called first thing in a request's completion: the request is no longer abortable. Other requests still running stay abortable.
	*/
	private func requestDidFinish(_ running: OAuth2RunningRequest) {
		abortableRequestLock.lock()
		defer { abortableRequestLock.unlock() }
		running.hasFinished = true
		running.task = nil
		abortableRequests.removeAll { $0 === running }
	}
	
	/**
	Cancels the requests started by `perform(request:callback:)` for `authorization` that have not answered yet. A request marked with
	`keepingRunningOnAbort(_:)` is never cancelled.
	
	- parameter of: The authorization whose requests to cancel; nil for the requests started while none was in progress
	- returns:      true if a request was cancelled; its completion still runs
	*/
	func abortTasks(of authorization: OAuth2AuthorizationID?) -> Bool {
		abortableRequestLock.lock()
		let aborted = abortableRequests.filter { $0.authorization == authorization }
		abortableRequests.removeAll { $0.authorization == authorization }
		abortableRequestLock.unlock()
		let tasks = aborted.compactMap { $0.task }
		guard !tasks.isEmpty else {
			return false
		}
		logger?.debug("OAuth2", msg: "Aborting request")
		tasks.forEach { $0.cancel() }
		return true
	}
	
	/**
	Cancels the requests of the authorization in progress (of none, outside `OAuth2Base`) that have not answered yet.
	
	- returns: true if a request was cancelled; its completion still runs
	*/
	func abortTask() -> Bool {
		return abortTasks(of: authorizationOfNewRequests)
	}
	
	/// The `URLProtocol` property `keepingRunningOnAbort(_:)` sets.
	private static let keepsRunningOnAbortProperty = "OAuth2KeepsRunningOnAbort"
	
	/**
	Marks a request so that aborting the authorization lets it finish. A refresh-token request needs this: the provider may already
	have rotated the refresh token, and only the response carries the new one; replaying the old one revokes the whole token family.
	
	- parameter request: The request to mark
	- returns:           The request, marked
	*/
	public static func keepingRunningOnAbort(_ request: URLRequest) -> URLRequest {
		guard let marked = (request as NSURLRequest).mutableCopy() as? NSMutableURLRequest else {
			return request
		}
		URLProtocol.setProperty(true, forKey: keepsRunningOnAbortProperty, in: marked)
		return marked as URLRequest
	}
	
	/// Whether `request` was marked by `keepingRunningOnAbort(_:)`.
	static func keepsRunningOnAbort(_ request: URLRequest) -> Bool {
		return (URLProtocol.property(forKey: keepsRunningOnAbortProperty, in: request) as? Bool) ?? false
	}
	
	
	// MARK: - Utilities
	
	/**
	Parse string-only JSON from NSData.
	
	- parameter data: NSData returned from the call, assumed to be JSON with string-values only.
	- returns: An OAuth2JSON instance
	*/
	open func parseJSON(_ data: Data) throws -> OAuth2JSON {
		do {
			let json = try JSONSerialization.jsonObject(with: data, options: [])
			if let json = json as? OAuth2JSON {
				return json
			}
			if let str = String(data: data, encoding: String.Encoding.utf8) {
				logger?.warn("OAuth2", msg: "JSON did not resolve to a dictionary, was: \(str)")
			}
			throw OAuth2Error.jsonParserError
		}
		catch let error where NSCocoaErrorDomain == error._domain && 3840 == error._code {		// JSON parser error
			if let str = String(data: data, encoding: String.Encoding.utf8) {
				logger?.warn("OAuth2", msg: "Unparsable JSON was: \(str)")
			}
			throw OAuth2Error.jsonParserError
		}
	}
	
	/**
	Parse a query string into a dictionary of String: String pairs.
	
	If you're retrieving a query or fragment from NSURLComponents, use the `percentEncoded##` variant as the others
	automatically perform percent decoding, potentially messing with your query string.
	
	- parameter fromQuery: The query string you want to have parsed
	- returns: A dictionary full of strings with the key-value pairs found in the query
	*/
	public final class func params(fromQuery query: String) -> OAuth2StringDict {
		let parts = query.split() { $0 == "&" }.map() { String($0) }
		var params = OAuth2StringDict(minimumCapacity: parts.count)
		for part in parts {
			let subparts = part.split() { $0 == "=" }.map() { String($0) }
			if 2 == subparts.count {
				params[subparts[0]] = subparts[1].wwwFormURLDecodedString
			}
		}
		return params
	}
}


/**
A request started by `OAuth2Requestable.perform(request:callback:)`, from the moment it is started until its completion runs. Only
touched while holding the requestable's `abortableRequestLock`.
*/
private final class OAuth2RunningRequest {
	
	/// The authorization in progress when the request started.
	let authorization: OAuth2AuthorizationID?
	
	/// Whether the request was marked by `OAuth2Requestable.keepingRunningOnAbort(_:)`.
	let keepsRunningOnAbort: Bool
	
	/// The request's task, once its performer has returned it and as long as the request has not answered.
	var task: URLSessionTask?
	
	/// Whether the request's completion has run.
	var hasFinished = false
	
	init(authorization: OAuth2AuthorizationID?, keepsRunningOnAbort: Bool) {
		self.authorization = authorization
		self.keepsRunningOnAbort = keepsRunningOnAbort
	}
}


/**
Helper function to ensure that the callback is executed on the main thread.
*/
public func callOnMainThread(_ callback: (() -> Void)) {
	if Thread.isMainThread {
		callback()
	}
	else {
		DispatchQueue.main.sync(execute: callback)
	}
}


/**
Helper function to run the callback on the main thread without blocking the caller.

Unlike `callOnMainThread(_:)`, this never uses `DispatchQueue.main.sync`, so it is safe to call from a
URLSession completion handler: a synchronous hop from there deadlocks whenever the main thread is itself
waiting on that session's work.
*/
public func callAsyncOnMainThread(_ callback: @escaping (() -> Void)) {
	if Thread.isMainThread {
		callback()
	}
	else {
		DispatchQueue.main.async(execute: callback)
	}
}

