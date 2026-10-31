//
//  OAuth2DeviceGrant.swift
//  OAuth2
//
//  Created by Dominik Paľo on 29/03/23.
//  Copyright © 2023 Cisco Systems, Inc. All rights reserved.
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
#endif

/// https://www.ietf.org/rfc/rfc8628.html
open class OAuth2DeviceGrant: OAuth2 {
	override open class var grantType: String {
		return "urn:ietf:params:oauth:grant-type:device_code"
	}
	
	override open class var responseType: String? {
		return ""
	}
		
	open func deviceAccessTokenRequest(with deviceCode: String) throws -> OAuth2AuthRequest {
		guard let clientId = clientConfig.clientId, !clientId.isEmpty else {
			throw OAuth2Error.noClientId
		}
		
		let req = OAuth2AuthRequest(url: (clientConfig.tokenURL ?? clientConfig.authorizeURL))
		req.params["device_code"] = deviceCode
		req.params["grant_type"] = type(of: self).grantType
		req.params["client_id"] = clientId
		return req
	}
	
	open func deviceAuthorizationRequest(params: OAuth2StringDict? = nil) throws -> OAuth2AuthRequest {
		guard let clientId = clientConfig.clientId, !clientId.isEmpty else {
			throw OAuth2Error.noClientId
		}
		
		guard let url = clientConfig.deviceAuthorizeURL else {
			throw OAuth2Error.noDeviceCodeURL
		}
		
		let req = OAuth2AuthRequest(url: url)
		req.params["client_id"] = clientId
		if let scope = clientConfig.scope {
			req.params["scope"] = scope
		}
		req.add(params: params)
		
		return req
	}
	
	open func parseDeviceAuthorizationResponse(data: Data) throws -> OAuth2JSON {
		let dict = try parseJSON(data)
		return try parseDeviceAuthorizationResponse(params: dict)
	}
	
	public final func parseDeviceAuthorizationResponse(params: OAuth2JSON) throws -> OAuth2JSON {
		try assureNoErrorInResponse(params)
		
		return params
	}
	
	/**
	Start the device authorization flow.
	
	- parameter params:   Optional key/value pairs to pass during authorize device request
	- parameter callback: The callback to call after the device authorization response has been received
	*/
	public func start(useNonTextualTransmission: Bool = false, params: OAuth2StringDict? = nil, completion: @escaping (DeviceAuthorization?, Error?) -> Void) {
		// Started for an authorization, polling answers only that one and stops once it has ended. Started outside one, it
		// answers as it always did: whichever authorization is in progress when the token arrives.
		let authorization = currentAuthorization
		let isWanted: (() -> Bool)? = (nil == authorization) ? nil : { self.isCurrentAuthorization(authorization) }
		authorizeDevice(params: params) { result, error in
			guard let result else {
				if let error {
					self.logger?.warn("OAuth2", msg: "Unable to get device code: \(error)")
				}
				completion(nil, error)
				return
			}
			
			guard let deviceCode = result["device_code"] as? String,
				let userCode = result["user_code"] as? String,
				let verificationUri = result["verification_uri"] as? String,
				let verificationUrl = URL(string: verificationUri),
				let expiresIn = result["expires_in"] as? Int else {
				let error = OAuth2Error.generic("The response doesn't contain all required fields.")
				self.logger?.warn("OAuth2", msg: String(describing: error))
				completion(nil, error)
				return
			}
			
			var verificationUrlComplete: URL?
			if let verificationUriComplete = result["verification_uri_complete"] as? String {
				verificationUrlComplete = URL(string: verificationUriComplete)
			}
			
			if useNonTextualTransmission, let url = verificationUrlComplete {
				do {
					try self.authorizer.openAuthorizeURLInBrowser(url)
				} catch let error {
					completion(nil, error)
				}
			}
			
			let pollingInterval = result["interval"] as? TimeInterval ?? 5
			self.getDeviceAccessToken(deviceCode: deviceCode, interval: pollingInterval, while: isWanted) { params, error in
				if let params {
					if nil == isWanted {
						self.didAuthorize(withParameters: params)
					} else {
						self.didAuthorize(withParameters: params, for: authorization)
					}
				}
				else if let error {
					if nil == isWanted {
						self.didFail(with: error.asOAuth2Error)
					} else {
						self.didFail(with: error.asOAuth2Error, for: authorization)
					}
				}
			}
			
			let deviceAuthorization = DeviceAuthorization(userCode: userCode, verificationUrl: verificationUrl, verificationUrlComplete: verificationUrlComplete, expiresIn: expiresIn)
			completion(deviceAuthorization, nil)
		}
	}
	
	private func authorizeDevice(params: OAuth2StringDict?, completion: @escaping (OAuth2JSON?, Error?) -> Void) {
		do {
			let post = try deviceAuthorizationRequest(params: params).asURLRequest(for: self)
			logger?.debug("OAuth2", msg: "Obtaining device code from \(post.url!)")
			
			perform(request: post) { response in
				do {
					let data = try response.responseData()
					let params = try self.parseDeviceAuthorizationResponse(data: data)
					completion(params, nil)
				}
				catch let error {
					completion(nil, error.asOAuth2Error)
				}
			}
		}
		catch let error {
			completion(nil, error.asOAuth2Error)
		}
	}
	
	/**
	Polls for the device's access token until it arrives or polling fails.
	
	- parameter while:      Nil, or checked on the main thread before each response is parsed (parsing installs the token; `completion`
	                        then runs in the same turn of the main thread) and before each poll after the first. Once it says no, polling
	                        stops and `completion` is not called.
	- parameter completion: Called once, with the token response or the error that ended polling
	*/
	private func getDeviceAccessToken(deviceCode: String, interval: TimeInterval, while isWanted: (() -> Bool)?, completion: @escaping (OAuth2JSON?, Error?) -> Void) {
		do {
			let post = try deviceAccessTokenRequest(with: deviceCode).asURLRequest(for: self)
			logger?.debug("OAuth2", msg: "Obtaining access token for device with code \(deviceCode) from \(post.url!)")
			
			perform(request: post) { response in
				guard let isWanted = isWanted else {
					self.handleDeviceAccessTokenResponse(response, deviceCode: deviceCode, interval: interval, while: nil, completion: completion)
					return
				}
				callAsyncOnMainThread {
					guard isWanted() else {
						self.logger?.debug("OAuth2", msg: "Dropping the device token response of an authorization that has ended")
						return
					}
					self.handleDeviceAccessTokenResponse(response, deviceCode: deviceCode, interval: interval, while: isWanted, completion: completion)
				}
			}
		}
		catch let error {
			completion(nil, error.asOAuth2Error)
		}
	}
	
	private func handleDeviceAccessTokenResponse(_ response: OAuth2Response, deviceCode: String, interval: TimeInterval, while isWanted: (() -> Bool)?, completion: @escaping (OAuth2JSON?, Error?) -> Void) {
		do {
			let data = try response.responseData()
			let params = try parseAccessTokenResponse(data: data)
			completion(params, nil)
		}
		catch let error {
			let oaerror = error.asOAuth2Error
			
			if oaerror == .authorizationPending(nil) {
				logger?.debug("OAuth2", msg: "AuthorizationPending, repeating in \(interval) seconds.")
				pollAgain(deviceCode: deviceCode, interval: interval, while: isWanted, completion: completion)
			} else if oaerror == .slowDown(nil) {
				let updatedInterval = interval + 5 // The 5 seconds increase is required by the RFC8628 standard (https://www.rfc-editor.org/rfc/rfc8628#section-3.5)
				logger?.debug("OAuth2", msg: "SlowDown, repeating in \(updatedInterval) seconds.")
				pollAgain(deviceCode: deviceCode, interval: updatedInterval, while: isWanted, completion: completion)
			} else {
				completion(nil, oaerror)
			}
		}
	}
	
	private func pollAgain(deviceCode: String, interval: TimeInterval, while isWanted: (() -> Bool)?, completion: @escaping (OAuth2JSON?, Error?) -> Void) {
		DispatchQueue.main.asyncAfter(deadline: .now() + interval) {
			if let isWanted = isWanted, !isWanted() {
				self.logger?.debug("OAuth2", msg: "Stopping to poll for the device token of an authorization that has ended")
				return
			}
			self.getDeviceAccessToken(deviceCode: deviceCode, interval: interval, while: isWanted, completion: completion)
		}
	}
}

public struct DeviceAuthorization {
	public let userCode: String
	public let verificationUrl: URL
	public let verificationUrlComplete: URL?
	public let expiresIn: Int
}
