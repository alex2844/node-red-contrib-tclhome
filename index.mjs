#!/usr/bin/env node

import EventEmitter from 'events';
import crypto from 'crypto';
import aws4 from 'aws4';

export class TCLHome extends EventEmitter {
	APP_ID = 'wx6e1af3fa84fbe523'; // com/tcl/bmiot/startup/IotInitialize.java: TclSmartSdk.getInstance().initSdk(var1, "", ":443", "", "wx6e1af3fa84fbe523", "2024162b231b92a838eea82c9aa7f832", 100);
	CLIENT_ID = '54148614'; // com/tcl/tclhome/repository/server/host/HostChangeHelper.java: if (environmentType == 2) { var1 = "54148614";
	constructor(credentials={}) {
		super();
		this.credentials = credentials;
	};
	auth() {
		const password = crypto.createHash('md5').update(this.credentials.password).digest('hex');
		return fetch('https://pa.account.tcl.com/account/login?clientId='+this.CLIENT_ID, {
			method: 'POST',
			body: JSON.stringify({
				password: password,
				username: this.credentials.username
			}),
			headers: {
				'content-type': 'application/json'
			}
		}).then(res => res.json()).then(json => {
			if (json.status !== 1)
				throw new Error('Login failed');
			this.credentials.accessToken = json.token;
			this.credentials.refreshToken = json.refreshtoken;
			this.credentials.userId = json.user.username;
			if (!this.credentials.country)
				this.credentials.country = json.user.countryAbbr;
			this.emit('auth', this.credentials);
			return json;
		});
	};
	async refreshToken() {
		if (!this.credentials.accessToken)
			await this.auth();
		return fetch('https://prod-eu.aws.tcljd.com/v3/auth/refresh_tokens', {
			method: 'POST',
			body: JSON.stringify({
				appId: this.APP_ID,
				userId: this.credentials.userId,
				ssoToken: this.credentials.accessToken
			})
		}).then(res => res.json()).then(json => {
			this.credentials.rtExpiredTime = Date.now() + 30 * 60 * 1000;
			this.credentials.saasToken = json.data.saasToken;
			this.credentials.cognitoToken = json.data.cognitoToken;
			this.credentials.cognitoId = json.data.cognitoId;
			this.emit('refreshToken', this.credentials);
			return json.data || json;
		});
	};
	async cognitoToken() {
		if ((this.credentials.rtExpiredTime||0) < Date.now())
			await this.refreshToken();
		return fetch('https://cognito-identity.eu-central-1.amazonaws.com/', {
			method: 'POST',
			headers: {
				'X-Amz-Target': 'AWSCognitoIdentityService.GetCredentialsForIdentity',
				'Content-Type': 'application/x-amz-json-1.1'
			},
			body: JSON.stringify({
				IdentityId: this.credentials.cognitoId,
				Logins: {
					'cognito-identity.amazonaws.com': this.credentials.cognitoToken
				}
			})
		}).then(res => res.json()).then(json => {
			this.credentials.ctExpiredTime = Date.now() + 60 * 60 * 1000;
			this.credentials.accessKeyId = json.Credentials.AccessKeyId;
			this.credentials.secretAccessKey = json.Credentials.SecretKey;
			this.credentials.sessionToken = json.Credentials.SessionToken;
			this.emit('cognitoToken', this.credentials);
			return json.Credentials || json;
		});
	};
	async aws(path, data) {
		if ((this.credentials.ctExpiredTime||0) < Date.now())
			await this.cognitoToken();
		var opts = {
			path,
			host: 'data.iot.eu-central-1.amazonaws.com',
			service: 'iotdata',
			region: 'eu-central-1',
			method: data && 'POST',
			body: data && JSON.stringify(data)
		};
		aws4.sign(opts, {
			accessKeyId: this.credentials.accessKeyId,
			secretAccessKey: this.credentials.secretAccessKey,
			sessionToken: this.credentials.sessionToken
		});
		process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
		return fetch(`https://${opts.host}${opts.path}`, opts).then(res => {
			delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
			return res.json();
		});
	};
	async request(path, data = {}) {
		if ((this.credentials.rtExpiredTime||0) < Date.now())
			await this.refreshToken();
		const timestamp = String(Date.now());
		const nonce = Math.random().toString(36).substring(2);
		const sign = this.calculateMD5HashBytes(timestamp + nonce + this.credentials.saasToken);
		return fetch('https://prod-eu.aws.tcljd.com'+path, {
			method: 'POST',
			headers: {
				timestamp, nonce, sign,
				accesstoken: this.credentials.saasToken,
				countrycode: this.credentials.country
			},
			body: JSON.stringify(data)
		}).then(res => {
			if (res.status !== 200)
				throw new Error(`${res.statusText} (${res.status})`);
			return res.json();
		});
	};
	getDevices() {
		return this.request('/v3/user/get_things').then(({ data }) => data);
	};
	getDevice(deviceId) {
		return this.aws(`/things/${deviceId}/shadow`).then(json => json?.state?.desired || json);
	};
	setDevice(deviceId, data) {
		return this.aws(`/topics/$aws/things/${deviceId}/shadow/update?qos=1`, {
			state: {
				desired: data
			}
		});
	};
	calculateMD5HashBytes(input) {
		try {
			const hash = crypto.createHash('md5').update(input).digest();
			const hexChars = [];
			for (let i = 0; i < hash.length; ++i) {
				let byteValue = hash[i] & 255;
				if (byteValue < 16)
					hexChars.push('0');
				hexChars.push(byteValue.toString(16));
			}
			return hexChars.join('');
		} catch (error) {
			console.error(error);
			return '';
		}
	};
};
export default TCLHome;
