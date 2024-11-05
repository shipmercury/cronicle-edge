#!/usr/bin/env node

// URL Plugin for Cronicle
// Invoked via the 'HTTP Client' Plugin
// Copyright (c) 2017 Joseph Huckaby
// Released under the MIT License

// Job Params: 
//		method, url, headers, data, timeout, follow, ssl_cert_bypass, success_match, error_match

var fs = require('fs');
var os = require('os');
var cp = require('child_process');
var path = require('path');
var JSONStream = require('pixl-json-stream');
var Tools = require('pixl-tools');
var Request = require('pixl-request');

// setup stdin / stdout streams 
process.stdin.setEncoding('utf8');
process.stdout.setEncoding('utf8');

var keycloakDevUrl = `https://auth-dev-titan.shipmercury.io/realms/shipmercury/protocol/openid-connect/token`;
var keycloakTestUrl = `https://auth-test-titan.shipmercury.io/realms/shipmercury/protocol/openid-connect/token`;
var keycloakStagingUrl = `https://auth-staging-titan.shipmercury.io/realms/shipmercury/protocol/openid-connect/token`;
var keycloakProdUrl = `https://auth.shipmercury.com/realms/shipmercury/protocol/openid-connect/token`;
var clientMap = {
	'api-dev-titan.shipmercury.io': keycloakDevUrl,
	'api-dev.shipmercury.io': keycloakDevUrl,
	'api-test-titan.shipmercury.io': keycloakTestUrl,
	'api-test.shipmercury.io': keycloakTestUrl,
	'api-staging-titan.shipmercury.io': keycloakStagingUrl,
	'api-staging.shipmercury.io': keycloakStagingUrl,
	'api-prod-titan.shipmercury.com': keycloakProdUrl,
	'api-prod.shipmercury.com': keycloakProdUrl,
}

var stream = new JSONStream(process.stdin, process.stdout);
stream.on('json', async function (job) {
	// got job from parent
	var params = job.params;
	var request = new Request();

	var print = function (text) {
		fs.appendFileSync(job.log_file, text);
	};

	// timeout
	var timeout = (params.timeout || 0) * 1000;
	print("\nTimeout: " + timeout + "ms\n");
	request.setTimeout(timeout);
	request.setIdleTimeout(timeout);

	if (!params.url || !params.url.match(/^https?\:\/\/\S+$/i)) {
		stream.write({ complete: 1, code: 1, description: "Malformed URL: " + (params.url || '(n/a)') });
		return;
	}

	// allow URL to be substituted using [placeholders]
	params.url = Tools.sub(params.url, job);

	print("Sending HTTP " + params.method + " to URL:\n" + params.url + "\n");

	// headers
	if (params.headers) {
		// allow headers to be substituted using [placeholders]
		params.headers = Tools.sub(params.headers, job);
		print("\nRequest Headers:\n");
		params.headers.replace(/\r\n/g, "\n").trim().split(/\n/).forEach(function (pair) {
			if (pair.match(/^([^\:]+)\:\s*(.+)$/)) {
				const headerKey = RegExp.$1;
				const headerValue = RegExp.$2;
				request.setHeader(headerKey, headerValue);
				const maskedValue = (headerKey.toLowerCase() === 'authorization' && headerValue.trim().includes(' ')) ? headerValue.replace(headerValue.trim().split(' ')[1], '*'.repeat(headerValue.trim().split(' ')[1].length)) : headerValue;
				print(`${headerKey}: ${maskedValue.trim()}\n`);
			}
		});
	}

	// set athentication header if set via secrets
	if (params.parse_auth && process.env['AUTH']) {
		process.env['AUTH'].replace(/\r\n/g, "\n").trim().split(/\n/).forEach(function (pair) {
			if (pair.match(/^([^\:]+)\:\s*(.+)$/)) {
				request.setHeader(RegExp.$1, RegExp.$2);
			}
		})
	}

	// get current host from URL

	var host = params.url.match(/^https?\:\/\/([^\/]+)/i);
	if (host) host = host[1];
	if (host && clientMap[host]) {
		// send a request to Keycloak to get access token using client credentials
		var keycloakClientUrl = clientMap[host];
		print(`\nHost is ${host}\n`);
		print(`Keycloak url is ${keycloakClientUrl}\n`);
		var keycloakOptions = {
			"grant_type": "client_credentials",
			"client_id": process.env['KEYCLOAK_CLIENT_ID'],
			"client_secret": process.env['KEYCLOAK_CLIENT_SECRET'],
			"scope": "openid",
		};

		var token = null;
		try {
			var rawResponse = await fetch(keycloakClientUrl, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded'
				},
				body: new URLSearchParams(keycloakOptions)
			});
			const data = await rawResponse.json();
			print(`Keycloak response: ${rawResponse.statusText}\n`);
			if (!data.access_token) {
				print("Failed to get access token from Keycloak: " + data);
			}
			token = data.access_token;
		} catch (err) {
			if (err) {
				print("Failed to get access token from Keycloak: " + err);
			}
		}
	}
	if (token) {
		request.setHeader('Authorization', `Bearer ${token}`);
	}

	// follow redirects
	if (params.follow) request.setFollow(32);

	var opts = {
		method: params.method
	};

	// ssl cert bypass
	if (params.ssl_cert_bypass) {
		opts.rejectUnauthorized = false;
	}

	// post data
	if (opts.method == 'POST') {
		// allow POST data to be substituted using [placeholders]
		params.data = Tools.sub(params.data, job);

		print("\nPOST Data:\n" + params.data.trim() + "\n");
		opts.data = Buffer.from(params.data || '');
	}

	// matching
	var success_match = new RegExp(params.success_match || '.*');
	var error_match = new RegExp(params.error_match || '(?!)');

	// start building cronicle JSON update
	var update = {
		complete: 1
	};
	request.setKeepAlive(false);
	// send request
	try {
		const { resp, data, perf } = await request.request(params.url, opts);
		print("Request finished\n");
		// HTTP code out of success range = error
		var err = null;
		if (resp.statusCode < 200 || resp.statusCode >= 400) {
			err = new Error("HTTP " + resp.statusCode + " " + resp.statusMessage);
			err.code = resp.statusCode;
		}
		print("Error check finished\n");

		// successmatch?  errormatch?
		var text = data ? data.toString() : '';
		if (text.match(error_match)) {
			err = new Error("Response contains error match: " + params.error_match);
		}
		else if (!text.match(success_match)) {
			err = new Error("Response missing success match: " + params.success_match);
		}
		print("Error-Success match finished\n");

		if (err) {
			update.code = err.code || 1;
			update.description = err.message || err;
		}
		else {
			update.code = 0;
			update.description = "Success (HTTP " + resp.statusCode + " " + resp.statusMessage + ")";
		}
		print("Json update finished\n");

		print("\n" + update.description + "\n");

		// add raw response headers into table
		if (resp && resp.rawHeaders) {
			var rows = [];
			print("\nResponse Headers:\n");

			for (var idx = 0, len = resp.rawHeaders.length; idx < len; idx += 2) {
				rows.push([resp.rawHeaders[idx], resp.rawHeaders[idx + 1]]);
				print(resp.rawHeaders[idx] + ": " + resp.rawHeaders[idx + 1] + "\n");
			}

			update.table = {
				title: "HTTP Response Headers",
				header: ["Header Name", "Header Value"],
				rows: rows.sort(function (a, b) {
					return a[0].localeCompare(b[0]);
				})
			};
		}
		print("Header update finished\n");

		// add response headers to chain_data if applicable
		if (job.chain) {
			update.chain_data = {
				headers: resp.headers
			};
		}
		print("Chain control finished\n");

		// add raw response content, if text (and not too long)
		if (text && resp.headers['content-type'] && resp.headers['content-type'].match(/(text|javascript|json|css|html)/i)) {
			print("\nRaw Response Content:\n" + text.trim() + "\n");

			if (text.length < 32768) {
				update.html = {
					title: "Raw Response Content",
					content: "<pre>" + text.replace(/</g, '&lt;').trim() + "</pre>"
				};
			}

			// if response was JSON and chain mode is enabled, chain parsed data
			if (job.chain && (text.length < 1024 * 1024) && resp.headers['content-type'].match(/(application|text)\/json/i)) {
				var json = null;
				try { json = JSON.parse(text); }
				catch (e) {
					print("\nWARNING: Failed to parse JSON response: " + e + " (could not include JSON in chain_data)\n");
				}
				if (json) update.chain_data.json = json;
			}
		}
		print("Text log finished\n");

		if (perf) {
			// passthru perf to cronicle
			update.perf = perf.metrics();
			print("\nPerformance Metrics: " + perf.summarize() + "\n");
		}
		print("Perf log finished\n");

	} catch (err) {
		update.code = err.code || 1;
		update.description = err.message || err;
		print("Got error\n" + JSON.stringify(update));
	}
	print("Stream finished\n");

	stream.write(update);
});