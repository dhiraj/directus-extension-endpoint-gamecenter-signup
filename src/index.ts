import {defineEndpoint} from "@directus/extensions-sdk";
import { isEmpty } from 'lodash-es';
import jwt from 'jsonwebtoken';
import {nanoid} from 'nanoid';
import ms from 'ms';
import * as url from "url";
import * as https from "https";
import {createVerify} from "node:crypto";


var cache:{[id: string]:any} = {}; // (publicKey -> cert) cache

function verifyPublicKeyUrl(publicKeyUrl:string) {
	var parsedUrl = url.parse(publicKeyUrl);
	if (parsedUrl.protocol !== 'https:') {
		return false;
	}

	var hostnameParts = parsedUrl.hostname.split('.');
	var length = hostnameParts.length;
	var domainParts = hostnameParts.slice(length-2, length);
	var domain = domainParts.join('.');
	if (domain !== 'apple.com') {
		return false;
	}

	return true;
}
function convertX509CertToPEM(X509Cert:string) {
	var pemPreFix = '-----BEGIN CERTIFICATE-----\n';
	var pemPostFix = '-----END CERTIFICATE-----';

	var base64 = X509Cert;
	var certBody = base64.match(new RegExp('.{0,64}', 'g')).join('\n');

	return pemPreFix + certBody + pemPostFix;
}

const getAppleCertificate = (publicKeyUrl:string, logger) => {
	return new Promise((resolve, reject) => {
		if (!verifyPublicKeyUrl(publicKeyUrl)) {
			reject(new Error('Invalid publicKeyUrl'));
		}

		if (cache[publicKeyUrl]) {
			logger.info(`Cache HIT: ${publicKeyUrl}`)
			resolve(cache[publicKeyUrl])
		}

		https.get(publicKeyUrl, function (res) {
			var data = '';
			res.on('data', function(chunk) {
				// logger.debug(`Received data chunk`)
				data += chunk.toString('base64');
			});
			res.on('end', function() {
				// logger.debug(`Response ended`)
				var cert = convertX509CertToPEM(data);

				if (res.headers['cache-control']) { // if there's a cache-control header
					var expire = res.headers['cache-control'].match(/max-age=([0-9]+)/);
					if (expire) { // if we got max-age
						cache[publicKeyUrl] = cert; // save in cache
						// we'll expire the cache entry later, as per max-age
						setTimeout(function () {
							delete cache[publicKeyUrl];
						}, parseInt(expire[1] as string, 10) * 1000);
					}
				}
				resolve(cert)
			});
		}).on('error', function(e) {
			reject(e)
		});
	})
}
function convertTimestampToBigEndian(timestamp) {
	// The timestamp parameter in Big-Endian UInt-64 format
	var buffer = new Buffer.alloc(8);
	buffer.fill(0);

	var high = ~~(timestamp / 0xffffffff); // jshint ignore:line
	var low = timestamp % (0xffffffff + 0x1); // jshint ignore:line

	buffer.writeUInt32BE(parseInt(high, 10), 0);
	buffer.writeUInt32BE(parseInt(low, 10), 4);

	return buffer;
}
function verifySignature(publicKey, teamPlayerId, bundleId, timestamp, salt, signature) {
	var verifier = createVerify('sha256');
	verifier.update(teamPlayerId, 'utf8');
	verifier.update(bundleId, 'utf8');
	verifier.update(convertTimestampToBigEndian(timestamp));
	verifier.update(salt, 'base64');

	if (!verifier.verify(publicKey, signature, 'base64')) {
		throw new Error('Invalid Signature');
	}
}
export default defineEndpoint({
	id: 'gamecenter',
	handler: (router, context) => {
		const { services, getSchema, env, logger } = context;
		const { UsersService, ItemsService } = services;


		router.post('/callback', async (req, res) => {
			const schema = await getSchema();
			const usersService = new UsersService({ schema});
			const sessionsService = new ItemsService('directus_sessions',{ schema });
			if (!req.body.publicKeyURL || isEmpty(req.body.publicKeyURL)){
				return res.status(422).json({error:"Need publickKeyURL"})
			}
			if (!req.body.teamPlayerId || isEmpty(req.body.teamPlayerId)){
				return res.status(422).json({error:"Need teamPlayerId"})
			}
			if (!req.body.signature || isEmpty(req.body.signature)){
				return res.status(422).json({error:"Need signature"})
			}
			if (!req.body.salt || isEmpty(req.body.salt)){
				return res.status(422).json({error:"Need salt"})
			}
			if (!req.body.timestamp || isEmpty(req.body.timestamp)){
				return res.status(422).json({error:"Need timestamp"})
			}
			const cert = await getAppleCertificate(req.body.publicKeyURL, logger)
			try {
				verifySignature(cert, req.body.teamPlayerId, env.IOS_BUNDLE_ID, req.body.timestamp, req.body.salt, req.body.signature)
				// logger.info(`Verification completed!`)
			} catch (e) {
				logger.error(`Error verifying signature: ${e}`)
				return res.status(444).json({error:"Could not verify signature, unknown error"}).end()
			}
			const userEmail = `${btoa(req.body.teamPlayerId)}@gknoemail.com`;
			let foundUser = await usersService.getUserByEmail(userEmail);
			try {
				if (!isEmpty(foundUser)){
					await usersService.updateOne(foundUser.id,{
						first_name: req.body.alias,
						last_name: req.body.displayName,
					})
				}
				else {
					foundUser = await usersService.createOne({
						provider: "apple",
						first_name: req.body.alias,
						last_name: req.body.displayName,
						email: userEmail,
						external_identifier: req.body.teamPlayerId,
						role: env.AUTH_GOOGLE_DEFAULT_ROLE_ID,
					});
				}
			}
			catch (e) {
				return res.status(500).json({error:"Exception:Could not access / create user for this AuthCode"}).end();
			}
			try{
				const access_token = jwt.sign({
					id: foundUser.id,
					role: env.AUTH_GOOGLE_DEFAULT_ROLE_ID,
					app_access:false,
					admin_access:false,
				}, env.SECRET, {
					expiresIn: env.ACCESS_TOKEN_TTL,
					issuer: 'directus',
				});
				const refresh_token = nanoid(64);
				const refreshTokenExpiration = new Date(Date.now() + ms(env.REFRESH_TOKEN_TTL));

				await sessionsService.createOne({
					token: refresh_token,
					user: foundUser.id,
					expires: refreshTokenExpiration
				});
				return res.json( {
					access_token,
					refresh_token,
					expires: ms(env.ACCESS_TOKEN_TTL)
				});
			}
			catch (e) {
				return res.status(500).json({error:"Exception:Could not create / sign access tokens for this Auth Code"}).end();
			}
		});
	},
});
