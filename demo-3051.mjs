#!/usr/bin/env node

import { MongoClient } from 'mongodb';
import { MongoServerError } from 'mongodb';
import fs from 'fs'; 
import express from 'express';
import { engine } from 'express-handlebars';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import http from 'http';
import {
    pjclHex2BitArray,
    pjclBitArray2Hex,
    pjclRBG128Instantiate,
    pjclRBG128Reseed,
    pjclRBGGen,
    pjclHex2BigInt,
    pjclCurve_P256,
    pjclECDSAVerifyMsg,
    pjclSHA256
} from 'pjcl/pjcl-with-argument-checking.js';
import {
    jsonUtilsObject2Hex,
    jsonUtilsHex2Object,
    jsonUtilsObject2BitArray
} from "./json-utils.js";

// making pjcl.js and browser-entropy.js available to views
//
// pjcl.js must be in dot for json-utils.js until i put json-utils on npm
// but it must be put there before running the demo, rather than copying to it
//
let pjclCopiedToStatic = false;
let browserEntropyCopiedToStatic = false;
let jsonUtilsCopiedToStatic = false;
//
fs.copyFile("./node_modules/pjcl/pjcl.js", "./static/pjcl.js", function(err) {
    if (err) throw new Error(err);
    pjclCopiedToStatic = true;
});
//
fs.copyFile("./node_modules/pjcl/browser-entropy.js", "./static/browser-entropy.js", function(err) {
    if (err) throw new Error(err);
    browserEntropyCopiedToStatic = true;
});
//
fs.copyFile("./json-utils.js", "./static/json-utils.js", function(err) {
    if (err) throw new Error(err);
    jsonUtilsCopiedToStatic = true;
});

// setting up a good source of entropy
//
const rbgStateObject = new Object();
const rbgSecurityStrength = 128;
const reseedPeriod = 604093; // a little over 10 minutes
//
function getDevRandomBits(bitLength, f) {
    const byteLength = bitLength / 8;
    const buf = Buffer.alloc(byteLength); 
    (function fillBuf(bufPos) {
        let remaining = byteLength - bufPos;
        if (remaining == 0) {
            f(buf.toString('hex'));
            return;
        }
        fs.open('/dev/random', 'r', function(err, fd) {
            if (err) throw new Error(err);
            fs.read(fd, buf, bufPos, remaining, 0, function(err, bytesRead) {
                if (err) throw new Error(err);
                bufPos += bytesRead;
                fs.close(fd, function(err) {
                    if (err) throw new Error(err);
                    fillBuf(bufPos);
                });
            });
        });
    })(0);
}
//
let rbgStateInitialized = false;
//
getDevRandomBits(rbgSecurityStrength, function(hex) {
    pjclRBG128Instantiate(rbgStateObject, pjclHex2BitArray(hex));
    rbgStateInitialized = true;            
    reseedPeriodically(reseedPeriod);
});
//
function reseedPeriodically(period) {
    setTimeout(getDevRandomBits, period, rbgSecurityStrength, function(hex) {
        pjclRBG128Reseed(rbgStateObject, pjclHex2BitArray(hex));
        reseedPeriodically(period);
    });
}

const connectionString = "mongodb://localhost:27017";
const mongoClient = new MongoClient(connectionString);

const ttl_for_cred_pres = 300; // 5 minutes
const ttl_for_inactive_user_record = 600; // 10 minutes
const ttl_for_active_user_record = 604800; // 1 week
const ttl_for_loggedIn_session = 1200; // 20 minutes

let db, uniqueIds, credPresSessions, loggedInSessions, userRecords;
async function connectToDb() {
    await mongoClient.connect();
    db = mongoClient.db('carRentalsDb');

    uniqueIds = db.collection('uniqueIds');
    await uniqueIds.createIndex({ uniqueId: 1 }, { unique: true });

    credPresSessions = db.collection('credPresSessions');
    await credPresSessions.createIndex(
	{ "createdAt": 1 },
	{ expireAfterSeconds: ttl_for_cred_pres }
    );
    await credPresSessions.createIndex({ sessionId: 1 }, { unique: true });

    loggedInSessions = db.collection('loggedInSessions');
    await loggedInSessions.createIndex(
	{ "createdAt": 1 },
	{
	    expireAfterSeconds: ttl_for_loggedIn_session
	}
    );
    await loggedInSessions.createIndex({ loggedInSessionId: 1 }, { unique: true });

    userRecords = db.collection('userRecords');
    await userRecords.createIndex({ username: 1 }, { unique: true });
    await userRecords.createIndex(
	{ "createdAt_inactive": 1 },
	{ 
	    expireAfterSeconds: ttl_for_inactive_user_record,
	    partialFilterExpression: { 
		status: "inactive" 
	    } 
	}
    );
    await userRecords.createIndex(
	{ "createdAt_active": 1 },
	{ 
	    expireAfterSeconds: ttl_for_active_user_record,
	}
    );
}
connectToDb();

const cleanup = async () => {
  await mongoClient.close();
  process.exit(0);
};
process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);

// Unique IDs
//
// genUniqueId generates a uniqueId as a statistically random integer
// between 100,000 and 999,999 that is unique in the context of the
// carRentalsDb database
//
async function genUniqueId() {
    let found = false;
    let uniqueId;
    while (!found) {
        try {
            uniqueId = 100000 + Math.floor(Math.random() * 900000);
            await uniqueIds.insertOne({ uniqueId });
            found = true;
        } catch (error) {
            if (error.code === 11000) {
                console.log("Duplicate value", error.keyValue);
            }
            else {
                throw error;
            }
        }
    }
    return uniqueId;
}

async function createCredPresSession(username, purpose) {
    const sessionId = await genUniqueId();
    const challenge_hex = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
    await credPresSessions.insertOne({
	createdAt: new Date(),
	purpose,
	username,
	sessionId,
	challenge_hex
    });
    return { sessionId, challenge_hex };
}

const app = express();
app.engine("handlebars", engine());
app.set("view engine", "handlebars");
app.set('views', './views');

http.createServer(app).listen(3051);
console.log("listening on port 3051");

app.use(express.static('static'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(function(req,res,next) {
    if (
	!pjclCopiedToStatic ||
        !browserEntropyCopiedToStatic ||
	!jsonUtilsCopiedToStatic ||
	!rbgStateInitialized    
    ) {
        res.status(503).send('SERVER BUSY, TRY AGAIN LATER');
    }
    else {
        next();
    }
});

app.get('/username-not-found.html',function(req,res) {
    res.render("home-page.handlebars", {
	error_login: 'Username not found'
    });
});

app.get('/incorrect-proof-of-possession-signature.html',function(req,res) {
    res.render("message.handlebars", {
	// layout: 'layout-without-bootstrap.handlebars',
        msg: "Incorrect proof-of-possession signature"
    });
});

app.get('/incorrect-certificate-signature.html',function(req,res) {
    res.render("message.handlebars", {
	// layout: 'layout-without-bootstrap.handlebars',
        msg: "Incorrect certificate signature"
    });
});

app.get('/incorrect-attribute-digest.html',function(req,res) {
    res.render("message.handlebars", {
	// layout: 'layout-without-bootstrap.handlebars',
        msg: "Incorrect attribute digest"
    });
});

app.get('/incorrect-self-signature.html',function(req,res) {
    res.render("message.handlebars", {
	// layout: 'layout-without-bootstrap.handlebars',
        msg: "Incorrect root cert self-signature"
    });
});

app.get('/wrong-document-number.html',function(req,res) {
    res.render("message.handlebars", {
	// layout: 'layout-without-bootstrap.handlebars',
        msg: "Wrong document number"
    });
});

const callbackEndpoint = "https://v5-rp-web.pomcor.com/cred-presentation";
const requestEndpoint = "https://v5-ci.pomcor.com/cred-request";
const credType = "selectiveDisclosure";
const profileAttrs_object = ["document_number", "given_name", "family_name", "birth_date", "resident_address"];
const profileAttrs_hex = jsonUtilsObject2Hex(profileAttrs_object);
const dlNumberOnly_object = ["document_number"];
const dlNumberOnly_hex = jsonUtilsObject2Hex(dlNumberOnly_object);

app.get('/', (req, res) => {
    res.redirect(303, "/home-page.html");
});

app.get('/car-reservation.html', (req, res) => {
    res.render("car-reservation.handlebars");
});

app.get('/home-page.html', async (req, res) => {
    let loggedIn = false;
    const loggedInSessionId = req.cookies.loggedInSessionId;
    if (loggedInSessionId) {
	const sessionQuery = { loggedInSessionId: Number(loggedInSessionId) };
	const loggedInSession = await loggedInSessions.findOne(sessionQuery);
	if (loggedInSession) {
	    const username = loggedInSession.username;
	    const userQuery = { username };
	    const userRecord = await userRecords.findOne(userQuery);
	    if (userRecord) {
		loggedIn = true;
		res.render("loggedIn-home-page.handlebars", {
		    username: username
		    // the logged-in home-page has a header with the username
		    // and links to:
		    // - rent a car page, and
		    // - the profile page
		    // those pages will access the user record from
		    // the loggedInSession cookie, or fall back on the
		    // not-logged-in home page if the user is not
		    // logged in
		});
	    }
	}
    }
    if (!loggedIn) {
	res.render("home-page.handlebars");
    }
});

app.post('/login', async (req, res) => {
    const username = req.body.username;
    const query = { username };
    const userRecord = await userRecords.findOne(query);
    if (userRecord == null) {
	res.redirect(303, "/username-not-found.html");
	return;
    };
    const { sessionId, challenge_hex } = await createCredPresSession(username, "login");
    res.render('cred-request.handlebars', {
	sessionId,
	credType, // selectiveDisclosure (global constant in demo-3051.mjs)
	attrs_hex: dlNumberOnly_hex,
	challenge_hex,
	requestEndpoint,
	callbackEndpoint
    });
});

app.post('/register', async (req, res) => {
    const username = req.body.username;
    //
    // creating the user record
    //
    try {
	await userRecords.insertOne({
	    createdAt: new Date(),
	    status: "inactive",
	    username: username,
	    certifiedAttrs: {},
	    selfAssertedAttrs: {}
	});
    } catch (error) {
	if (error.code == 11000) {
	    res.render("home-page.handlebars", {
		error_register: 'The username you chose is taken'
	    });
	    return;
	}
	else {
	    throw new Error("Unexpected error");
	}
    }
    const { sessionId, challenge_hex } = await createCredPresSession(username, "registration");
    res.render('cred-request.handlebars', {
	sessionId,
	credType, // selectiveDisclosure (global constant in demo-3051.mjs)
	attrs_hex: profileAttrs_hex, // standard will way that attrs-hex is included for selectiveDisclosure only
	challenge_hex,
	requestEndpoint,
	callbackEndpoint
    });
});

app.post('/cred-presentation', async (req, res) => {
    const r_hex = req.body.r_hex;
    const r = pjclHex2BigInt(r_hex); // r component of the signature
    const s_hex = req.body.s_hex;
    const s = pjclHex2BigInt(s_hex); // s component of the signature
    const cert_hex = req.body.cert_hex;
    const chain_hex = req.body.chain_hex;
    const sessionId = req.body.sessionId;

    const query = { sessionId: Number(sessionId) };
    const credPresSession = await credPresSessions.findOne(query);

    const challenge_hex = credPresSession.challenge_hex;
    const toBeSigned_object = {
        challenge_hex,
        callbackEndpoint // JS constant declared in the outer block
    };
    const toBeSigned = jsonUtilsObject2BitArray(toBeSigned_object);
    const cert_object = jsonUtilsHex2Object(cert_hex);
    const subjectPubKey = cert_object.subjectPubKey;
    const Q_x_hex = subjectPubKey.Q_x_hex;
    const Q_y_hex = subjectPubKey.Q_y_hex;
    const x = pjclHex2BigInt(Q_x_hex);
    const y = pjclHex2BigInt(Q_y_hex);
    const Q = {x:x, y:y, z:[1]};
    if (!pjclECDSAVerifyMsg(pjclCurve_P256,Q,toBeSigned,r,s)) {
	res.redirect(303, "/incorrect-proof-of-possession-signature.html");
	return;
    };

    let digestsWithoutAttributes = [];
    const attributes_object = {};
    cert_object.saltedAttributesWithDigests.forEach(saltedAttributeWithDigest => {
	const digest_hex = saltedAttributeWithDigest.digest_hex;
	digestsWithoutAttributes.push({digest_hex});
	const saltedAttribute = saltedAttributeWithDigest.saltedAttribute;
	if (saltedAttribute !== undefined) {
	    const saltedAttribute_bitArray = jsonUtilsObject2BitArray(saltedAttribute);
	    const attributeDigest = pjclSHA256(saltedAttribute_bitArray);
	    if (digest_hex != pjclBitArray2Hex(attributeDigest)) {
		res.redirect(303, "/incorrect-attribute-digest.html");
		return;
	    };
	    const attributeName = saltedAttribute.name;
	    const attributeValue = saltedAttribute.value;
	    attributes_object[attributeName] = attributeValue;
	};
    });

    // the signature in the certificate has been computed
    // by the issuer on the certificate with digests only,
    // and can be verified using the issuer's public key,
    // which can be found in the CA certificate element of
    // the certificate chain
    //
    const chain = jsonUtilsHex2Object(chain_hex);
    const issuerPubKey = chain.caCert.subjectPubKey;
    const issuer_x = pjclHex2BigInt(issuerPubKey.Q_x_hex);
    const issuer_y = pjclHex2BigInt(issuerPubKey.Q_y_hex);
    const issuer_Q = {x:issuer_x, y:issuer_y, z:[1]};

    const toBeSignedByIssuer_object = {
	digestsWithoutAttributes,
	subjectPubKey
    };
    const toBeSignedByIssuer = jsonUtilsObject2BitArray(toBeSignedByIssuer_object);
    const issuer_r = pjclHex2BigInt(cert_object.signatureOnSdCert.r_hex);
    const issuer_s = pjclHex2BigInt(cert_object.signatureOnSdCert.s_hex);
    if (!pjclECDSAVerifyMsg(pjclCurve_P256,issuer_Q,toBeSignedByIssuer,issuer_r,issuer_s)) {
	res.redirect(303, "/incorrect-certificate-signature.html");
	return;
    };

    // verifying that the root certificate is self-signed
    //
    const rootCert = chain.rootCert;
    const unsignedRootCert_object = {
	issuer: rootCert.issuer,
	validity: rootCert.validity,
	subject: rootCert.subject,
	subjectPubKey: rootCert.subjectPubKey
    };
    const unsignedRootCert = jsonUtilsObject2BitArray(unsignedRootCert_object);
    const root_x = pjclHex2BigInt(rootCert.subjectPubKey.Q_x_hex);
    const root_y = pjclHex2BigInt(rootCert.subjectPubKey.Q_y_hex);
    const root_Q = { x:root_x, y:root_y, z:[1] };
    const root_r = pjclHex2BigInt(rootCert.signature.r_hex);
    const root_s = pjclHex2BigInt(rootCert.signature.s_hex);
    if (!pjclECDSAVerifyMsg(pjclCurve_P256,root_Q,unsignedRootCert,root_r,root_s)) {
	res.redirect(303, "/incorrect-self-signature.html");
	return;
    };

    const username = credPresSession.username;

    const purpose = credPresSession.purpose;
    if (purpose == "registration") {
	const userRecords = db.collection('userRecords');
	const filter = { username };
	const updateDoc = {
	    $set: {
		certifiedAttrs: attributes_object,
		status: "active"
	    }
	};
	await userRecords.updateOne(filter, updateDoc);
    }
    else { // purpose is login
	const userRecords = db.collection('userRecords');
	const query = { username };
	const userRecord = await userRecords.findOne(query);
	if (userRecord.certifiedAttrs.document_number != attributes_object['document_number']) {
	    res.redirect(303, "/wrong-document-number.html");
	    return;
	};
    }

    // now creating the loggedIn session, not to be confused
    // with the credential presentation session
    // 
    const uniqueId = await genUniqueId();
    await loggedInSessions.insertOne({
	createdAt: new Date(),
	username,
	loggedInSessionId: uniqueId
    });

    res.cookie('loggedInSessionId', uniqueId, {httpOnly: true, secure: true});
    if (purpose == "registration") {
	const attributes_hex = jsonUtilsObject2Hex(attributes_object);
	res.render('credential-presented.handlebars', {
    	    username,
	    attributes_hex
	});
    }
    else {
	res.render('loggedIn-home-page.handlebars', {
	    username
	});
    }
});

app.get('/logout', async (req, res) => {
    const loggedInSessionId = req.cookies.loggedInSessionId;
    if (loggedInSessionId) {
        res.clearCookie('loggedInSessionId');
	const query = { loggedInSessionId };
	await loggedInSessions.deleteOne(query);
    }
    res.redirect(303, "/");
});

app.get('/profile', async (req, res) => {
    let loggedIn = false;
    const loggedInSessionId = req.cookies.loggedInSessionId;
    if (loggedInSessionId) {
	const sessionQuery = { loggedInSessionId: Number(loggedInSessionId) };
	const loggedInSession = await loggedInSessions.findOne(sessionQuery);
	if (loggedInSession) {
	    const username = loggedInSession.username;
	    const userRecords = db.collection('userRecords');
	    const userQuery = { username };
	    const userRecord = await userRecords.findOne(userQuery);
	    if (userRecord) {
		loggedIn = true;
		const certifiedAttrs_hex = jsonUtilsObject2Hex(userRecord.certifiedAttrs);
		res.render('profile.handlebars', {
		    username,
		    certifiedAttrs_hex
		});
	    }
	}
    }
    if (!loggedIn) {
	res.render("message.handlebars", {
            msg: "You must be logged in to access your profile",
	});
    }
});

app.use(function(req,res) {
    res.status(404).send('NOT FOUND');
});
app.use(function(err,req,res,next) {
    console.log("Error: " + err.stack);
    res.status(500).send('INTERNAL ERROR');
});
